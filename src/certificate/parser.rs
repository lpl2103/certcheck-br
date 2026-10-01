//! Decodificador de certificados X.509 (DER) e extrator de atributos ICP-Brasil.

use crate::certificate::identity::{IcpBrasilIdentity, PersonType};
use crate::certificate::types::{
    BasicConstraints, CertificateExtensions, CertificatePolicy, CertificateSource,
    CertificateType, DistinguishedName, ExtendedKeyUsageEntry, Fingerprints, KeyAlgorithm,
    KeyUsage, SanEntry,
};
use crate::certificate::CertificateInfo;
use crate::error::{CertCheckError, Result};
use crate::icp_brasil::oids::*;
use chrono::{DateTime, Utc};
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

/// Converte bytes DER de um certificado X.509 em uma estrutura `CertificateInfo` completa.
pub fn parse_x509_der(
    der: &[u8],
    source: CertificateSource,
    has_private_key: bool,
    is_hardware_backed: bool,
) -> Result<CertificateInfo> {
    let (_, x509) = parse_x509_certificate(der)
        .map_err(|e| CertCheckError::CertificateParseError(format!("Falha ao decodificar ASN.1 DER: {:?}", e)))?;

    let tbs = &x509.tbs_certificate;

    // 1. Distinguished Names (Subject & Issuer)
    let subject = extract_distinguished_name(&tbs.subject);
    let issuer = extract_distinguished_name(&tbs.issuer);

    // 2. Número de Série (formato HEX legível: AA:BB:CC:...)
    let serial_raw = tbs.serial.to_bytes_be();
    let serial_number_hex = format_hex_bytes(&serial_raw);

    // 3. Validade temporal (NotBefore e NotAfter)
    let not_before = asn1_time_to_datetime(&tbs.validity.not_before);
    let not_after = asn1_time_to_datetime(&tbs.validity.not_after);

    // 4. Algoritmo de Assinatura
    let signature_algorithm = tbs.signature.algorithm.to_string();

    // 5. Chave Pública
    let public_key = extract_public_key(&tbs.subject_pki);

    // 6. Impressões digitais (Fingerprints)
    let sha256_hash = sha2::Sha256::digest(der);
    let sha1_hash = sha1::Sha1::digest(der);
    let fingerprints = Fingerprints {
        sha256: format_hex_bytes(&sha256_hash),
        sha1: format_hex_bytes(&sha1_hash),
    };

    // 7. Extensões X.509
    let (extensions, parsed_sans) = extract_extensions(&tbs)?;

    // 8. Identidade ICP-Brasil (extração das OIDs de SAN OtherName e fallback por CN)
    let identity = extract_icp_brasil_identity(&subject, &parsed_sans);

    // 9. Classificação do Tipo de Certificado
    let cert_type = classify_certificate_type(
        &subject,
        &issuer,
        &extensions,
        has_private_key,
        is_hardware_backed,
    );

    // 10. ID Único em memória baseado no SHA-1
    let id = format!("cert_{}", fingerprints.sha1.replace(':', "").to_lowercase());

    Ok(CertificateInfo {
        id,
        source,
        cert_type,
        subject,
        issuer,
        serial_number_hex,
        not_before,
        not_after,
        signature_algorithm,
        public_key,
        fingerprints,
        extensions,
        identity,
        has_private_key,
        is_hardware_backed,
        raw_der: der.to_vec(),
    })
}

/// Extrai os campos do Distinguished Name (DN).
fn extract_distinguished_name(x509_name: &X509Name) -> DistinguishedName {
    let mut dn = DistinguishedName {
        raw: x509_name.to_string(),
        common_name: None,
        organization: None,
        organizational_unit: None,
        country: None,
        state_or_province: None,
        locality: None,
        email_address: None,
        serial_number: None,
    };

    for rdn in x509_name.iter_rdn() {
        for attr in rdn.iter() {
            let oid = attr.attr_type().to_string();
            let value = attr.attr_value().as_str().map(|s| s.to_string()).unwrap_or_else(|_| {
                String::from_utf8_lossy(attr.attr_value().data).into_owned()
            });

            match oid.as_str() {
                "2.5.4.3" => dn.common_name = Some(value),
                "2.5.4.10" => dn.organization = Some(value),
                "2.5.4.11" => dn.organizational_unit = Some(value),
                "2.5.4.6" => dn.country = Some(value),
                "2.5.4.8" => dn.state_or_province = Some(value),
                "2.5.4.7" => dn.locality = Some(value),
                "2.5.4.5" => dn.serial_number = Some(value),
                "1.2.840.113549.1.9.1" => dn.email_address = Some(value),
                _ => {}
            }
        }
    }

    dn
}

/// Converte ASN1Time para chrono::DateTime<Utc>.
fn asn1_time_to_datetime(t: &x509_parser::time::ASN1Time) -> DateTime<Utc> {
    let ts = t.timestamp();
    DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}

/// Extrai as propriedades da Chave Pública (RSA/ECDSA).
fn extract_public_key(spki: &SubjectPublicKeyInfo) -> KeyAlgorithm {
    let alg_oid = spki.algorithm.algorithm.to_string();
    if alg_oid == "1.2.840.113549.1.1.1" {
        // RSA Encryption
        if let Ok(x509_parser::public_key::PublicKey::RSA(parsed_rsa)) = spki.parsed() {
            let bits = parsed_rsa.modulus.len() * 8;
            let exp_bytes = parsed_rsa.exponent;
            let mut exponent: u64 = 0;
            for &b in exp_bytes {
                exponent = (exponent << 8) | (b as u64);
            }
            return KeyAlgorithm::Rsa { bits, exponent };
        }
        KeyAlgorithm::Rsa { bits: 2048, exponent: 65537 }
    } else if alg_oid == "1.2.840.10045.2.1" {
        // EC Public Key
        let curve = spki.algorithm.parameters
            .as_ref()
            .and_then(|p| p.as_oid().ok())
            .map(|o| o.to_string())
            .unwrap_or_else(|| "Desconhecida".to_string());
        KeyAlgorithm::Ecdsa {
            curve,
            bits: spki.subject_public_key.data.len() * 8,
        }
    } else {
        KeyAlgorithm::Other(alg_oid)
    }
}

/// Extrai extensões RFC 5280.
fn extract_extensions(
    tbs: &TbsCertificate,
) -> Result<(CertificateExtensions, Vec<(String, Vec<u8>)>)> {
    let mut key_usage = None;
    let mut extended_key_usages = Vec::new();
    let mut sans = Vec::new();
    let mut parsed_other_names = Vec::new();
    let mut basic_constraints = None;
    let mut subject_key_identifier = None;
    let mut authority_key_identifier = None;
    let mut policies = Vec::new();
    let mut crl_distribution_points = Vec::new();
    let mut ocsp_servers = Vec::new();
    let mut ca_issuers = Vec::new();

    for ext in tbs.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::KeyUsage(ku) => {
                key_usage = Some(KeyUsage {
                    digital_signature: ku.digital_signature(),
                    non_repudiation: ku.non_repudiation(),
                    key_encipherment: ku.key_encipherment(),
                    data_encipherment: ku.data_encipherment(),
                    key_agreement: ku.key_agreement(),
                    key_cert_sign: ku.key_cert_sign(),
                    crl_sign: ku.crl_sign(),
                    encipher_only: ku.encipher_only(),
                    decipher_only: ku.decipher_only(),
                });
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                if eku.client_auth {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: "1.3.6.1.5.5.7.3.2".to_string(),
                        name: "Autenticação de Cliente (clientAuth)".to_string(),
                    });
                }
                if eku.email_protection {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: "1.3.6.1.5.5.7.3.4".to_string(),
                        name: "Proteção de E-mail (emailProtection)".to_string(),
                    });
                }
                if eku.server_auth {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: "1.3.6.1.5.5.7.3.1".to_string(),
                        name: "Autenticação de Servidor (serverAuth)".to_string(),
                    });
                }
                if eku.code_signing {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: "1.3.6.1.5.5.7.3.3".to_string(),
                        name: "Assinatura de Código (codeSigning)".to_string(),
                    });
                }
                if eku.time_stamping {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: "1.3.6.1.5.5.7.3.8".to_string(),
                        name: "Carimbo do Tempo (timeStamping)".to_string(),
                    });
                }
                for other_oid in &eku.other {
                    extended_key_usages.push(ExtendedKeyUsageEntry {
                        oid: other_oid.to_string(),
                        name: format!("OID {}", other_oid),
                    });
                }
            }
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(d) => sans.push(SanEntry::Dns(d.to_string())),
                        GeneralName::RFC822Name(e) => sans.push(SanEntry::Email(e.to_string())),
                        GeneralName::URI(u) => sans.push(SanEntry::Uri(u.to_string())),
                        GeneralName::IPAddress(ip) => {
                            sans.push(SanEntry::Ip(format!("{:?}", ip)));
                        }
                        GeneralName::OtherName(oid, val) => {
                            let oid_str = oid.to_string();
                            parsed_other_names.push((oid_str.clone(), val.to_vec()));
                            sans.push(SanEntry::OtherName {
                                oid: oid_str,
                                value_hex: format_hex_bytes(val),
                                interpreted: None,
                            });
                        }
                        _ => {}
                    }
                }
            }
            ParsedExtension::BasicConstraints(bc) => {
                basic_constraints = Some(BasicConstraints {
                    is_ca: bc.ca,
                    path_len_constraint: bc.path_len_constraint.map(|c| c as u32),
                });
            }
            ParsedExtension::SubjectKeyIdentifier(ski) => {
                subject_key_identifier = Some(format_hex_bytes(&ski.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                if let Some(key_id) = &aki.key_identifier {
                    authority_key_identifier = Some(format_hex_bytes(&key_id.0));
                }
            }
            ParsedExtension::CRLDistributionPoints(cdp) => {
                for dp in &cdp.points {
                    if let Some(x509_parser::extensions::DistributionPointName::FullName(names)) = &dp.distribution_point {
                        for gn in names {
                            if let GeneralName::URI(uri) = gn {
                                crl_distribution_points.push(uri.to_string());
                            }
                        }
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                for desc in &aia.accessdescs {
                    let method = desc.access_method.to_string();
                    if let GeneralName::URI(uri) = &desc.access_location {
                        if method == "1.3.6.1.5.5.7.48.1" {
                            ocsp_servers.push(uri.to_string());
                        } else if method == "1.3.6.1.5.5.7.48.2" {
                            ca_issuers.push(uri.to_string());
                        }
                    }
                }
            }
            ParsedExtension::CertificatePolicies(cp) => {
                for p in cp.iter() {
                    policies.push(CertificatePolicy {
                        oid: p.policy_id.to_string(),
                        cps_uri: None,
                        user_notice: None,
                    });
                }
            }
            _ => {}
        }
    }

    let exts = CertificateExtensions {
        key_usage,
        extended_key_usages,
        subject_alternative_names: sans,
        basic_constraints,
        subject_key_identifier,
        authority_key_identifier,
        policies,
        crl_distribution_points,
        ocsp_servers,
        ca_issuers,
    };

    Ok((exts, parsed_other_names))
}

/// Desencapsula estruturas TLV (Tag-Length-Value) ASN.1 DER para extrair o valor puro
/// de campos OtherName da ICP-Brasil (como [0] EXPLICIT, OCTET STRING, PrintableString, UTF8String).
fn unwrap_asn1_tlv(mut data: &[u8]) -> &[u8] {
    while !data.is_empty() {
        let tag = data[0];
        // Tags ASN.1 que atuam como wrapper ou tipo string:
        // 0xA0: [0] EXPLICIT Context-Specific
        // 0x30: SEQUENCE
        // 0x04: OCTET STRING
        // 0x0C: UTF8String
        // 0x13: PrintableString
        // 0x14: T61String
        // 0x16: IA5String
        // 0x1E: BMPString
        if tag == 0xA0
            || tag == 0x30
            || tag == 0x04
            || tag == 0x0C
            || tag == 0x13
            || tag == 0x14
            || tag == 0x16
            || tag == 0x1E
        {
            if data.len() < 2 {
                break;
            }
            let (header_len, payload_len) = parse_asn1_length(&data[1..]);
            if header_len > 0 && 1 + header_len + payload_len <= data.len() {
                let payload = &data[1 + header_len..1 + header_len + payload_len];
                data = payload;
                if (tag == 0x0C || tag == 0x13 || tag == 0x14 || tag == 0x16 || tag == 0x1E || tag == 0x04)
                    && (!payload.starts_with(&[0xA0]) && !payload.starts_with(&[0x30]))
                {
                    break;
                }
            } else {
                break;
            }
        } else {
            break;
        }
    }
    data
}

fn parse_asn1_length(bytes: &[u8]) -> (usize, usize) {
    if bytes.is_empty() {
        return (0, 0);
    }
    let first = bytes[0];
    if first < 0x80 {
        (1, first as usize)
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes == 0 || bytes.len() < 1 + num_bytes {
            return (0, 0);
        }
        let mut len: usize = 0;
        for &b in &bytes[1..=num_bytes] {
            len = (len << 8) | (b as usize);
        }
        (1 + num_bytes, len)
    }
}

/// Extrai a identidade ICP-Brasil usando SAN OtherNames e fallback de Common Name.
fn extract_icp_brasil_identity(
    subject: &DistinguishedName,
    other_names: &[(String, Vec<u8>)],
) -> IcpBrasilIdentity {
    let mut identity = IcpBrasilIdentity::default();

    // 1. Varre os OtherNames específicos da ICP-Brasil
    for (oid, raw_val) in other_names {
        match oid.as_str() {
            OID_ICP_BR_PF_DADOS => {
                // Pessoa Física: nascimento (8), CPF (11), NIS (11), RG (15)...
                identity.person_type = Some(PersonType::PessoaFisica);
                identity.data_source_description = "SAN otherName PF (2.16.76.1.3.1)".to_string();

                let unwrapped = unwrap_asn1_tlv(raw_val);
                let s = String::from_utf8_lossy(unwrapped);
                let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 19 {
                    // Após 8 dígitos de data de nascimento, vêm 11 de CPF
                    let cpf_cand = &digits[8..19];
                    identity.cpf = Some(cpf_cand.to_string());
                }
            }
            OID_ICP_BR_PJ_NOME_RESPONSAVEL => {
                // Nome do Responsável Legal da Pessoa Jurídica
                let unwrapped = unwrap_asn1_tlv(raw_val);
                let s = String::from_utf8_lossy(unwrapped);
                let clean: String = s.chars().filter(|c| !c.is_control()).collect();
                let sanitized = clean
                    .trim_start_matches(|c: char| !c.is_alphanumeric())
                    .trim()
                    .to_string();
                if !sanitized.is_empty() && identity.holder_name.is_none() {
                    identity.holder_name = Some(sanitized);
                }
            }
            OID_ICP_BR_PJ_CNPJ => {
                // Pessoa Jurídica: CNPJ (14 dígitos)
                identity.person_type = Some(PersonType::PessoaJuridica);
                identity.data_source_description = "SAN otherName PJ (2.16.76.1.3.3)".to_string();

                let unwrapped = unwrap_asn1_tlv(raw_val);
                let s = String::from_utf8_lossy(unwrapped);
                let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 14 {
                    identity.cnpj = Some(digits[..14].to_string());
                }
            }
            OID_ICP_BR_PJ_RESPONSAVEL => {
                let unwrapped = unwrap_asn1_tlv(raw_val);
                let s = String::from_utf8_lossy(unwrapped);
                let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                if digits.len() >= 19 {
                    let cpf_resp = &digits[8..19];
                    if identity.cpf.is_none() {
                        identity.cpf = Some(cpf_resp.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    // 2. Fallback: Parse no Common Name (CN padrão ICP-Brasil: "NOME:00000000000" ou "EMPRESA:00000000000100")
    if let Some(cn) = &subject.common_name {
        if let Some((name_part, doc_part)) = cn.rsplit_once(':') {
            let doc_clean: String = doc_part.chars().filter(|c| c.is_ascii_digit()).collect();
            if doc_clean.len() == 11 && identity.cpf.is_none() {
                identity.cpf = Some(doc_clean);
                if identity.holder_name.is_none() {
                    identity.holder_name = Some(name_part.trim().to_string());
                }
                if identity.person_type.is_none() {
                    identity.person_type = Some(PersonType::PessoaFisica);
                    identity.data_source_description = "Subject Common Name (:CPF)".to_string();
                }
            } else if doc_clean.len() == 14 && identity.cnpj.is_none() {
                identity.cnpj = Some(doc_clean);
                if identity.company_name.is_none() {
                    identity.company_name = Some(name_part.trim().to_string());
                }
                if identity.person_type.is_none() {
                    identity.person_type = Some(PersonType::PessoaJuridica);
                    identity.data_source_description = "Subject Common Name (:CNPJ)".to_string();
                }
            }
        }
    }

    if identity.holder_name.is_none() {
        if let Some(cn) = &subject.common_name {
            if let Some((name_part, doc_part)) = cn.rsplit_once(':') {
                let doc_clean: String = doc_part.chars().filter(|c| c.is_ascii_digit()).collect();
                if doc_clean.len() == 11 || doc_clean.len() == 14 {
                    identity.holder_name = Some(name_part.trim().to_string());
                } else {
                    identity.holder_name = Some(cn.clone());
                }
            } else {
                identity.holder_name = Some(cn.clone());
            }
        }
    }
    if identity.company_name.is_none() {
        if let Some(cn) = &subject.common_name {
            if let Some((name_part, _)) = cn.rsplit_once(':') {
                identity.company_name = Some(name_part.trim().to_string());
            } else {
                identity.company_name = subject.organization.clone();
            }
        } else {
            identity.company_name = subject.organization.clone();
        }
    }
    if identity.email.is_none() {
        identity.email = subject.email_address.clone();
    }

    identity
}

/// Classifica o tipo de certificado (A1, A3, SSL, etc.).
fn classify_certificate_type(
    subject: &DistinguishedName,
    issuer: &DistinguishedName,
    extensions: &CertificateExtensions,
    has_private_key: bool,
    is_hardware_backed: bool,
) -> CertificateType {
    if is_hardware_backed {
        return CertificateType::A3;
    }

    let is_icp_br = subject.raw.contains("ICP-Brasil")
        || issuer.raw.contains("ICP-Brasil")
        || issuer.raw.contains("AC ")
        || extensions.policies.iter().any(|p| p.oid.starts_with("2.16.76.1"));

    if is_icp_br {
        if has_private_key {
            CertificateType::A1
        } else {
            CertificateType::A1 // Certificado ICP-Brasil
        }
    } else if extensions.extended_key_usages.iter().any(|e| e.oid == "1.3.6.1.5.5.7.3.1") {
        CertificateType::ServerSsl
    } else if extensions.extended_key_usages.iter().any(|e| e.oid == "1.3.6.1.5.5.7.3.3") {
        CertificateType::CodeSigning
    } else if has_private_key {
        CertificateType::A1
    } else {
        CertificateType::Unknown
    }
}

/// Formata bytes como sequência hexadecimal separada por dois pontos: "AA:BB:CC:...".
fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}
