//! Testes unitários do domínio do CertCheck BR.

use certcheck_br::certificate::*;
use certcheck_br::error::{CertCheckError, ErrorCategory};
use certcheck_br::icp_brasil::*;
use certcheck_br::logging::{sanitize_log_message, LogEntry, LogLevel, MemoryLogBuffer};
use certcheck_br::report::DiagnosticReport;
use certcheck_br::revocation::*;
use certcheck_br::validation::*;
use chrono::{Duration, Utc};

#[test]
fn test_distinguished_name_display() {
    let dn_cn = DistinguishedName {
        raw: "CN=JOAO DA SILVA, C=BR".to_string(),
        common_name: Some("JOAO DA SILVA".to_string()),
        ..Default::default()
    };
    assert_eq!(dn_cn.display_name(), "JOAO DA SILVA");

    let dn_raw = DistinguishedName {
        raw: "O=EMPRESA SEM CN, C=BR".to_string(),
        common_name: None,
        ..Default::default()
    };
    assert_eq!(dn_raw.display_name(), "O=EMPRESA SEM CN, C=BR");
}

#[test]
fn test_certificate_validity_calculations() {
    let now = Utc::now();
    let cert = CertificateInfo {
        id: "test_cert".to_string(),
        source: CertificateSource::FilePem("test.pem".to_string()),
        cert_type: CertificateType::A1,
        subject: DistinguishedName::default(),
        issuer: DistinguishedName::default(),
        serial_number_hex: "01:02:03".to_string(),
        not_before: now - Duration::days(10),
        not_after: now + Duration::days(50),
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key: KeyAlgorithm::Rsa { bits: 2048, exponent: 65537 },
        fingerprints: Fingerprints::default(),
        extensions: CertificateExtensions::default(),
        identity: IcpBrasilIdentity::default(),
        has_private_key: true,
        is_hardware_backed: false,
    };

    assert!(cert.is_currently_valid(now));
    assert_eq!(cert.days_remaining(now), 50);

    let summary = cert.validity_summary(now);
    assert!(summary.contains("Válido"));
    assert!(summary.contains("50 dias"));
}

#[test]
fn test_icp_brasil_cpf_cnpj_formatting() {
    let id_pf = IcpBrasilIdentity {
        person_type: Some(PersonType::PessoaFisica),
        cpf: Some("12345678901".to_string()),
        ..Default::default()
    };
    assert_eq!(id_pf.formatted_cpf().as_deref(), Some("123.456.789-01"));

    let id_pj = IcpBrasilIdentity {
        person_type: Some(PersonType::PessoaJuridica),
        cnpj: Some("12345678000199".to_string()),
        ..Default::default()
    };
    assert_eq!(id_pj.formatted_cnpj().as_deref(), Some("12.345.678/0001-99"));
}

#[test]
fn test_validation_result_decision_logic() {
    let mut val = ValidationResult::new();

    // Vazio -> Não verificado
    assert_eq!(val.compute_overall_status(), OverallStatus::NaoVerificado);

    // Adiciona apenas checagens PASS -> Apto
    val.add_check(ValidationCheck::new(
        CheckCategory::X509Structure,
        "X.509",
        CheckStatus::Pass,
        "Válido",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::AptoParaUso);
    assert_eq!(val.count_passed(), 1);
    assert_eq!(val.count_warnings(), 0);
    assert_eq!(val.count_errors(), 0);

    // Adiciona WARNING -> Com Restrições
    val.add_check(ValidationCheck::new(
        CheckCategory::RevocationCrl,
        "CRL",
        CheckStatus::Warning,
        "CRL offline",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::ComRestricoes);
    assert_eq!(val.count_warnings(), 1);

    // Adiciona ERROR -> Inapto
    val.add_check(ValidationCheck::new(
        CheckCategory::ValidityPeriod,
        "Validade",
        CheckStatus::Error,
        "Expirado",
        None,
    ));
    assert_eq!(val.compute_overall_status(), OverallStatus::Inapto);
    assert_eq!(val.count_errors(), 1);
}

#[test]
fn test_revocation_summary_logic() {
    let mut summary = RevocationSummary::default();
    assert_eq!(summary.determine_status(), RevocationStatus::NotChecked);

    // Adiciona OCSP indisponível
    summary.ocsp_checks.push(OcspDetails {
        url: "http://ocsp.test".to_string(),
        status: RevocationStatus::Unavailable,
        responder_id: None,
        produced_at: None,
        this_update: None,
        next_update: None,
        revocation_time: None,
        revocation_reason: None,
        error_message: Some("Timeout de conexão".to_string()),
    });
    assert_eq!(summary.determine_status(), RevocationStatus::Unavailable);

    // Adiciona CRL Good
    summary.crl_checks.push(CrlDetails {
        url: "http://crl.test".to_string(),
        status: RevocationStatus::Good,
        this_update: None,
        next_update: None,
        crl_number: None,
        issuer: None,
        revocation_time: None,
        revocation_reason: None,
        error_message: None,
        cached: false,
    });
    assert_eq!(summary.determine_status(), RevocationStatus::Good);

    // Se houver qualquer indicação de REVOKED, o veredito final deve ser REVOKED
    summary.ocsp_checks[0].status = RevocationStatus::Revoked;
    assert_eq!(summary.determine_status(), RevocationStatus::Revoked);
}

#[test]
fn test_icp_brasil_oids_recognition() {
    assert!(is_icp_brasil_oid(OID_ICP_BR_PF_DADOS));
    assert!(is_icp_brasil_oid(OID_ICP_BR_PJ_CNPJ));
    assert!(is_icp_brasil_oid(OID_POLICY_A3));
    assert!(!is_icp_brasil_oid("1.3.6.1.5.5.7.3.2")); // clientAuth

    assert!(describe_icp_oid(OID_ICP_BR_PF_DADOS).is_some());
    assert!(describe_icp_oid(OID_ICP_BR_PJ_CNPJ).is_some());
    assert!(describe_icp_oid(OID_POLICY_A1).is_some());
    assert!(describe_icp_oid("1.2.3.4.5").is_none());
}

#[test]
fn test_error_category_mapping() {
    let err_exp = CertCheckError::CertificateExpired {
        expiration: "2025-01-01".to_string(),
    };
    assert_eq!(err_exp.category(), ErrorCategory::Certificate);

    let err_crl = CertCheckError::CrlError {
        url: "http://crl.exemplo.br".to_string(),
        reason: "404 Not Found".to_string(),
    };
    assert_eq!(err_crl.category(), ErrorCategory::Revocation);

    let err_sign = CertCheckError::SigningError("Chave inacessível".to_string());
    assert_eq!(err_sign.category(), ErrorCategory::Crypto);

    let err_sc = CertCheckError::SmartCardError("Cartão não detectado".to_string());
    assert_eq!(err_sc.category(), ErrorCategory::SmartCard);
}

#[test]
fn test_logging_buffer_and_sanitization() {
    let buffer = MemoryLogBuffer::new(3);

    assert_eq!(sanitize_log_message("teste com senha=1234"), "teste com senha=[REDACTED]");
    assert_eq!(sanitize_log_message("token com pin=5678"), "token com pin=[REDACTED]");

    buffer.push(LogEntry::new(LogLevel::Info, "test", "Mensagem normal"));
    buffer.push(LogEntry::new(LogLevel::Warn, "test", "Tentativa com senha=supersecret123"));
    buffer.push(LogEntry::new(LogLevel::Error, "crypto", "Falha de pin=9876 no token"));

    let entries = buffer.get_filtered(LogLevel::Trace, "");
    assert_eq!(entries.len(), 3);

    // Verifica sanitização
    let warn_entry = entries.iter().find(|e| e.level == LogLevel::Warn).unwrap();
    assert!(!warn_entry.message.contains("supersecret123"));
    assert!(warn_entry.message.contains("[REDACTED]"));

    let error_entry = entries.iter().find(|e| e.level == LogLevel::Error).unwrap();
    assert!(!error_entry.message.contains("9876"));
    assert!(error_entry.message.contains("[REDACTED]"));

    // Teste de capacidade máxima
    buffer.push(LogEntry::new(LogLevel::Info, "test", "Quarta mensagem"));
    let entries_after = buffer.get_filtered(LogLevel::Trace, "");
    assert_eq!(entries_after.len(), 3);
    assert_eq!(entries_after[0].message, "Tentativa com senha=[REDACTED]");
}

#[test]
fn test_report_json_serialization() {
    let now = Utc::now();
    let cert = CertificateInfo {
        id: "cert_json_test".to_string(),
        source: CertificateSource::FilePfx("teste.pfx".to_string()),
        cert_type: CertificateType::A1,
        subject: DistinguishedName {
            raw: "CN=EMPRESA TESTE, C=BR".to_string(),
            common_name: Some("EMPRESA TESTE".to_string()),
            organization: Some("EMPRESA TESTE".to_string()),
            ..Default::default()
        },
        issuer: DistinguishedName {
            raw: "CN=AC RAIZ, C=BR".to_string(),
            common_name: Some("AC RAIZ".to_string()),
            ..Default::default()
        },
        serial_number_hex: "01:AA:BB".to_string(),
        not_before: now - Duration::days(1),
        not_after: now + Duration::days(364),
        signature_algorithm: "sha256WithRSAEncryption".to_string(),
        public_key: KeyAlgorithm::Rsa { bits: 2048, exponent: 65537 },
        fingerprints: Fingerprints {
            sha256: "AA:BB:CC".to_string(),
            sha1: "11:22:33".to_string(),
        },
        extensions: CertificateExtensions::default(),
        identity: IcpBrasilIdentity {
            person_type: Some(PersonType::PessoaJuridica),
            cnpj: Some("12345678000199".to_string()),
            ..Default::default()
        },
        has_private_key: true,
        is_hardware_backed: false,
    };

    let mut val = ValidationResult::new();
    val.add_check(ValidationCheck::new(
        CheckCategory::X509Structure,
        "X.509",
        CheckStatus::Pass,
        "Conforme",
        None,
    ));
    val.compute_overall_status();

    let report = DiagnosticReport::new(cert, val, RevocationSummary::default(), None);
    let json = report.to_json_pretty().expect("Falha na serialização JSON");

    assert!(json.contains("EMPRESA TESTE"));
    assert!(json.contains("12345678000199"));
    assert!(json.contains("AptoParaUso"));
    assert!(!json.contains("senha"));
    assert!(!json.contains("private_key_raw"));
}

#[test]
fn test_windows_store_enumeration_runs_without_panic() {
    let result = certcheck_br::certificate::windows_store::enumerate_a1_certificates();
    assert!(result.is_ok(), "Enumeração do Windows Certificate Store deve rodar com sucesso: {:?}", result.err());
    let certs = result.unwrap();
    println!("Certificados encontrados no repositório pessoal: {}", certs.len());
    for c in &certs {
        assert!(!c.id.is_empty());
        assert!(!c.fingerprints.sha1.is_empty());
        assert!(!c.fingerprints.sha256.is_empty());
    }
}

#[test]
fn test_real_pfx_import_and_identity_extraction() {
    use certcheck_br::certificate::windows_store::import_pfx_certificates;

    let test_files = [
        ("CD_Armindo_Senha12345678.pfx", Some("12345678")),
        ("2026 AFC COMERCIO DE ROUPAS LTDA_55902817000147.pfx", Some("afc2026")),
        ("certificadoAF.pfx", Some("aire2026")),
        ("certificadoSkyler.pfx", Some("sklrn2026")),
    ];

    for (file_name, pwd) in test_files {
        let path = std::path::Path::new(file_name);
        if !path.exists() {
            println!("Arquivo {} não encontrado na raiz, ignorando.", file_name);
            continue;
        }

        let bytes = std::fs::read(path).expect("Leitura do arquivo PFX falhou");
        let certs = import_pfx_certificates(&bytes, pwd, file_name)
            .expect("Falha ao importar PFX com Windows CryptoAPI");

        assert!(!certs.is_empty(), "PFX deve conter pelo menos 1 certificado");
        let cert = &certs[0];

        // Garante que NÃO é o mock antigo "EMPRESA ARQUIVO LTDA"
        assert_ne!(cert.subject.display_name(), "certificadoAF.pfx");
        assert_ne!(cert.subject.organization.as_deref(), Some("EMPRESA ARQUIVO LTDA"));

        // Deve conter CNPJ formatado válido
        let cnpj = cert.identity.formatted_cnpj();
        assert!(cnpj.is_some(), "Certificado {} deve conter CNPJ formatado", file_name);

        // Garante que o nome limpo do titular não contém resíduos de ASN.1 nem sufixos numéricos
        let clean_title = cert.subject.clean_name();
        assert!(!clean_title.contains(':'), "clean_name não deve conter o sufixo com dois pontos");

        let holder = cert.identity.holder_name.as_ref().expect("holder_name deve estar preenchido");
        assert!(!holder.starts_with('\u{FFFD}'), "holder_name não pode conter caractere de substituição UTF-8");
        assert!(!holder.starts_with('!'), "holder_name não pode iniciar com '!'");
        assert!(!holder.starts_with('"'), "holder_name não pode iniciar com '\"'");
        assert!(!holder.starts_with('#'), "holder_name não pode iniciar com '#'");
        assert!(holder.chars().next().unwrap().is_alphabetic(), "holder_name deve iniciar com letra do alfabeto");

        println!("Certificado: {} | CNPJ: {:?} | CPF: {:?} | Holder: {:?}", clean_title, cnpj, cert.identity.formatted_cpf(), holder);
    }
}

#[test]
fn test_pfx_import_without_password() {
    use certcheck_br::certificate::windows_store::import_pfx_certificates;

    let test_files = [
        "CD_Armindo_Senha12345678.pfx",
        "2026 AFC COMERCIO DE ROUPAS LTDA_55902817000147.pfx",
        "certificadoAF.pfx",
        "certificadoSkyler.pfx",
    ];

    for file_name in test_files {
        let path = std::path::Path::new(file_name);
        if !path.exists() { continue; }
        let bytes = std::fs::read(path).unwrap();
        let res = import_pfx_certificates(&bytes, None, file_name);
        println!("File: {} -> Result: {:?}", file_name, res.is_ok());
        if let Ok(ref certs) = res {
            println!("  Total certs in PFX: {}", certs.len());
            for (idx, c) in certs.iter().enumerate() {
                let is_ca = c.extensions.basic_constraints.as_ref().map(|bc| bc.is_ca).unwrap_or(false);
                println!("  [{}] CN: {} | is_ca: {} | has_pk: {} | hw: {}", idx, c.subject.clean_name(), is_ca, c.has_private_key, c.is_hardware_backed);
            }
        }
        if let Err(ref e) = res {
            println!("Error: {:?}", e);
        }
    }
}

#[test]
fn test_check_for_updates_runs() {
    let info = certcheck_br::updater::check_for_updates();
    println!("Update info: {:?}", info);
}


