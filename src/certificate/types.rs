use serde::{Deserialize, Serialize};

/// Origem ou fonte de onde o certificado foi carregado.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateSource {
    FilePfx(String),
    FileP12(String),
    FileCer(String),
    FileCrt(String),
    FilePem(String),
    WindowsStore { store_name: String },
    HardwareToken { reader_name: String },
}

impl std::fmt::Display for CertificateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateSource::FilePfx(_) => write!(f, "Arquivo PFX"),
            CertificateSource::FileP12(_) => write!(f, "Arquivo P12"),
            CertificateSource::FileCer(_) => write!(f, "Arquivo CER"),
            CertificateSource::FileCrt(_) => write!(f, "Arquivo CRT"),
            CertificateSource::FilePem(_) => write!(f, "Arquivo PEM"),
            CertificateSource::WindowsStore { store_name } => write!(f, "Windows Store ({})", store_name),
            CertificateSource::HardwareToken { reader_name } => write!(f, "Token/Cartão ({})", reader_name),
        }
    }
}

/// Classificação do tipo de certificado digital.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateType {
    A1,
    A3,
    A4,
    ServerSsl,
    CodeSigning,
    TimeStamping,
    Unknown,
}

impl std::fmt::Display for CertificateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertificateType::A1 => write!(f, "A1 (Software)"),
            CertificateType::A3 => write!(f, "A3 (Hardware/Token)"),
            CertificateType::A4 => write!(f, "A4 (HSM)"),
            CertificateType::ServerSsl => write!(f, "Servidor SSL/TLS"),
            CertificateType::CodeSigning => write!(f, "Assinatura de Código"),
            CertificateType::TimeStamping => write!(f, "Carimbo de Tempo"),
            CertificateType::Unknown => write!(f, "Desconhecido"),
        }
    }
}

/// Algoritmo da chave pública.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyAlgorithm {
    Rsa { bits: usize, exponent: u64 },
    Ecdsa { curve: String, bits: usize },
    Ed25519,
    Other(String),
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Rsa { bits, exponent } => write!(f, "RSA ({} bits, e={})", bits, exponent),
            KeyAlgorithm::Ecdsa { curve, bits } => write!(f, "ECDSA ({}, {} bits)", curve, bits),
            KeyAlgorithm::Ed25519 => write!(f, "Ed25519"),
            KeyAlgorithm::Other(name) => write!(f, "{}", name),
        }
    }
}

/// Representação de Distinguished Name (DN) X.500.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistinguishedName {
    pub raw: String,
    pub common_name: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub country: Option<String>,
    pub state_or_province: Option<String>,
    pub locality: Option<String>,
    pub email_address: Option<String>,
    pub serial_number: Option<String>,
}

impl DistinguishedName {
    pub fn display_name(&self) -> &str {
        self.common_name
            .as_deref()
            .unwrap_or(if self.raw.is_empty() { "Desconhecido" } else { &self.raw })
    }

    /// Retorna o nome de exibição amigável e limpo, sem o sufixo numérico normativo (ex: ":00000000000" ou ":00000000000100").
    pub fn clean_name(&self) -> &str {
        let name = self.display_name();
        if let Some((clean, doc)) = name.rsplit_once(':') {
            let doc_trimmed = doc.trim();
            if doc_trimmed.chars().all(|c| c.is_ascii_digit())
                && (doc_trimmed.len() == 11 || doc_trimmed.len() == 14)
            {
                let clean_trimmed = clean.trim();
                if !clean_trimmed.is_empty() {
                    return clean_trimmed;
                }
            }
        }
        name
    }
}

/// Fingerprints criptográficos calculados sobre o DER do certificado.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprints {
    pub sha256: String,
    pub sha1: String,
}

/// Flags padrão da extensão Key Usage (RFC 5280).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUsage {
    pub digital_signature: bool,
    pub non_repudiation: bool,
    pub key_encipherment: bool,
    pub data_encipherment: bool,
    pub key_agreement: bool,
    pub key_cert_sign: bool,
    pub crl_sign: bool,
    pub encipher_only: bool,
    pub decipher_only: bool,
}

/// Item da extensão Extended Key Usage (EKU).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedKeyUsageEntry {
    pub oid: String,
    pub name: String,
}

/// Entradas do Subject Alternative Name (SAN).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanEntry {
    Dns(String),
    Email(String),
    Ip(String),
    Uri(String),
    OtherName { oid: String, value_hex: String, interpreted: Option<String> },
}

/// Restrições básicas (Basic Constraints).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicConstraints {
    pub is_ca: bool,
    pub path_len_constraint: Option<u32>,
}

/// Políticas de certificado e qualificadores.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificatePolicy {
    pub oid: String,
    pub cps_uri: Option<String>,
    pub user_notice: Option<String>,
}

/// Agrupamento das extensões do certificado X.509.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateExtensions {
    pub key_usage: Option<KeyUsage>,
    pub extended_key_usages: Vec<ExtendedKeyUsageEntry>,
    pub subject_alternative_names: Vec<SanEntry>,
    pub basic_constraints: Option<BasicConstraints>,
    pub subject_key_identifier: Option<String>,
    pub authority_key_identifier: Option<String>,
    pub policies: Vec<CertificatePolicy>,
    pub crl_distribution_points: Vec<String>,
    pub ocsp_servers: Vec<String>,
    pub ca_issuers: Vec<String>,
}
