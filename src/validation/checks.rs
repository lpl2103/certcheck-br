//! Definição dos status e modelos de checagem de validação do certificado.

use serde::{Deserialize, Serialize};

/// Status individual de uma regra ou checagem técnica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    Pass,
    Info,
    Warning,
    Error,
    NotChecked,
    NotApplicable,
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Pass => write!(f, "PASS"),
            CheckStatus::Info => write!(f, "INFO"),
            CheckStatus::Warning => write!(f, "AVISO"),
            CheckStatus::Error => write!(f, "FALHA"),
            CheckStatus::NotChecked => write!(f, "NÃO VERIFICADO"),
            CheckStatus::NotApplicable => write!(f, "N/A"),
        }
    }
}

/// Camada arquitetural da validação técnica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckCategory {
    X509Structure,
    ValidityPeriod,
    KeyCharacteristics,
    KeyUsage,
    ExtendedKeyUsage,
    BasicConstraints,
    Extensions,
    TrustChain,
    IcpBrasilPolicy,
    RevocationCrl,
    RevocationOcsp,
    CryptographicSignature,
    HardwareProvider,
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckCategory::X509Structure => write!(f, "Estrutura X.509"),
            CheckCategory::ValidityPeriod => write!(f, "Período de Validade"),
            CheckCategory::KeyCharacteristics => write!(f, "Chave Pública"),
            CheckCategory::KeyUsage => write!(f, "Key Usage"),
            CheckCategory::ExtendedKeyUsage => write!(f, "Extended Key Usage"),
            CheckCategory::BasicConstraints => write!(f, "Basic Constraints"),
            CheckCategory::Extensions => write!(f, "Extensões X.509"),
            CheckCategory::TrustChain => write!(f, "Cadeia de Confiança"),
            CheckCategory::IcpBrasilPolicy => write!(f, "Políticas ICP-Brasil"),
            CheckCategory::RevocationCrl => write!(f, "Revogação (CRL)"),
            CheckCategory::RevocationOcsp => write!(f, "Revogação (OCSP)"),
            CheckCategory::CryptographicSignature => write!(f, "Assinatura Criptográfica"),
            CheckCategory::HardwareProvider => write!(f, "Provider / Hardware"),
        }
    }
}

/// Item individual de validação com detalhes técnicos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub category: CheckCategory,
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    pub technical_details: Option<String>,
}

impl ValidationCheck {
    pub fn new(
        category: CheckCategory,
        name: impl Into<String>,
        status: CheckStatus,
        message: impl Into<String>,
        details: Option<&str>,
    ) -> Self {
        Self {
            category,
            name: name.into(),
            status,
            message: message.into(),
            technical_details: details.map(|d| d.to_string()),
        }
    }
}
