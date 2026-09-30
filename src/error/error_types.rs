//! Tipos e definições de erros do CertCheck BR.
//!
//! Todas as falhas são modeladas como tipos fortemente tipados com `thiserror`,
//! garantindo rastreabilidade técnica sem expor segredos ou utilizar `unwrap()`.

use thiserror::Error;

/// Categoria ou camada onde o erro ocorreu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ErrorCategory {
    Certificate,
    Validation,
    Chain,
    Trust,
    Revocation,
    Crypto,
    Provider,
    SmartCard,
    Network,
    Io,
}

/// Erro principal do CertCheck BR.
#[derive(Error, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum CertCheckError {
    #[error("Erro ao analisar estrutura X.509: {0}")]
    CertificateParseError(String),

    #[error("Certificado expirado em {expiration}")]
    CertificateExpired { expiration: String },

    #[error("Certificado ainda não é válido. Válido a partir de {not_before}")]
    CertificateNotYetValid { not_before: String },

    #[error("Falha ao construir a cadeia de certificação: {0}")]
    ChainBuildError(String),

    #[error("Erro de validação de confiança: {0}")]
    TrustError(String),

    #[error("Erro na verificação de revogação: {0}")]
    RevocationError(String),

    #[error("Falha na consulta OCSP ({url}): {reason}")]
    OcspError { url: String, reason: String },

    #[error("Falha no download/processamento da CRL ({url}): {reason}")]
    CrlError { url: String, reason: String },

    #[error("Erro no provider criptográfico ({provider}): {reason}")]
    ProviderError { provider: String, reason: String },

    #[error("Falha na comunicação com o Smart Card/Token: {0}")]
    SmartCardError(String),

    #[error("Erro na operação de assinatura digital: {0}")]
    SigningError(String),

    #[error("Senha incorreta ou arquivo PKCS#12 corrompido")]
    InvalidPasswordOrCorruptPkcs12,

    #[error("Chave privada não encontrada no arquivo/dispositivo")]
    PrivateKeyNotFound,

    #[error("Erro de E/S de arquivo: {0}")]
    IoError(String),

    #[error("Operação cancelada pelo usuário")]
    Cancelled,

    #[error("Operação não suportada nesta plataforma ou dispositivo: {0}")]
    Unsupported(String),
}

impl CertCheckError {
    /// Identifica a camada técnica responsável pelo erro.
    pub fn category(&self) -> ErrorCategory {
        match self {
            CertCheckError::CertificateParseError(_)
            | CertCheckError::CertificateExpired { .. }
            | CertCheckError::CertificateNotYetValid { .. }
            | CertCheckError::InvalidPasswordOrCorruptPkcs12 => ErrorCategory::Certificate,

            CertCheckError::ChainBuildError(_) => ErrorCategory::Chain,
            CertCheckError::TrustError(_) => ErrorCategory::Trust,

            CertCheckError::RevocationError(_)
            | CertCheckError::OcspError { .. }
            | CertCheckError::CrlError { .. } => ErrorCategory::Revocation,

            CertCheckError::ProviderError { .. } => ErrorCategory::Provider,
            CertCheckError::SmartCardError(_) => ErrorCategory::SmartCard,

            CertCheckError::SigningError(_)
            | CertCheckError::PrivateKeyNotFound => ErrorCategory::Crypto,

            CertCheckError::IoError(_) => ErrorCategory::Io,
            CertCheckError::Cancelled | CertCheckError::Unsupported(_) => ErrorCategory::Validation,
        }
    }
}
