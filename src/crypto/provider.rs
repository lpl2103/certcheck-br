//! Abstração fundamental de provedor criptográfico (`CryptoProvider`).
//!
//! Permite desacoplar operações de hardware (KSP, CSP, PKCS#11) e software (PFX/P12),
//! garantindo que chaves privadas permaneçam seguras no dispositivo.

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// Identificador de certificado gerenciado por um provider.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CertificateId(pub String);

/// Algoritmo de hash para operações de assinatura.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "SHA-256"),
            HashAlgorithm::Sha384 => write!(f, "SHA-384"),
            HashAlgorithm::Sha512 => write!(f, "SHA-512"),
        }
    }
}

/// Esquema de preenchimento (padding) para assinatura.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignaturePadding {
    Pkcs1v15,
    Pss,
    None, // ECDSA ou raw
}

/// Metadados do provedor criptográfico.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderInfo {
    pub name: String,
    pub provider_type: String, // ex: "CNG / KSP", "CryptoAPI / CSP", "PKCS#11", "Software PKCS#12"
    pub version: Option<String>,
    pub manufacturer: Option<String>,
    pub hardware_backed: bool,
    pub supports_pin_dialog: bool,
}

/// Resultado de uma operação de assinatura digital.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: String,
    pub raw_bytes: Vec<u8>,
    pub hex: String,
}

impl Signature {
    pub fn new(algorithm: impl Into<String>, bytes: Vec<u8>) -> Self {
        let hex = bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
        Self {
            algorithm: algorithm.into(),
            raw_bytes: bytes,
            hex,
        }
    }
}

/// Abstração base de operações criptográficas sem exposição de chaves privadas.
pub trait CryptoProvider: Send + Sync {
    /// Obtém informações descritivas do provedor.
    fn provider_info(&self) -> Result<ProviderInfo>;

    /// Assina um bloco de dados usando a chave privada associada ao certificado.
    ///
    /// NUNCA exporta a chave. A operação é delegada ao módulo de segurança ou CSP/KSP.
    fn sign(
        &self,
        certificate_id: &CertificateId,
        hash_alg: HashAlgorithm,
        padding: SignaturePadding,
        data_to_sign: &[u8],
    ) -> Result<Signature>;

    /// Verifica se a chave privada está acessível para operações.
    fn test_private_key_access(&self, certificate_id: &CertificateId) -> Result<bool>;
}
