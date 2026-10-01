//! Módulo de abstrações criptográficas e operações de assinatura.

pub mod provider;
pub mod signing;

pub use provider::{
    CertificateId, CryptoProvider, HashAlgorithm, ProviderInfo, Signature, SignaturePadding,
};
pub use signing::execute_real_signature_test;


use serde::{Deserialize, Serialize};

/// Resultado do teste de assinatura e verificação.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureTestResult {
    pub success: bool,
    pub algorithm: String,
    pub hash_algorithm: HashAlgorithm,
    pub input_size_bytes: usize,
    pub signature_hex: Option<String>,
    pub verified: bool,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}
