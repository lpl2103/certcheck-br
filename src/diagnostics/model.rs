//! Modelos de dados para diagnóstico de hardware A3, middlewares e conectividade de rede.

use serde::{Deserialize, Serialize};

/// Informações sobre um leitor de cartão inteligente.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReaderInfo {
    pub name: String,
    pub is_card_present: bool,
    pub card_atr_hex: Option<String>,
    pub status: String,
}

/// Informações sobre um token criptográfico ou smart card inserido.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub label: String,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub serial_number: Option<String>,
    pub is_read_only: bool,
    pub is_pin_initialized: bool,
}

/// Informações sobre o Cryptographic Service Provider (CSP) ou Key Storage Provider (KSP) do Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDiagnostic {
    pub name: String,
    pub provider_type: String, // "KSP (CNG)" ou "CSP (CryptoAPI)"
    pub container_name: Option<String>,
    pub is_available: bool,
    pub description: Option<String>,
}

/// Diagnóstico de teste de conectividade de rede.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityCheck {
    pub target: String,
    pub is_reachable: bool,
    pub latency_ms: Option<u64>,
    pub status_message: String,
}

/// Diagnóstico consolidado de ambiente A3 e Middleware.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct A3DiagnosticSummary {
    pub reader_detected: bool,
    pub smart_card_detected: bool,
    pub token_detected: bool,
    pub provider_detected: bool,
    pub ksp_csp_detected: bool,
    pub certificate_detected: bool,
    pub private_key_accessible: bool,
    pub signature_test_passed: bool,

    pub readers: Vec<ReaderInfo>,
    pub tokens: Vec<TokenInfo>,
    pub providers: Vec<ProviderDiagnostic>,
    pub possible_causes_for_failure: Vec<String>,
}
