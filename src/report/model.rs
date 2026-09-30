//! Modelo de relatório técnico estruturado e exportação JSON.

use crate::certificate::CertificateInfo;
use crate::diagnostics::A3DiagnosticSummary;
use crate::revocation::RevocationSummary;
use crate::validation::ValidationResult;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Relatório consolidado para exportação em JSON e apresentação técnica.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    pub generated_at: DateTime<Utc>,
    pub app_version: String,
    pub certificate: CertificateInfo,
    pub validation: ValidationResult,
    pub revocation: RevocationSummary,
    pub a3_diagnostics: Option<A3DiagnosticSummary>,
}

impl DiagnosticReport {
    pub fn new(
        certificate: CertificateInfo,
        validation: ValidationResult,
        revocation: RevocationSummary,
        a3_diagnostics: Option<A3DiagnosticSummary>,
    ) -> Self {
        Self {
            generated_at: Utc::now(),
            app_version: env!("CARGO_PKG_VERSION").to_string(),
            certificate,
            validation,
            revocation,
            a3_diagnostics,
        }
    }

    /// Serializa o relatório como string JSON formatada (pretty print).
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
