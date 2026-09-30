//! Modelos de dados para verificação de revogação via CRL e OCSP.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Estado de revogação de um certificado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationStatus {
    Good,
    Revoked,
    Unknown,
    NotChecked,
    Unavailable,
    Error,
}

impl std::fmt::Display for RevocationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RevocationStatus::Good => write!(f, "VÁLIDO (NÃO REVOGADO)"),
            RevocationStatus::Revoked => write!(f, "REVOGADO"),
            RevocationStatus::Unknown => write!(f, "DESCONHECIDO"),
            RevocationStatus::NotChecked => write!(f, "NÃO VERIFICADO"),
            RevocationStatus::Unavailable => write!(f, "INDISPONÍVEL"),
            RevocationStatus::Error => write!(f, "ERRO NA CONSULTA"),
        }
    }
}

/// Detalhes de uma verificação por Lista de Certificados Revogados (CRL).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlDetails {
    pub url: String,
    pub status: RevocationStatus,
    pub this_update: Option<DateTime<Utc>>,
    pub next_update: Option<DateTime<Utc>>,
    pub crl_number: Option<String>,
    pub issuer: Option<String>,
    pub revocation_time: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub error_message: Option<String>,
    pub cached: bool,
}

/// Detalhes de uma consulta via Online Certificate Status Protocol (OCSP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcspDetails {
    pub url: String,
    pub status: RevocationStatus,
    pub responder_id: Option<String>,
    pub produced_at: Option<DateTime<Utc>>,
    pub this_update: Option<DateTime<Utc>>,
    pub next_update: Option<DateTime<Utc>>,
    pub revocation_time: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub error_message: Option<String>,
}

/// Resumo consolidado das verificações de revogação do certificado.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevocationSummary {
    pub final_status: Option<RevocationStatus>,
    pub crl_checks: Vec<CrlDetails>,
    pub ocsp_checks: Vec<OcspDetails>,
}

impl RevocationSummary {
    /// Determina o veredito final de revogação combinando OCSP e CRL de forma segura.
    pub fn determine_status(&mut self) -> RevocationStatus {
        let is_any_revoked = self.ocsp_checks.iter().any(|o| o.status == RevocationStatus::Revoked)
            || self.crl_checks.iter().any(|c| c.status == RevocationStatus::Revoked);

        if is_any_revoked {
            self.final_status = Some(RevocationStatus::Revoked);
            return RevocationStatus::Revoked;
        }

        let has_good = self.ocsp_checks.iter().any(|o| o.status == RevocationStatus::Good)
            || self.crl_checks.iter().any(|c| c.status == RevocationStatus::Good);

        let status = if has_good {
            RevocationStatus::Good
        } else if self.ocsp_checks.is_empty() && self.crl_checks.is_empty() {
            RevocationStatus::NotChecked
        } else if self.ocsp_checks.iter().any(|o| o.status == RevocationStatus::Unavailable)
            || self.crl_checks.iter().any(|c| c.status == RevocationStatus::Unavailable)
        {
            RevocationStatus::Unavailable
        } else {
            RevocationStatus::Unknown
        };

        self.final_status = Some(status);
        status
    }
}
