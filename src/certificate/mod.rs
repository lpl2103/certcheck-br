//! Módulo de domínio de certificados digitais X.509 e ICP-Brasil.

pub mod identity;
pub mod parser;
pub mod types;
pub mod windows_store;

pub use identity::{IcpBrasilIdentity, PersonType};
pub use types::{
    BasicConstraints, CertificateExtensions, CertificatePolicy, CertificateSource,
    CertificateType, DistinguishedName, ExtendedKeyUsageEntry, Fingerprints, KeyAlgorithm,
    KeyUsage, SanEntry,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Estrutura principal contendo todas as informações extraídas e analisadas de um certificado digital.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Identificador único em memória.
    pub id: String,
    pub source: CertificateSource,
    pub cert_type: CertificateType,
    pub subject: DistinguishedName,
    pub issuer: DistinguishedName,
    pub serial_number_hex: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub signature_algorithm: String,
    pub public_key: KeyAlgorithm,
    pub fingerprints: Fingerprints,
    pub extensions: CertificateExtensions,
    pub identity: IcpBrasilIdentity,
    pub has_private_key: bool,
    /// Chave privada reside em token/smart card físico não exportável
    pub is_hardware_backed: bool,
}

impl CertificateInfo {
    /// Retorna o número de dias restantes até a expiração (positivo) ou dias expirados (negativo).
    pub fn days_remaining(&self, now: DateTime<Utc>) -> i64 {
        let duration = self.not_after.signed_duration_since(now);
        duration.num_days()
    }

    /// Verifica se o certificado está atualmente dentro do período de validade.
    pub fn is_currently_valid(&self, now: DateTime<Utc>) -> bool {
        now >= self.not_before && now <= self.not_after
    }

    /// Retorna uma descrição em português do status de validade temporal.
    pub fn validity_summary(&self, now: DateTime<Utc>) -> String {
        if now < self.not_before {
            format!(
                "Ainda não válido (válido a partir de {})",
                self.not_before.format("%d/%m/%Y %H:%M")
            )
        } else if now > self.not_after {
            format!(
                "Expirado há {} dia(s) em {}",
                now.signed_duration_since(self.not_after).num_days(),
                self.not_after.format("%d/%m/%Y %H:%M")
            )
        } else {
            let days = self.days_remaining(now);
            format!("Válido (restam {} dias até {})", days, self.not_after.format("%d/%m/%Y"))
        }
    }
}
