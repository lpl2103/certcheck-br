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
    /// Bytes binários originais em formato DER do certificado X.509
    pub raw_der: Vec<u8>,
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

/// Abre o certificado no visualizador nativo oficial do Windows (certmgr / cryptext.dll).
#[cfg(target_os = "windows")]
pub fn open_in_windows_viewer(cert: &CertificateInfo) -> crate::error::Result<()> {
    if cert.raw_der.is_empty() {
        return Err(crate::error::CertCheckError::CertificateParseError(
            "Bytes DER originais não disponíveis para este certificado.".to_string(),
        ));
    }

    let temp_dir = std::env::temp_dir();
    let safe_name: String = cert
        .subject
        .clean_name()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect();

    let file_name = if safe_name.is_empty() {
        format!("certcheck_view_{}.cer", &cert.id)
    } else {
        format!("certcheck_view_{}.cer", safe_name)
    };

    let temp_path = temp_dir.join(file_name);
    std::fs::write(&temp_path, &cert.raw_der).map_err(|e| {
        crate::error::CertCheckError::IoError(format!(
            "Falha ao gerar arquivo temporário .cer: {}",
            e
        ))
    })?;

    // Invoca o visualizador de certificados nativo do Windows via explorer
    let _ = std::process::Command::new("explorer")
        .arg(&temp_path)
        .spawn()
        .map_err(|e| {
            crate::error::CertCheckError::IoError(format!(
                "Falha ao invocar visualizador de certificados do Windows: {}",
                e
            ))
        })?;

    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn open_in_windows_viewer(_cert: &CertificateInfo) -> crate::error::Result<()> {
    Err(crate::error::CertCheckError::Unsupported(
        "Visualizador do Windows suportado apenas em sistemas Windows.".to_string(),
    ))
}

