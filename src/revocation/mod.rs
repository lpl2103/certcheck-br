//! Módulo de verificação de revogação de certificados (CRL e OCSP).

pub mod model;
pub mod online;

pub use model::{CrlDetails, OcspDetails, RevocationStatus, RevocationSummary};
pub use online::verify_revocation_online;

