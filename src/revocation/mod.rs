//! Módulo de verificação de revogação de certificados (CRL e OCSP).

pub mod model;

pub use model::{CrlDetails, OcspDetails, RevocationStatus, RevocationSummary};
