//! Módulo de tratamento de erros do CertCheck BR.

pub mod error_types;

pub use error_types::{CertCheckError, ErrorCategory};

/// Tipo Result padrão para o CertCheck BR.
pub type Result<T> = std::result::Result<T, CertCheckError>;
