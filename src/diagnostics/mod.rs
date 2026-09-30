//! Módulo de diagnósticos de hardware, middleware e conectividade.

pub mod model;

pub use model::{
    A3DiagnosticSummary, ConnectivityCheck, ProviderDiagnostic, ReaderInfo, TokenInfo,
};
