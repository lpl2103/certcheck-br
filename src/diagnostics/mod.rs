//! Módulo de diagnósticos de hardware, middleware e conectividade.

pub mod model;
pub mod winscard;

pub use model::{
    A3DiagnosticSummary, ConnectivityCheck, ProviderDiagnostic, ReaderInfo, TokenInfo,
};
pub use winscard::scan_a3_hardware;

