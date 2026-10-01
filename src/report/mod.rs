//! Módulo de relatórios técnicos e exportação de dados.

pub mod html_report;
pub mod model;

pub use html_report::generate_html_report;
pub use model::DiagnosticReport;

