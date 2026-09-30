//! Estado global da aplicação CertCheck BR.

use crate::certificate::CertificateInfo;
use crate::diagnostics::A3DiagnosticSummary;
use crate::logging::{LogLevel, MemoryLogBuffer};
use crate::revocation::RevocationSummary;
use crate::validation::ValidationResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Aba técnica selecionada na visualização de detalhes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetailTab {
    Resumo,
    Identidade,
    Chave,
    Extensoes,
    Cadeia,
    Validacao,
    Revogacao,
    Assinatura,
    A3,
    Diagnostico,
    Logs,
}

impl std::fmt::Display for DetailTab {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetailTab::Resumo => write!(f, "Resumo"),
            DetailTab::Identidade => write!(f, "Identidade"),
            DetailTab::Chave => write!(f, "Chave Pública"),
            DetailTab::Extensoes => write!(f, "Extensões"),
            DetailTab::Cadeia => write!(f, "Cadeia de Confiança"),
            DetailTab::Validacao => write!(f, "Validação"),
            DetailTab::Revogacao => write!(f, "Revogação"),
            DetailTab::Assinatura => write!(f, "Assinatura"),
            DetailTab::A3 => write!(f, "Diagnóstico A3"),
            DetailTab::Diagnostico => write!(f, "Diagnóstico Geral"),
            DetailTab::Logs => write!(f, "Logs Técnicos"),
        }
    }
}

/// Modo de tema visual da interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeMode {
    Dark,
    Light,
}

/// Configurações gerais do usuário.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub auto_check_crl: bool,
    pub auto_check_ocsp: bool,
    pub auto_validate_chain: bool,
    pub advanced_technical_mode: bool,
    pub network_timeout_seconds: u64,
    pub language: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_check_crl: false,
            auto_check_ocsp: true,
            auto_validate_chain: true,
            advanced_technical_mode: false,
            network_timeout_seconds: 10,
            language: "pt-BR".to_string(),
        }
    }
}

/// Estado reativo principal compartilhado com a interface gráfica.
pub struct AppState {
    pub certificates: Vec<CertificateInfo>,
    pub selected_cert_id: Option<String>,
    pub validation_results: HashMap<String, ValidationResult>,
    pub revocation_summaries: HashMap<String, RevocationSummary>,
    pub a3_diagnostics: Option<A3DiagnosticSummary>,

    pub active_tab: DetailTab,
    pub theme_mode: ThemeMode,
    pub config: AppConfig,

    pub log_buffer: Arc<MemoryLogBuffer>,
    pub log_search: String,
    pub log_min_level: LogLevel,

    pub is_busy: bool,
    pub busy_message: String,
    pub settings_open: bool,
    pub password_prompt: Option<PasswordPrompt>,

    // Atualizações automáticas
    pub available_update: Option<crate::updater::RemoteVersionInfo>,
    pub update_status: crate::updater::UpdateStatus,
    pub show_update_modal: bool,
    pub has_prompted_update: bool,
}

#[derive(Debug, Clone)]
pub struct PasswordPrompt {
    pub file_path: std::path::PathBuf,
    pub password_input: String,
    pub error_msg: Option<String>,
}

impl AppState {
    pub fn new(log_buffer: Arc<MemoryLogBuffer>) -> Self {
        Self {
            certificates: Vec::new(),
            selected_cert_id: None,
            validation_results: HashMap::new(),
            revocation_summaries: HashMap::new(),
            a3_diagnostics: None,

            active_tab: DetailTab::Resumo,
            theme_mode: ThemeMode::Dark,
            config: AppConfig::default(),

            log_buffer,
            log_search: String::new(),
            log_min_level: LogLevel::Info,

            is_busy: false,
            busy_message: String::new(),
            settings_open: false,
            password_prompt: None,

            available_update: None,
            update_status: crate::updater::UpdateStatus::Idle,
            show_update_modal: false,
            has_prompted_update: false,
        }
    }

    /// Retorna uma referência ao certificado atualmente selecionado.
    pub fn selected_certificate(&self) -> Option<&CertificateInfo> {
        let id = self.selected_cert_id.as_ref()?;
        self.certificates.iter().find(|c| &c.id == id)
    }

    /// Retorna o resultado da validação para o certificado atualmente selecionado.
    pub fn current_validation(&self) -> Option<&ValidationResult> {
        let id = self.selected_cert_id.as_ref()?;
        self.validation_results.get(id)
    }

    /// Retorna o resumo de revogação para o certificado atualmente selecionado.
    pub fn current_revocation(&self) -> Option<&RevocationSummary> {
        let id = self.selected_cert_id.as_ref()?;
        self.revocation_summaries.get(id)
    }
}
