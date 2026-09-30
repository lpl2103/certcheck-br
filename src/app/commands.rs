//! Despacho de comandos assíncronos e eventos de comunicação com a interface.

use crate::certificate::CertificateInfo;
use crate::diagnostics::A3DiagnosticSummary;
use crate::error::CertCheckError;
use crate::revocation::RevocationSummary;
use crate::validation::ValidationResult;
use std::path::PathBuf;

/// Comandos emitidos pela interface gráfica para os workers de background.
#[derive(Debug, Clone)]
pub enum AppCommand {
    /// Atualizar certificados da Windows Certificate Store
    RefreshWindowsStore,
    /// Carregar arquivo de certificado (.pfx, .p12, .cer, .crt, .pem)
    LoadCertificateFile {
        path: PathBuf,
        password: Option<String>,
    },
    /// Iniciar detecção de hardware A3 (leitores, smartcards, tokens)
    DetectA3Hardware,
    /// Executar conjunto completo de validações no certificado
    ValidateCertificate { cert_id: String },
    /// Consultar revogação via CRL e OCSP
    CheckRevocation { cert_id: String },
    /// Executar teste de assinatura digital
    TestSignature { cert_id: String, hash_alg: String },
    /// Exportar relatório de diagnóstico em JSON
    ExportReportJson { cert_id: String, destination: PathBuf },
    /// Verificar se há atualizações disponíveis no GitHub
    CheckForUpdates,
    /// Executar download e substituição do executável
    TriggerAutoUpdate { download_url: Option<String> },
}

/// Eventos retornados dos workers de background para a interface gráfica.
#[derive(Debug, Clone)]
pub enum AppEvent {
    BusyStateChanged { is_busy: bool, message: String },
    CertificatesLoaded(Vec<CertificateInfo>),
    CertificateAdded(Box<CertificateInfo>),
    ValidationCompleted { cert_id: String, result: ValidationResult },
    RevocationCompleted { cert_id: String, summary: RevocationSummary },
    A3DiagnosticsUpdated(A3DiagnosticSummary),
    SignatureTestCompleted { cert_id: String, success: bool, message: String },
    OperationError(CertCheckError),
    PasswordRequired { path: PathBuf, reason: String },
    StatusNotification(String),
    UpdateCheckCompleted(Option<crate::updater::RemoteVersionInfo>),
    UpdateStatusChanged(crate::updater::UpdateStatus),
}
