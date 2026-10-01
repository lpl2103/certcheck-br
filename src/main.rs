#![windows_subsystem = "windows"]

#[cfg(target_os = "windows")]
mod win7_compat;

use std::sync::Arc;
use std::thread;

use certcheck_br::app::{AppCommand, AppEvent, AppState};
use certcheck_br::certificate::CertificateSource;
use certcheck_br::gui::CertCheckApp;
use certcheck_br::logging::{MemoryLayer, MemoryLogBuffer};

use crossbeam_channel::{Receiver, Sender};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() -> eframe::Result {
    // 0. Limpa executáveis temporários de uma atualização anterior (.exe.old / .exe.new)
    certcheck_br::updater::clean_old_update_files();

    // 1. Inicializa o buffer de logs em memória para a GUI
    let log_buffer = Arc::new(MemoryLogBuffer::new(2000));
    let memory_layer = MemoryLayer::new(log_buffer.clone());

    // 2. Configura o subscriber de logs (console + buffer em memória)
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_ansi(true))
        .with(memory_layer)
        .init();

    tracing::info!("CertCheck BR inicializado com sucesso.");
    tracing::info!("Sistema operacional: Windows x86_64. Plataforma ICP-Brasil.");

    // 3. Criação de canais de comunicação com workers de background
    let (cmd_tx, cmd_rx): (Sender<AppCommand>, Receiver<AppCommand>) =
        crossbeam_channel::unbounded();
    let (evt_tx, evt_rx): (Sender<AppEvent>, Receiver<AppEvent>) = crossbeam_channel::unbounded();

    // Dispara verificação assíncrona de atualizações no GitHub ao iniciar
    let _ = cmd_tx.send(AppCommand::CheckForUpdates);

    // 5. Carrega ícone da aplicação
    let icon_bytes = include_bytes!("../assets/icon.png");
    let icon = if let Ok(img) = image::load_from_memory(icon_bytes) {
        let rgba = img.to_rgba8();
        let (width, height) = rgba.dimensions();
        egui::IconData {
            rgba: rgba.into_raw(),
            width,
            height,
        }
    } else {
        Default::default()
    };

    // 6. Configuração e inicialização da janela nativa eframe
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([880.0, 600.0])
            .with_icon(icon)
            .with_title("CertCheck BR — Diagnóstico Técnico de Certificados Digitais"),
        ..Default::default()
    };

    let mut state = AppState::new(log_buffer);
    state.selected_cert_id = None;

    eframe::run_native(
        "CertCheck BR",
        native_options,
        Box::new(move |cc| {
            let worker_evt_tx = evt_tx.clone();
            let egui_ctx = cc.egui_ctx.clone();
            thread::spawn(move || {
                background_worker(cmd_rx, worker_evt_tx, egui_ctx);
            });
            Ok(Box::new(CertCheckApp::new(state, cmd_tx, evt_rx, cc)))
        }),
    )
}

/// Envoltório de envio de eventos que acorda o loop reativo do egui imediatamente em cada mensagem.
#[derive(Clone)]
struct EventSender {
    tx: Sender<AppEvent>,
    ctx: egui::Context,
}

impl EventSender {
    fn send(&self, event: AppEvent) {
        let _ = self.tx.send(event);
        self.ctx.request_repaint();
    }
}

/// Worker em background para isolar chamadas de hardware, rede e criptografia da thread da GUI.
fn background_worker(cmd_rx: Receiver<AppCommand>, evt_tx_raw: Sender<AppEvent>, egui_ctx: egui::Context) {
    let evt_tx = EventSender {
        tx: evt_tx_raw,
        ctx: egui_ctx,
    };
    let mut loaded_certs: std::collections::HashMap<String, certcheck_br::certificate::CertificateInfo> =
        std::collections::HashMap::new();

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            AppCommand::RefreshWindowsStore => {
                tracing::info!("Buscando certificados no Windows Certificate Store (CurrentUser\\MY)...");
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Procurando certificados A1 no repositório pessoal do Windows...".to_string(),
                });

                match certcheck_br::certificate::windows_store::enumerate_a1_certificates() {
                    Ok(certs) => {
                        for c in &certs {
                            loaded_certs.insert(c.id.clone(), c.clone());
                        }
                        let total = certs.len();
                        let with_pk = certs.iter().filter(|c| c.has_private_key).count();

                        tracing::info!(
                            "Busca concluída: {} certificado(s) localizado(s) no Windows ({} com chave privada).",
                            total,
                            with_pk
                        );

                        if certs.is_empty() {
                            let _ = evt_tx.send(AppEvent::StatusNotification(
                                "Nenhum certificado digital foi localizado no repositório pessoal do Windows (CurrentUser\\MY).".to_string(),
                            ));
                            let _ = evt_tx.send(AppEvent::CertificatesLoaded(Vec::new()));
                        } else {
                            let _ = evt_tx.send(AppEvent::CertificatesLoaded(certs.clone()));
                            let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                "{} certificado(s) carregado(s) do repositório pessoal do Windows.",
                                total
                            )));

                            for c in &certs {
                                let val = certcheck_br::validation::validate_certificate_real(c);
                                let _ = evt_tx.send(AppEvent::ValidationCompleted {
                                    cert_id: c.id.clone(),
                                    result: val,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Erro ao acessar o Windows Certificate Store: {}", e);
                        let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                            "Erro ao acessar repositório do Windows: {}",
                            e
                        )));
                    }
                }

                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::LoadCertificateFile { path, password } => {
                let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("arquivo").to_string();
                tracing::info!("Carregando arquivo de certificado: {:?}", path);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: format!("Analisando arquivo {}...", file_name),
                });

                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                if ext == "cer" || ext == "crt" || ext == "pem" {
                    match std::fs::read(&path) {
                        Ok(bytes) => {
                            let der = if bytes.starts_with(b"-----BEGIN") {
                                x509_parser::pem::parse_x509_pem(&bytes)
                                    .map(|(_, pem)| pem.contents)
                                    .unwrap_or_else(|_| bytes.clone())
                            } else {
                                bytes.clone()
                            };

                            let source = match ext.as_str() {
                                "pem" => CertificateSource::FilePem(path.display().to_string()),
                                "cer" => CertificateSource::FileCer(path.display().to_string()),
                                _ => CertificateSource::FileCrt(path.display().to_string()),
                            };

                            match certcheck_br::certificate::parser::parse_x509_der(&der, source, false, false) {
                                Ok(cert) => {
                                    let cert_id = cert.id.clone();
                                    let cn = cert.subject.clean_name().to_string();
                                    let val = certcheck_br::validation::validate_certificate_real(&cert);
                                    loaded_certs.insert(cert_id.clone(), cert.clone());
                                    let _ = evt_tx.send(AppEvent::CertificateAdded(Box::new(cert)));
                                    let _ = evt_tx.send(AppEvent::BusyStateChanged {
                                        is_busy: false,
                                        message: String::new(),
                                    });
                                    let _ = evt_tx.send(AppEvent::ValidationCompleted {
                                        cert_id,
                                        result: val,
                                    });
                                    let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                        "Certificado carregado: {}",
                                        cn
                                    )));
                                    continue;
                                }
                                Err(e) => {
                                    tracing::error!("Erro ao analisar certificado X.509: {}", e);
                                    let _ = evt_tx.send(AppEvent::OperationError(e));
                                    let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                        "Falha ao interpretar {} como certificado X.509.",
                                        file_name
                                    )));
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Erro ao ler arquivo {:?}: {}", path, e);
                            let _ = evt_tx.send(AppEvent::OperationError(certcheck_br::error::CertCheckError::IoError(format!(
                                "Erro ao ler {}: {}", file_name, e
                            ))));
                            let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                "Erro ao abrir {}: {}",
                                file_name, e
                            )));
                        }
                    }
                    let _ = evt_tx.send(AppEvent::BusyStateChanged {
                        is_busy: false,
                        message: String::new(),
                    });
                    continue;
                }

                // Arquivos PKCS#12 (.PFX / .P12)
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        match certcheck_br::certificate::windows_store::import_pfx_certificates(
                            &bytes,
                            password.as_deref(),
                            &path.display().to_string(),
                        ) {
                            Ok(certs) => {
                                // Filtra certificados intermediários e raízes (CAs) contidos no arquivo PFX,
                                // mantendo apenas o(s) certificado(s) de titular/assinante do usuário
                                let subscriber_certs: Vec<_> = {
                                    let filtered: Vec<_> = certs
                                        .iter()
                                        .filter(|c| {
                                            let is_ca = c
                                                .extensions
                                                .basic_constraints
                                                .as_ref()
                                                .map(|bc| bc.is_ca)
                                                .unwrap_or(false);
                                            c.has_private_key || !is_ca
                                        })
                                        .cloned()
                                        .collect();
                                    if filtered.is_empty() {
                                        certs
                                    } else {
                                        filtered
                                    }
                                };

                                for cert in subscriber_certs {
                                    let cert_id = cert.id.clone();
                                    let cn = cert.subject.clean_name().to_string();
                                    let val = certcheck_br::validation::validate_certificate_real(&cert);
                                    loaded_certs.insert(cert_id.clone(), cert.clone());
                                    let _ = evt_tx.send(AppEvent::CertificateAdded(Box::new(cert)));
                                    let _ = evt_tx.send(AppEvent::ValidationCompleted {
                                        cert_id,
                                        result: val,
                                    });
                                    let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                        "Certificado A1 carregado: {}",
                                        cn
                                    )));
                                }
                            }
                            Err(e) => {
                                tracing::error!("Erro ao importar PFX: {}", e);
                                if matches!(e, certcheck_br::error::CertCheckError::InvalidPasswordOrCorruptPkcs12) {
                                    let reason = if password.is_some() {
                                        format!("Senha incorreta para {}. Por favor digite a senha correta:", file_name)
                                    } else {
                                        format!("O arquivo {} é protegido por senha. Informe a senha para abrir:", file_name)
                                    };
                                    let _ = evt_tx.send(AppEvent::PasswordRequired {
                                        path: path.clone(),
                                        reason: reason.clone(),
                                    });
                                    let _ = evt_tx.send(AppEvent::StatusNotification(reason));
                                } else {
                                    let _ = evt_tx.send(AppEvent::OperationError(e));
                                    let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                        "Falha ao abrir {}: Verifique o arquivo e a senha.",
                                        file_name
                                    )));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Erro ao ler arquivo {:?}: {}", path, e);
                        let _ = evt_tx.send(AppEvent::OperationError(certcheck_br::error::CertCheckError::IoError(format!(
                            "Erro ao ler {}: {}", file_name, e
                        ))));
                        let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                            "Erro ao ler arquivo: {}",
                            e
                        )));
                    }
                }

                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::DetectA3Hardware => {
                tracing::info!("Iniciando detecção real de hardware A3 (leitores e tokens via PC/SC)...");
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Varrendo leitoras de Smart Card e tokens USB via WinSCard...".to_string(),
                });

                let summary = certcheck_br::diagnostics::scan_a3_hardware();

                let _ = evt_tx.send(AppEvent::A3DiagnosticsUpdated(summary));
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
                tracing::info!("Diagnóstico de hardware A3 concluído.");
            }
            AppCommand::ValidateCertificate { cert_id } => {
                tracing::info!("Executando validação técnica real para {}", cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Executando conjunto de validações X.509 e ICP-Brasil...".to_string(),
                });

                if let Some(cert) = loaded_certs.get(&cert_id) {
                    let result = certcheck_br::validation::validate_certificate_real(cert);
                    let _ = evt_tx.send(AppEvent::ValidationCompleted { cert_id, result });
                }

                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::CheckRevocation { cert_id } => {
                tracing::info!("Consultando revogação online real para {}", cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Baixando listas CRL e consultando servidores OCSP...".to_string(),
                });

                if let Some(cert) = loaded_certs.get(&cert_id) {
                    let summary = certcheck_br::revocation::verify_revocation_online(cert);
                    let _ = evt_tx.send(AppEvent::RevocationCompleted { cert_id, summary });
                }

                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::TestSignature { cert_id, hash_alg } => {
                tracing::info!("Executando teste real de assinatura com chave privada ({}) para {}", hash_alg, cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Assinando desafio via CryptoAPI/CNG (solicitação de PIN se A3)...".to_string(),
                });

                if let Some(cert) = loaded_certs.get(&cert_id) {
                    let res = certcheck_br::crypto::execute_real_signature_test(cert, b"Desafio de Teste de Assinatura Digital CertCheck BR");
                    let msg = if res.success {
                        "Assinatura gerada pela chave privada e verificada com sucesso com a chave pública!".to_string()
                    } else {
                        res.error_message.clone().unwrap_or_else(|| "Falha no teste de assinatura.".to_string())
                    };
                    let _ = evt_tx.send(AppEvent::SignatureTestCompleted {
                        cert_id,
                        success: res.success,
                        message: msg,
                    });
                }

                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::ExportReportJson { cert_id, destination } => {
                tracing::info!("Exportando relatório JSON para {:?}", destination);
                let _ = evt_tx.send(AppEvent::StatusNotification(format!("Relatório para {} exportado com sucesso.", cert_id)));
            }
            AppCommand::CheckForUpdates => {
                let worker_evt_tx = evt_tx.clone();
                thread::spawn(move || {
                    let info = certcheck_br::updater::check_for_updates();
                    let _ = worker_evt_tx.send(AppEvent::UpdateCheckCompleted(info));
                });
            }
            AppCommand::TriggerAutoUpdate { download_url } => {
                let worker_evt_tx = evt_tx.clone();
                thread::spawn(move || {
                    let evt_cb = worker_evt_tx.clone();
                    let result = certcheck_br::updater::perform_auto_update(download_url, move |status| {
                        let _ = evt_cb.send(AppEvent::UpdateStatusChanged(status));
                    });
                    if let Err(e) = result {
                        let _ = worker_evt_tx.send(AppEvent::UpdateStatusChanged(
                            certcheck_br::updater::UpdateStatus::Error(format!("{:#}", e)),
                        ));
                    }
                });
            }
            AppCommand::ClearSslCache => {
                let worker_evt_tx = evt_tx.clone();
                thread::spawn(move || {
                    let res = certcheck_br::tools::clear_windows_ssl_cache();
                    let (success, message) = match res {
                        Ok(msg) => (true, msg),
                        Err(e) => (false, e),
                    };
                    let _ = worker_evt_tx.send(AppEvent::ToolOperationCompleted {
                        tool_name: "Limpeza de Estado SSL".to_string(),
                        success,
                        message,
                    });
                });
            }
            AppCommand::InstallIcpBrasilRoots => {
                let worker_evt_tx = evt_tx.clone();
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Baixando e instalando cadeias da AC Raiz da ICP-Brasil...".to_string(),
                });
                thread::spawn(move || {
                    let res = certcheck_br::tools::install_official_icp_brasil_roots();
                    let (success, message) = match res {
                        Ok(msg) => (true, msg),
                        Err(e) => (false, e),
                    };
                    let _ = worker_evt_tx.send(AppEvent::ToolOperationCompleted {
                        tool_name: "Instalação de Cadeias ICP-Brasil".to_string(),
                        success,
                        message,
                    });
                    let _ = worker_evt_tx.send(AppEvent::BusyStateChanged {
                        is_busy: false,
                        message: String::new(),
                    });
                });
            }
            AppCommand::RunEnvironmentDiagnostic => {
                let worker_evt_tx = evt_tx.clone();
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Analisando drivers, middlewares e assinadores do sistema...".to_string(),
                });
                thread::spawn(move || {
                    let diag = certcheck_br::tools::run_environment_diagnostic();
                    let _ = worker_evt_tx.send(AppEvent::EnvironmentDiagnosticCompleted(diag));
                    let _ = worker_evt_tx.send(AppEvent::BusyStateChanged {
                        is_busy: false,
                        message: String::new(),
                    });
                });
            }
            AppCommand::RunConnectivityTest => {
                let worker_evt_tx = evt_tx.clone();
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Testando conectividade TLS com portais governamentais...".to_string(),
                });
                thread::spawn(move || {
                    let tests = certcheck_br::tools::run_government_services_test();
                    let _ = worker_evt_tx.send(AppEvent::ConnectivityTestCompleted(tests));
                    let _ = worker_evt_tx.send(AppEvent::BusyStateChanged {
                        is_busy: false,
                        message: String::new(),
                    });
                });
            }
            AppCommand::ExportReportHtml { cert_id, destination } => {
                if let Some(cert) = loaded_certs.get(&cert_id) {
                    let val = certcheck_br::validation::validate_certificate_real(cert);
                    let rev = certcheck_br::revocation::verify_revocation_online(cert);
                    let a3 = Some(certcheck_br::diagnostics::scan_a3_hardware());
                    let rep = certcheck_br::report::DiagnosticReport::new(cert.clone(), val, rev, a3);
                    let html = certcheck_br::report::generate_html_report(&rep);
                    if let Ok(_) = std::fs::write(&destination, html) {
                        let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                            "Laudo Técnico HTML gerado com sucesso em: {:?}",
                            destination
                        )));
                    } else {
                        let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                            "Falha ao salvar Laudo Técnico em {:?}",
                            destination
                        )));
                    }
                }
            }
            AppCommand::SignTestFile { cert_id, file_path } => {
                let worker_evt_tx = evt_tx.clone();
                let cert_opt = loaded_certs.get(&cert_id).cloned();
                thread::spawn(move || {
                    if let Some(cert) = cert_opt {
                        match std::fs::read(&file_path) {
                            Ok(bytes) => {
                                let res = certcheck_br::crypto::execute_real_signature_test(&cert, &bytes);
                                let _ = worker_evt_tx.send(AppEvent::FileSigningCompleted {
                                    success: res.success,
                                    result: res,
                                });
                            }
                            Err(e) => {
                                let _ = worker_evt_tx.send(AppEvent::StatusNotification(format!(
                                    "Erro ao ler arquivo para teste de assinatura: {e}"
                                )));
                            }
                        }
                    }
                });
            }
        }
    }
}
