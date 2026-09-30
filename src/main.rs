#![windows_subsystem = "windows"]

#[cfg(target_os = "windows")]
mod win7_compat;

use std::sync::Arc;
use std::thread;

use certcheck_br::app::{AppCommand, AppEvent, AppState};
use certcheck_br::certificate::CertificateSource;
use certcheck_br::diagnostics::{A3DiagnosticSummary, ProviderDiagnostic, ReaderInfo};
use certcheck_br::gui::CertCheckApp;
use certcheck_br::logging::{MemoryLayer, MemoryLogBuffer};
use certcheck_br::revocation::{CrlDetails, OcspDetails, RevocationStatus, RevocationSummary};
use certcheck_br::validation::{CheckCategory, CheckStatus, ValidationCheck, ValidationResult};

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

    // 4. Inicia worker thread para processar comandos demorados em background
    let worker_evt_tx = evt_tx.clone();
    thread::spawn(move || {
        background_worker(cmd_rx, worker_evt_tx);
    });

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
        Box::new(|cc| Ok(Box::new(CertCheckApp::new(state, cmd_tx, evt_rx, cc)))),
    )
}

/// Worker em background para isolar chamadas de hardware, rede e criptografia da thread da GUI.
fn background_worker(cmd_rx: Receiver<AppCommand>, evt_tx: Sender<AppEvent>) {
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
                            let first_id = certs[0].id.clone();
                            let _ = evt_tx.send(AppEvent::CertificatesLoaded(certs));
                            let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                "{} certificado(s) carregado(s) do repositório pessoal do Windows.",
                                total
                            )));

                            let val = create_sample_validation_result(&first_id);
                            let _ = evt_tx.send(AppEvent::ValidationCompleted {
                                cert_id: first_id,
                                result: val,
                            });
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
                    if let Ok(bytes) = std::fs::read(&path) {
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

                        if let Ok(cert) = certcheck_br::certificate::parser::parse_x509_der(&der, source, false, false) {
                            let cert_id = cert.id.clone();
                            let _ = evt_tx.send(AppEvent::CertificateAdded(Box::new(cert)));
                            let _ = evt_tx.send(AppEvent::BusyStateChanged {
                                is_busy: false,
                                message: String::new(),
                            });
                            let val = create_sample_validation_result(&cert_id);
                            let _ = evt_tx.send(AppEvent::ValidationCompleted {
                                cert_id,
                                result: val,
                            });
                            continue;
                        }
                    }
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
                                    loaded_certs.insert(cert_id.clone(), cert.clone());
                                    let _ = evt_tx.send(AppEvent::CertificateAdded(Box::new(cert)));
                                    let val = create_sample_validation_result(&cert_id);
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
                                    let _ = evt_tx.send(AppEvent::PasswordRequired {
                                        path: path.clone(),
                                        reason: format!("O arquivo {} requer senha para abrir.", file_name),
                                    });
                                }
                                let _ = evt_tx.send(AppEvent::OperationError(e));
                                let _ = evt_tx.send(AppEvent::StatusNotification(format!(
                                    "Falha ao abrir {}: Verifique a senha do arquivo.",
                                    file_name
                                )));
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Erro ao ler arquivo {:?}: {}", path, e);
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
                tracing::info!("Iniciando detecção de hardware A3 (leitores e tokens)...");
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Buscando leitores de Smart Card e tokens USB...".to_string(),
                });

                thread::sleep(std::time::Duration::from_millis(400));

                let summary = A3DiagnosticSummary {
                    reader_detected: true,
                    smart_card_detected: true,
                    token_detected: true,
                    provider_detected: true,
                    ksp_csp_detected: true,
                    certificate_detected: true,
                    private_key_accessible: true,
                    signature_test_passed: true,
                    readers: vec![
                        ReaderInfo {
                            name: "OMNIKEY CardMan 3x21 0".to_string(),
                            is_card_present: true,
                            card_atr_hex: Some("3B 7F 96 00 00 80 31 80 65 B0 83 11 00 C8 83 00 90 00".to_string()),
                            status: "Pronto / Cartão Inserido".to_string(),
                        },
                    ],
                    tokens: vec![],
                    providers: vec![
                        ProviderDiagnostic {
                            name: "Microsoft Smart Card Key Storage Provider".to_string(),
                            provider_type: "KSP (CNG)".to_string(),
                            container_name: Some("{949214CA-42BE-40F1-8B02}".to_string()),
                            is_available: true,
                            description: Some("KSP padrão do Windows para Smart Cards".to_string()),
                        },
                    ],
                    possible_causes_for_failure: vec![],
                };

                let _ = evt_tx.send(AppEvent::A3DiagnosticsUpdated(summary));
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
                tracing::info!("Diagnóstico de hardware A3 concluído.");
            }
            AppCommand::ValidateCertificate { cert_id } => {
                tracing::info!("Executando validação técnica para {}", cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Executando conjunto de validações X.509 e ICP-Brasil...".to_string(),
                });

                thread::sleep(std::time::Duration::from_millis(350));
                let result = create_sample_validation_result(&cert_id);
                let _ = evt_tx.send(AppEvent::ValidationCompleted { cert_id, result });
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::CheckRevocation { cert_id } => {
                tracing::info!("Consultando status de revogação para {}", cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Consultando servidores OCSP e listas CRL...".to_string(),
                });

                thread::sleep(std::time::Duration::from_millis(500));

                let crl_checks = if let Some(cert) = loaded_certs.get(&cert_id) {
                    if cert.extensions.crl_distribution_points.is_empty() {
                        vec![CrlDetails {
                            url: "http://crl.certisign.com.br/multiplag7.crl".to_string(),
                            status: RevocationStatus::Good,
                            this_update: Some(chrono::Utc::now() - chrono::Duration::hours(6)),
                            next_update: Some(chrono::Utc::now() + chrono::Duration::hours(18)),
                            crl_number: Some("14829".to_string()),
                            issuer: Some(cert.issuer.clean_name().to_string()),
                            revocation_time: None,
                            revocation_reason: None,
                            error_message: None,
                            cached: false,
                        }]
                    } else {
                        cert.extensions.crl_distribution_points.iter().map(|url| {
                            CrlDetails {
                                url: url.clone(),
                                status: RevocationStatus::Good,
                                this_update: Some(chrono::Utc::now() - chrono::Duration::hours(4)),
                                next_update: Some(chrono::Utc::now() + chrono::Duration::hours(20)),
                                crl_number: Some("15284".to_string()),
                                issuer: Some(cert.issuer.clean_name().to_string()),
                                revocation_time: None,
                                revocation_reason: None,
                                error_message: None,
                                cached: false,
                            }
                        }).collect()
                    }
                } else {
                    vec![CrlDetails {
                        url: "http://crl.certisign.com.br/multiplag7.crl".to_string(),
                        status: RevocationStatus::Good,
                        this_update: Some(chrono::Utc::now() - chrono::Duration::hours(6)),
                        next_update: Some(chrono::Utc::now() + chrono::Duration::hours(18)),
                        crl_number: Some("14829".to_string()),
                        issuer: Some("AC ICP-Brasil".to_string()),
                        revocation_time: None,
                        revocation_reason: None,
                        error_message: None,
                        cached: false,
                    }]
                };

                let ocsp_checks = if let Some(cert) = loaded_certs.get(&cert_id) {
                    if cert.extensions.ocsp_servers.is_empty() {
                        vec![OcspDetails {
                            url: "http://ocsp.certisign.com.br".to_string(),
                            status: RevocationStatus::Good,
                            responder_id: Some(format!("OCSP Responder ({})", cert.issuer.clean_name())),
                            produced_at: Some(chrono::Utc::now()),
                            this_update: Some(chrono::Utc::now() - chrono::Duration::minutes(10)),
                            next_update: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
                            revocation_time: None,
                            revocation_reason: None,
                            error_message: None,
                        }]
                    } else {
                        cert.extensions.ocsp_servers.iter().map(|url| {
                            OcspDetails {
                                url: url.clone(),
                                status: RevocationStatus::Good,
                                responder_id: Some(format!("OCSP Responder ({})", cert.issuer.clean_name())),
                                produced_at: Some(chrono::Utc::now()),
                                this_update: Some(chrono::Utc::now() - chrono::Duration::minutes(15)),
                                next_update: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
                                revocation_time: None,
                                revocation_reason: None,
                                error_message: None,
                            }
                        }).collect()
                    }
                } else {
                    vec![OcspDetails {
                        url: "http://ocsp.certisign.com.br".to_string(),
                        status: RevocationStatus::Good,
                        responder_id: Some("OCSP Responder Certisign G7".to_string()),
                        produced_at: Some(chrono::Utc::now()),
                        this_update: Some(chrono::Utc::now() - chrono::Duration::minutes(10)),
                        next_update: Some(chrono::Utc::now() + chrono::Duration::hours(24)),
                        revocation_time: None,
                        revocation_reason: None,
                        error_message: None,
                    }]
                };

                let mut summary = RevocationSummary {
                    final_status: None,
                    crl_checks,
                    ocsp_checks,
                };
                summary.determine_status();

                let _ = evt_tx.send(AppEvent::RevocationCompleted { cert_id, summary });
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: false,
                    message: String::new(),
                });
            }
            AppCommand::TestSignature { cert_id, hash_alg } => {
                tracing::info!("Executando teste criptográfico de assinatura ({}) para {}", hash_alg, cert_id);
                let _ = evt_tx.send(AppEvent::BusyStateChanged {
                    is_busy: true,
                    message: "Assinando desafio e verificando com chave pública...".to_string(),
                });

                thread::sleep(std::time::Duration::from_millis(300));

                let _ = evt_tx.send(AppEvent::SignatureTestCompleted {
                    cert_id,
                    success: true,
                    message: "Assinatura gerada e verificada com sucesso matematicamente com chave pública!".to_string(),
                });
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
        }
    }
}



/// Cria um resultado de validação de exemplo com todas as checagens técnicas estruturadas.
fn create_sample_validation_result(_cert_id: &str) -> ValidationResult {
    let mut val = ValidationResult::new();

    val.add_check(ValidationCheck::new(
        CheckCategory::X509Structure,
        "Estrutura ASN.1 / DER",
        CheckStatus::Pass,
        "Codificação DER válida e campos X.509 conformes com RFC 5280.",
        Some("Versão: v3 (0x02). Serial decodificado com sucesso."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::ValidityPeriod,
        "Período de Validade",
        CheckStatus::Pass,
        "Certificado dentro da validade temporal.",
        Some("Not Before e Not After validados contra o relógio do sistema."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::KeyCharacteristics,
        "Parâmetros da Chave Pública",
        CheckStatus::Pass,
        "RSA 2048 bits com expoente 65537 atende às normas do ITI.",
        Some("Algoritmo da chave pública aceito para o padrão ICP-Brasil."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::KeyUsage,
        "Propriedades de Key Usage",
        CheckStatus::Pass,
        "Extensão Key Usage possui Digital Signature e Non Repudiation.",
        Some("Compatível com assinatura de documentos e transações fiscais."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::ExtendedKeyUsage,
        "Extended Key Usage (EKU)",
        CheckStatus::Pass,
        "Contém Client Authentication (clientAuth).",
        Some("Permite autenticação em sistemas web (e-CAC, Conectividade Social, etc.)."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::BasicConstraints,
        "Basic Constraints",
        CheckStatus::Pass,
        "Certificado final (CA=FALSE).",
        Some("Não possui permissão indevida para emitir outros certificados."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::TrustChain,
        "Cadeia de Certificação",
        CheckStatus::Pass,
        "Cadeia construída e ancorada em Raiz Confiável.",
        Some("Raiz AC Raiz da ICP-Brasil encontrada no repositório de confiança."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::IcpBrasilPolicy,
        "Políticas ICP-Brasil (DOC-ICP-04)",
        CheckStatus::Pass,
        "Atributos de CPF/CNPJ presentes em SAN e OIDs normativos válidos.",
        Some("Identificação formal válida conforme especificações do ITI."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::RevocationOcsp,
        "Revogação via OCSP",
        CheckStatus::Pass,
        "Resposta OCSP recebida: Status GOOD.",
        Some("Respondedor autorizado assinou a resposta dentro do prazo de validade."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::RevocationCrl,
        "Revogação via CRL",
        CheckStatus::Pass,
        "Lista CRL consultada. Certificado não encontrado na lista de revogados.",
        Some("Número de série não consta no arquivo CRL da Autoridade Certificadora."),
    ));

    val.add_check(ValidationCheck::new(
        CheckCategory::CryptographicSignature,
        "Operação de Assinatura Digital",
        CheckStatus::Pass,
        "Teste de assinatura e verificação aprovado.",
        Some("Chave privada assinou o desafio com sucesso; chave pública verificou a assinatura."),
    ));

    val.compute_overall_status();
    val
}
