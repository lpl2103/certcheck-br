//! Ponto central da interface gráfica com egui/eframe.

pub mod a3;
pub mod certificates;
pub mod dashboard;
pub mod details;
pub mod diagnostics;
pub mod revocation;
pub mod settings;
pub mod signature;
pub mod theme;
pub mod tools;
pub mod validation;

use crate::app::{AppCommand, AppEvent, AppState, ThemeMode};
use crate::gui::certificates::render_certificates_sidebar;
use crate::gui::details::render_certificate_details;
use crate::gui::settings::render_settings_dialog;
use crate::gui::theme::{configure_native_fonts, configure_visuals, ThemeColors};
use crossbeam_channel::{Receiver, Sender};
use eframe::App;
use egui::{RichText, TopBottomPanel};

pub struct CertCheckApp {
    state: AppState,
    command_sender: Sender<AppCommand>,
    event_receiver: Receiver<AppEvent>,
}

impl CertCheckApp {
    pub fn new(
        state: AppState,
        command_sender: Sender<AppCommand>,
        event_receiver: Receiver<AppEvent>,
        cc: &eframe::CreationContext<'_>,
    ) -> Self {
        // Inicializa fontes nativas do Windows (Segoe UI e Segoe UI Emoji) e escala aumentada
        configure_native_fonts(&cc.egui_ctx);

        // Inicializa tema padrão
        configure_visuals(&cc.egui_ctx, state.theme_mode);

        Self {
            state,
            command_sender,
            event_receiver,
        }
    }

    /// Processa eventos emitidos pelos workers em background.
    fn handle_events(&mut self, ctx: &egui::Context) {
        let mut got_event = false;
        while let Ok(event) = self.event_receiver.try_recv() {
            got_event = true;
            match event {
                AppEvent::BusyStateChanged { is_busy, message } => {
                    self.state.is_busy = is_busy;
                    self.state.busy_message = message;
                }
                AppEvent::CertificatesLoaded(store_certs) => {
                    self.state.certificates.retain(|c| !matches!(c.source, crate::certificate::CertificateSource::WindowsStore { .. }));
                    for c in &store_certs {
                        self.state.certificates.push(c.clone());
                    }
                    if self.state.selected_cert_id.is_none() {
                        if let Some(first) = self.state.certificates.first() {
                            self.state.selected_cert_id = Some(first.id.clone());
                        }
                    }
                    self.state.password_prompt = None;
                }
                AppEvent::CertificateAdded(cert) => {
                    let id = cert.id.clone();
                    self.state.certificates.retain(|c| c.id != id);
                    self.state.certificates.push(*cert);
                    self.state.selected_cert_id = Some(id);
                    self.state.password_prompt = None;
                    self.state.last_error_message = None;
                    self.state.last_status_message = None;
                }
                AppEvent::ValidationCompleted { cert_id, result } => {
                    self.state.validation_results.insert(cert_id, result);
                }
                AppEvent::RevocationCompleted { cert_id, summary } => {
                    self.state.revocation_summaries.insert(cert_id, summary);
                }
                AppEvent::A3DiagnosticsUpdated(diag) => {
                    self.state.a3_diagnostics = Some(diag);
                }
                AppEvent::SignatureTestCompleted { message, .. } => {
                    tracing::info!("Resultado do teste de assinatura: {}", message);
                }
                AppEvent::OperationError(err) => {
                    tracing::error!("Erro operacional [{}]: {}", err.category() as u8, err);
                    self.state.last_error_message = Some(format!("{}", err));
                }
                AppEvent::PasswordRequired { path, reason } => {
                    self.state.password_prompt = Some(crate::app::PasswordPrompt {
                        file_path: path,
                        password_input: String::new(),
                        error_msg: Some(reason),
                    });
                }
                AppEvent::StatusNotification(msg) => {
                    tracing::info!("{}", msg);
                    self.state.last_status_message = Some(msg);
                }
                AppEvent::UpdateCheckCompleted(info) => {
                    if let Some(ref update) = info {
                        tracing::info!("Atualização disponível detectada: v{}", update.version);
                        if !self.state.has_prompted_update {
                            self.state.show_update_modal = true;
                            self.state.has_prompted_update = true;
                        }
                    } else {
                        tracing::info!("Nenhuma atualização disponível.");
                    }
                    self.state.available_update = info;
                }
                AppEvent::UpdateStatusChanged(status) => {
                    self.state.update_status = status;
                }
                AppEvent::EnvironmentDiagnosticCompleted(diag) => {
                    self.state.env_diagnostic = Some(diag);
                }
                AppEvent::ConnectivityTestCompleted(tests) => {
                    self.state.connectivity_results = tests;
                }
                AppEvent::ToolOperationCompleted { tool_name, success, message } => {
                    self.state.tool_feedback_message = Some((success, format!("{tool_name}: {message}")));
                }
                AppEvent::FileSigningCompleted { success: _, result } => {
                    self.state.file_signing_result = Some(result);
                }
            }
        }
        if got_event {
            ctx.request_repaint();
        }
    }
}

impl App for CertCheckApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Processa eventos assíncronos
        self.handle_events(ctx);

        let colors = ThemeColors::for_mode(self.state.theme_mode);

        // Barra Superior
        TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("🛡 CertCheck BR")
                        .size(19.0)
                        .strong()
                        .color(colors.info),
                );
                ui.label(
                    RichText::new("v".to_owned() + env!("CARGO_PKG_VERSION"))
                        .size(12.0)
                        .color(colors.neutral),
                );

                if let Some(ref update) = self.state.available_update {
                    let update_btn = egui::Button::new(
                        RichText::new(format!("🚀 Nova v{} disponível!", update.version))
                            .size(12.0)
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0, 140, 60))
                    .corner_radius(egui::CornerRadius::same(6));

                    if ui.add(update_btn).clicked() {
                        self.state.show_update_modal = true;
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(RichText::new("⚙ Configurações").strong()).clicked() {
                        self.state.settings_open = true;
                    }

                    ui.separator();

                    let is_dark = self.state.theme_mode == ThemeMode::Dark;
                    let theme_icon = if is_dark { "🌙 Escuro" } else { "☀ Claro" };
                    if ui.button(theme_icon).clicked() {
                        let next_theme = if is_dark {
                            ThemeMode::Light
                        } else {
                            ThemeMode::Dark
                        };
                        self.state.theme_mode = next_theme;
                        configure_visuals(ctx, next_theme);
                    }
                });
            });
            ui.add_space(4.0);
        });

        // Barra de Status Inferior
        TopBottomPanel::bottom("bottom_status_bar").show(ctx, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let cert_count = self.state.certificates.len();
                ui.label(
                    RichText::new(format!("{} certificado(s) carregado(s)", cert_count))
                        .size(11.0)
                        .color(colors.neutral),
                );

                if self.state.is_busy {
                    ui.separator();
                    ui.spinner();
                    ui.label(
                        RichText::new(&self.state.busy_message)
                            .size(11.0)
                            .color(colors.info),
                    );
                } else if let Some(ref err) = self.state.last_error_message {
                    ui.separator();
                    ui.label(
                        RichText::new(format!("⚠ {}", err))
                            .size(11.0)
                            .color(colors.error),
                    );
                    if ui.small_button("✕").on_hover_text("Fechar aviso").clicked() {
                        self.state.last_error_message = None;
                    }
                } else if let Some(ref msg) = self.state.last_status_message {
                    ui.separator();
                    ui.label(
                        RichText::new(format!("ℹ {}", msg))
                            .size(11.0)
                            .color(colors.info),
                    );
                    if ui.small_button("✕").on_hover_text("Fechar mensagem").clicked() {
                        self.state.last_status_message = None;
                    }
                } else {
                    ui.separator();
                    ui.label(
                        RichText::new("Pronto")
                            .size(11.0)
                            .color(colors.pass),
                    );
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("ICP-Brasil • X.509 • A1 / A3 Windows")
                            .size(11.0)
                            .color(colors.neutral),
                    );
                });
            });
            ui.add_space(2.0);
        });

        // Barra Lateral Esquerda: Gerenciador e Lista de Certificados em Cartões
        egui::SidePanel::left("cert_sidebar")
            .resizable(true)
            .default_width(360.0)
            .min_width(310.0)
            .max_width(520.0)
            .show(ctx, |ui| {
                render_certificates_sidebar(ui, &mut self.state, &self.command_sender);
            });

        // Painel Central: Diagnóstico Técnico Completo e Abas
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    render_certificate_details(ui, &mut self.state, &self.command_sender);
                });
        });

        // Diálogo modal de configurações
        render_settings_dialog(ctx, &mut self.state, &self.command_sender);

        // Diálogo modal de senha para arquivos PFX protegidos
        render_password_dialog(ctx, &mut self.state, &self.command_sender);

        // Diálogo modal de nova versão disponível
        render_update_dialog(ctx, &mut self.state, &self.command_sender);
    }
}

/// Diálogo modal interativo para digitação de senha de arquivos .PFX / .P12 protegidos.
fn render_password_dialog(
    ctx: &egui::Context,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let Some(mut prompt) = state.password_prompt.clone() else {
        return;
    };

    let colors = ThemeColors::for_mode(state.theme_mode);
    let mut close_dialog = false;
    let mut submit_password = false;

    // Fundo escuro semitransparente (Modal Backdrop)
    egui::Area::new(egui::Id::new("password_modal_backdrop"))
        .order(egui::Order::Middle)
        .interactable(true)
        .show(ctx, |ui| {
            ui.painter().rect_filled(
                ctx.screen_rect(),
                0.0,
                egui::Color32::from_black_alpha(160),
            );
        });

    egui::Window::new(RichText::new("🔑 Senha do Certificado Digital").strong())
        .id(egui::Id::new("password_dialog_window"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .default_width(420.0)
        .show(ctx, |ui| {
            ui.add_space(4.0);
            let file_name = prompt
                .file_path
                .file_name()
                .and_then(|f| f.to_str())
                .unwrap_or("certificado.pfx");

            ui.label(
                RichText::new(format!("📄 Arquivo: {}", file_name))
                    .strong()
                    .size(13.5),
            );

            ui.add_space(4.0);
            ui.label(
                RichText::new("Este arquivo PKCS#12 (.pfx/.p12) está protegido por senha. Informe a chave para descriptografar e ler os dados do titular:")
                    .size(12.5)
                    .color(colors.neutral),
            );

            if let Some(ref err) = prompt.error_msg {
                ui.add_space(6.0);
                egui::Frame::NONE
                    .fill(colors.error.gamma_multiply(0.15))
                    .corner_radius(egui::CornerRadius::same(6))
                    .stroke(egui::Stroke::new(1.0_f32, colors.error))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("⚠").color(colors.error).strong());
                            ui.label(RichText::new(err).color(colors.error).size(12.0));
                        });
                    });
            }

            ui.add_space(8.0);
            ui.label(RichText::new("Senha de Proteção:").strong().size(13.0));
            let pw_field = ui.add(
                egui::TextEdit::singleline(&mut prompt.password_input)
                    .password(true)
                    .hint_text("Digite a senha do certificado...")
                    .desired_width(ui.available_width()),
            );

            if prompt.password_input.is_empty() && !pw_field.has_focus() {
                pw_field.request_focus();
            }

            let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
            if enter_pressed && !prompt.password_input.is_empty() {
                submit_password = true;
            }

            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                close_dialog = true;
            }

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(6.0);

            ui.horizontal(|ui| {
                if ui.button(RichText::new("✖ Cancelar").size(13.0)).clicked() {
                    close_dialog = true;
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let confirm_btn = egui::Button::new(
                        RichText::new("🔓 Abrir Certificado")
                            .color(egui::Color32::WHITE)
                            .strong()
                            .size(13.0),
                    )
                    .fill(colors.accent)
                    .corner_radius(egui::CornerRadius::same(6));

                    if ui.add(confirm_btn).clicked() {
                        submit_password = true;
                    }
                });
            });
        });

    if submit_password {
        state.last_error_message = None;
        let _ = command_sender.send(AppCommand::LoadCertificateFile {
            path: prompt.file_path.clone(),
            password: Some(prompt.password_input.clone()),
        });
        prompt.error_msg = None;
        state.password_prompt = Some(prompt);
        ctx.request_repaint();
    } else if close_dialog {
        state.password_prompt = None;
        ctx.request_repaint();
    } else {
        state.password_prompt = Some(prompt);
    }
}

/// Diálogo modal interativo para notificação e download de nova versão do CertCheck BR.
fn render_update_dialog(
    ctx: &egui::Context,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    if !state.show_update_modal {
        return;
    }

    let Some(ref info) = state.available_update.clone() else {
        return;
    };

    let colors = ThemeColors::for_mode(state.theme_mode);
    let mut close_dialog = false;

    // Fundo escuro semitransparente (Modal Backdrop)
    egui::Area::new(egui::Id::new("update_modal_backdrop"))
        .order(egui::Order::Middle)
        .interactable(true)
        .show(ctx, |ui| {
            ui.painter().rect_filled(
                ctx.screen_rect(),
                0.0,
                egui::Color32::from_black_alpha(160),
            );
        });

    egui::Window::new(RichText::new("🚀 Nova Versão Disponível").strong())
        .id(egui::Id::new("update_dialog_window"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.add_space(4.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("Uma nova versão do CertCheck BR está pronta para download!")
                        .size(14.0)
                        .strong(),
                );
            });

            ui.add_space(8.0);
            ui.group(|ui| {
                ui.horizontal(|ui| {
                    ui.label("Versão Instalada:");
                    ui.label(
                        RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                            .monospace()
                            .strong(),
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("Nova Versão no GitHub:");
                    ui.label(
                        RichText::new(format!("v{}", info.version))
                            .monospace()
                            .strong()
                            .color(egui::Color32::from_rgb(0, 200, 80)),
                    );
                });
                if !info.release_notes.is_empty() {
                    ui.add_space(4.0);
                    ui.label(RichText::new("Notas da Versão:").strong().size(12.0));
                    egui::ScrollArea::vertical()
                        .max_height(100.0)
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(&info.release_notes)
                                    .small()
                                    .weak(),
                            );
                        });
                }
            });

            ui.add_space(10.0);

            match state.update_status {
                crate::updater::UpdateStatus::Idle => {
                    ui.horizontal(|ui| {
                        if ui.button(RichText::new("Mais Tarde").size(13.0)).clicked() {
                            close_dialog = true;
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let btn_update = egui::Button::new(
                                RichText::new(format!("⬇ Baixar e Atualizar para v{}", info.version))
                                    .color(egui::Color32::WHITE)
                                    .strong()
                                    .size(13.0),
                            )
                            .fill(egui::Color32::from_rgb(0, 140, 60))
                            .corner_radius(egui::CornerRadius::same(6));

                            if ui.add(btn_update).clicked() {
                                let _ = command_sender.send(AppCommand::TriggerAutoUpdate {
                                    download_url: Some(info.download_url.clone()),
                                });
                            }
                        });
                    });
                }
                crate::updater::UpdateStatus::Downloading(progress) => {
                    ui.label(format!("Baixando atualização... ({:.0}%)", progress * 100.0));
                    ui.add(egui::ProgressBar::new(progress).animate(true));
                    ui.add_space(4.0);
                    ui.label(
                        RichText::new("O aplicativo será reiniciado automaticamente ao concluir.")
                            .small()
                            .italics()
                            .color(colors.neutral),
                    );
                }
                crate::updater::UpdateStatus::Success(ref msg) => {
                    ui.label(
                        RichText::new(msg)
                            .color(egui::Color32::from_rgb(0, 200, 80))
                            .strong()
                            .size(13.0),
                    );
                }
                crate::updater::UpdateStatus::Error(ref err) => {
                    egui::Frame::NONE
                        .fill(colors.error.gamma_multiply(0.15))
                        .corner_radius(egui::CornerRadius::same(6))
                        .stroke(egui::Stroke::new(1.0_f32, colors.error))
                        .inner_margin(egui::Margin::symmetric(10, 6))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("Erro ao atualizar: {}", err))
                                    .color(colors.error)
                                    .size(12.0),
                            );
                        });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("Fechar").clicked() {
                            close_dialog = true;
                        }
                        if ui.button("Tentar Novamente").clicked() {
                            let _ = command_sender.send(AppCommand::TriggerAutoUpdate {
                                download_url: Some(info.download_url.clone()),
                            });
                        }
                    });
                }
            }
            ui.add_space(4.0);
        });

    if close_dialog {
        state.show_update_modal = false;
    }
}
