//! Barra lateral de certificados em formato de cartões visuais (Card-Based Master-Detail).
//!
//! Substitui tabelas rígidas por cartões informativos, interativos e enriquecidos com emojis.

use crate::app::{AppCommand, AppState};
use crate::certificate::types::CertificateType;
use crate::gui::theme::{render_status_badge, ThemeColors};
use crate::validation::{CheckStatus, OverallStatus};
use crossbeam_channel::Sender;
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke, Ui};

pub fn render_certificates_sidebar(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    ui.add_space(4.0);

    // 1. Cabeçalho da Barra Lateral com Contagem
    ui.horizontal(|ui| {
        ui.label(RichText::new("📁 Meus Certificados").size(18.0).strong());
        let count = state.certificates.len();
        let badge_bg = if count > 0 { colors.pass.gamma_multiply(0.2) } else { colors.neutral.gamma_multiply(0.2) };
        let badge_color = if count > 0 { colors.pass } else { colors.neutral };

        Frame::NONE
            .fill(badge_bg)
            .corner_radius(CornerRadius::same(10))
            .inner_margin(Margin::symmetric(8, 2))
            .show(ui, |ui| {
                ui.label(RichText::new(format!("{}", count)).color(badge_color).strong().size(12.0));
            });
    });

    ui.add_space(10.0);

    // 2. Ações Rápidas em Destaque
    // Botão Principal: Procurar Certificados A1 instalados
    let a1_btn = egui::Button::new(
        RichText::new("🔍 Procurar A1 no Windows")
            .size(14.5)
            .color(Color32::WHITE)
            .strong(),
    )
    .fill(colors.accent)
    .corner_radius(CornerRadius::same(6))
    .min_size(egui::vec2(ui.available_width(), 34.0));

    if ui.add(a1_btn).clicked() {
        let _ = command_sender.send(AppCommand::RefreshWindowsStore);
    }

    ui.add_space(4.0);

    // Botões Secundários: Abrir Arquivo e Detectar A3
    ui.horizontal(|ui| {
        let btn_width = (ui.available_width() - 8.0) / 2.0;

        let file_btn = egui::Button::new(RichText::new("📂 Abrir Arquivo").size(13.0))
            .min_size(egui::vec2(btn_width, 28.0));
        if ui.add(file_btn).clicked() {
            let dialog = rfd::FileDialog::new()
                .add_filter(
                    "Certificados Digitais (*.pfx, *.p12, *.cer, *.crt, *.pem)",
                    &["pfx", "p12", "cer", "crt", "pem"],
                )
                .set_title("Selecionar Certificado Digital");

            if let Some(path) = dialog.pick_file() {
                let _ = command_sender.send(AppCommand::LoadCertificateFile {
                    path,
                    password: None,
                });
            }
        }

        let a3_btn = egui::Button::new(RichText::new("🔐 Detectar A3").size(13.0))
            .min_size(egui::vec2(btn_width, 28.0));
        if ui.add(a3_btn).clicked() {
            let _ = command_sender.send(AppCommand::DetectA3Hardware);
        }
    });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(8.0);

    // 3. Lista de Certificados em Cartões
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if state.certificates.is_empty() {
                // Estado Vazio Amigável
                Frame::NONE
                    .fill(colors.card_bg)
                    .corner_radius(CornerRadius::same(8))
                    .stroke(Stroke::new(1.0_f32, colors.border))
                    .inner_margin(Margin::same(16))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            ui.add_space(12.0);
                            ui.label(RichText::new("📭").size(36.0));
                            ui.add_space(6.0);
                            ui.label(RichText::new("Nenhum certificado carregado").strong().size(15.0));
                            ui.add_space(6.0);
                            ui.label(
                                RichText::new("Clique no botão acima para varrer o computador ou abra um arquivo .pfx / .cer.")
                                    .color(colors.neutral)
                                    .size(13.0),
                            );
                            ui.add_space(12.0);
                        });
                    });
                return;
            }

            let now = chrono::Utc::now();

            for cert in &state.certificates {
                let is_selected = state.selected_cert_id.as_deref() == Some(&cert.id);
                let cert_id = cert.id.clone();

                let validation = state.validation_results.get(&cert_id);
                let status = validation
                    .and_then(|v| v.overall_status)
                    .map(|s| match s {
                        OverallStatus::AptoParaUso => CheckStatus::Pass,
                        OverallStatus::ComRestricoes => CheckStatus::Warning,
                        OverallStatus::Inapto => CheckStatus::Error,
                        OverallStatus::NaoVerificado => CheckStatus::NotChecked,
                    })
                    .unwrap_or(CheckStatus::NotChecked);

                // Estilização do Cartão do Certificado
                let card_border = if is_selected {
                    Stroke::new(2.0_f32, colors.accent)
                } else {
                    Stroke::new(1.0_f32, colors.border)
                };

                let card_bg = if is_selected {
                    colors.accent.gamma_multiply(0.12)
                } else {
                    colors.card_bg
                };

                let card_response = Frame::NONE
                    .fill(card_bg)
                    .corner_radius(CornerRadius::same(8))
                    .stroke(card_border)
                    .inner_margin(Margin::same(12))
                    .show(ui, |ui| {
                        // Linha Superior: Tipo do Certificado e Badge de Status
                        ui.horizontal(|ui| {
                            let type_icon = match cert.cert_type {
                                CertificateType::A1 => "🔖 A1 (Software)",
                                CertificateType::A3 => "🔐 A3 (Token/Cartão)",
                                CertificateType::ServerSsl => "🌐 Servidor SSL",
                                CertificateType::CodeSigning => "📝 Assinatura Código",
                                _ => "📜 Certificado",
                            };

                            ui.label(RichText::new(type_icon).size(12.5).color(colors.neutral).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                render_status_badge(ui, status, state.theme_mode);
                            });
                        });

                        ui.add_space(4.0);

                        // Linha Principal: Titular em Negrito (Nome amigável sem sufixo numérico)
                        let title = cert.subject.clean_name();
                        ui.label(RichText::new(title).strong().size(14.5));

                        // Documento formatado se disponível (CNPJ prioritário para empresas, CPF para PF ou responsável)
                        if let Some(cnpj) = cert.identity.formatted_cnpj() {
                            ui.label(RichText::new(format!("🏢 CNPJ: {}", cnpj)).size(12.5).color(colors.neutral));
                            if let Some(cpf) = cert.identity.formatted_cpf() {
                                let resp_name = cert.identity.holder_name.as_deref().unwrap_or("");
                                let resp_text = if !resp_name.is_empty() && resp_name != title {
                                    format!("👤 Resp: {} ({})", resp_name, cpf)
                                } else {
                                    format!("👤 Resp CPF: {}", cpf)
                                };
                                ui.label(RichText::new(resp_text).size(11.5).color(colors.neutral));
                            }
                        } else if let Some(cpf) = cert.identity.formatted_cpf() {
                            ui.label(RichText::new(format!("👤 CPF: {}", cpf)).size(12.5).color(colors.neutral));
                        }

                        ui.add_space(2.0);

                        // Emissor resumido
                        let issuer = cert.issuer.display_name();
                        ui.label(RichText::new(format!("🏛 {}", issuer)).size(12.0).color(colors.neutral));

                        ui.add_space(4.0);

                        // Rodapé do Cartão: Validade e Origem
                        ui.horizontal(|ui| {
                            let days = cert.days_remaining(now);
                            let (val_text, val_color) = if days < 0 {
                                (format!("🔴 Expirado"), colors.error)
                            } else if days <= 30 {
                                (format!("⚠ Restam {} d", days), colors.warning)
                            } else {
                                (format!("⏳ {} dias ({})", days, cert.not_after.format("%d/%m/%y")), colors.pass)
                            };

                            ui.label(RichText::new(val_text).size(12.0).color(val_color).strong());

                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let src_label = match &cert.source {
                                    crate::certificate::types::CertificateSource::WindowsStore { .. } => "💻 Windows",
                                    _ => "📁 Arquivo",
                                };
                                ui.label(RichText::new(src_label).size(11.5).color(colors.neutral));
                            });
                        });
                    });

                // Torna todo o cartão clicável para seleção
                let interact_rect = card_response.response.rect;
                let click_response = ui.interact(
                    interact_rect,
                    ui.id().with(&cert.id),
                    egui::Sense::click(),
                );

                if click_response.clicked() {
                    state.selected_cert_id = Some(cert_id);
                }

                ui.add_space(8.0);
            }
        });
}
