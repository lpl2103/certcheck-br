//! Painel de consulta e diagnóstico de revogação (CRL e OCSP) responsivo e sem overflow.

use crate::app::{AppCommand, AppState};
use crate::gui::theme::ThemeColors;
use crate::revocation::{RevocationStatus, RevocationSummary};
use crossbeam_channel::Sender;
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke, Ui};

pub fn render_revocation_panel(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    let Some(cert) = state.selected_certificate().cloned() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    let summary = state.current_revocation().cloned();

    // 1. Cabeçalho com Botão de Consulta Online
    ui.horizontal(|ui| {
        ui.heading("🚫 Verificação de Revogação de Certificados");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let check_btn = egui::Button::new(
                RichText::new("🔍 Consultar Revogação (Online)")
                    .color(Color32::WHITE)
                    .strong(),
            )
            .fill(colors.accent)
            .corner_radius(CornerRadius::same(6));

            if ui.add(check_btn).clicked() {
                let _ = command_sender.send(AppCommand::CheckRevocation {
                    cert_id: cert.id.clone(),
                });
            }
        });
    });

    ui.add_space(8.0);

    // 2. Banner de Status Consolidado de Revogação
    render_overall_revocation_banner(ui, summary.as_ref(), &colors);

    ui.add_space(10.0);

    // 3. Seção: Listas de Certificados Revogados (CRL / LCR)
    render_crl_section(ui, &cert, summary.as_ref(), &colors);

    ui.add_space(12.0);

    // 4. Seção: Protocolo OCSP (Online Certificate Status Protocol)
    render_ocsp_section(ui, &cert, summary.as_ref(), &colors);

    ui.add_space(10.0);
}

fn render_overall_revocation_banner(
    ui: &mut Ui,
    summary: Option<&RevocationSummary>,
    colors: &ThemeColors,
) {
    let (bg, border, emoji, title, desc) = match summary.and_then(|s| s.final_status) {
        Some(RevocationStatus::Good) => (
            colors.pass.gamma_multiply(0.18),
            colors.pass,
            "✅",
            "CERTIFICADO ÍNTEGRO / NÃO REVOGADO",
            "Nenhum registro de revogação foi localizado nas Listas de Certificados Revogados (CRL) nem no serviço OCSP.",
        ),
        Some(RevocationStatus::Revoked) => (
            colors.error.gamma_multiply(0.18),
            colors.error,
            "❌",
            "CERTIFICADO CONSTA COMO REVOGADO",
            "O certificado foi revogado pela Autoridade Certificadora emissora e não deve ser utilizado para assinaturas.",
        ),
        Some(RevocationStatus::Unavailable) | Some(RevocationStatus::Error) => (
            colors.warning.gamma_multiply(0.18),
            colors.warning,
            "⚠",
            "SERVIÇOS DE REVOGAÇÃO INDISPONÍVEIS",
            "Não foi possível contatar os pontos de distribuição de CRL ou servidores OCSP no momento.",
        ),
        _ => (
            colors.neutral.gamma_multiply(0.15),
            colors.border,
            "⏳",
            "DIAGNÓSTICO DE REVOGAÇÃO PENDENTE",
            "Clique no botão '🔍 Consultar Revogação (Online)' para verificar o status em tempo real junto à Autoridade Certificadora.",
        ),
    };

    Frame::NONE
        .fill(bg)
        .stroke(Stroke::new(1.2_f32, border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(emoji).size(22.0));
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(15.0).color(border).strong());
                    ui.add(egui::Label::new(RichText::new(desc).size(12.5)).wrap());
                });
            });
        });
}

fn render_crl_section(
    ui: &mut Ui,
    cert: &crate::certificate::CertificateInfo,
    summary: Option<&RevocationSummary>,
    colors: &ThemeColors,
) {
    Frame::NONE
        .fill(colors.card_bg)
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("📋").size(16.0));
                ui.label(RichText::new("Listas de Certificados Revogados (CRL / LCR)").size(15.5).strong());
            });

            ui.add_space(3.0);
            ui.separator();
            ui.add_space(6.0);

            if cert.extensions.crl_distribution_points.is_empty() {
                Frame::NONE
                    .fill(colors.warning.gamma_multiply(0.12))
                    .stroke(Stroke::new(1.0_f32, colors.warning.gamma_multiply(0.4)))
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("⚠").color(colors.warning).strong());
                            ui.add(egui::Label::new(
                                RichText::new("Nenhum Ponto de Distribuição de CRL (CDP) foi encontrado nas extensões X.509 deste certificado.")
                                    .color(colors.warning)
                                    .size(12.5),
                            ).wrap());
                        });
                    });
                return;
            }

            ui.label(
                RichText::new("Pontos de distribuição configurados no certificado para download periódico das listas de revogação assinadas pela AC:")
                    .size(12.5)
                    .color(colors.neutral),
            );
            ui.add_space(8.0);

            for (idx, url) in cert.extensions.crl_distribution_points.iter().enumerate() {
                let check_match = summary.and_then(|s| {
                    s.crl_checks.iter().find(|c| &c.url == url || (s.crl_checks.len() == 1 && cert.extensions.crl_distribution_points.len() == 1))
                });

                render_crl_card(ui, idx + 1, url, check_match, colors);
                ui.add_space(8.0);
            }
        });
}

fn render_crl_card(
    ui: &mut Ui,
    idx: usize,
    url: &str,
    check: Option<&crate::revocation::CrlDetails>,
    colors: &ThemeColors,
) {
    Frame::NONE
        .fill(colors.card_bg.gamma_multiply(0.7))
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            // Linha 1: Título do Ponto e Botão de Cópia
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("🌐 Ponto de Distribuição CRL #{}", idx)).strong().size(13.5));

                if let Some(c) = check {
                    let (status_text, status_color) = match c.status {
                        RevocationStatus::Good => ("✔ VÁLIDO (NÃO CONSTA)", colors.pass),
                        RevocationStatus::Revoked => ("❌ REVOGADO", colors.error),
                        RevocationStatus::Unavailable => ("⚠ INDISPONÍVEL", colors.warning),
                        RevocationStatus::Error => ("❌ ERRO", colors.error),
                        _ => ("⏳ PENDENTE", colors.neutral),
                    };

                    Frame::NONE
                        .fill(status_color.gamma_multiply(0.15))
                        .stroke(Stroke::new(1.0_f32, status_color))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(RichText::new(status_text).color(status_color).size(11.0).strong());
                        });
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(RichText::new("📋 Copiar URL").size(12.0)).clicked() {
                        ui.ctx().copy_text(url.to_string());
                    }
                });
            });

            ui.add_space(6.0);

            // Linha 2: Caixa da URL com quebra de linha (wrap) garantida
            Frame::NONE
                .fill(colors.card_bg)
                .stroke(Stroke::new(1.0_f32, colors.border.gamma_multiply(0.6)))
                .corner_radius(CornerRadius::same(4))
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(url)
                                .monospace()
                                .size(12.0)
                                .color(colors.info),
                        )
                        .wrap(),
                    );
                });

            // Linha 3: Detalhes da Consulta (se realizada)
            if let Some(c) = check {
                ui.add_space(6.0);
                egui::Grid::new(ui.id().with(format!("crl_grid_{}", idx)))
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        if let Some(this_up) = &c.this_update {
                            ui.label(RichText::new("Última publicação (thisUpdate):").color(colors.neutral).size(12.0));
                            ui.label(RichText::new(this_up.format("%d/%m/%Y às %H:%M:%S UTC").to_string()).size(12.0).strong());
                            ui.end_row();
                        }
                        if let Some(next_up) = &c.next_update {
                            ui.label(RichText::new("Próxima publicação (nextUpdate):").color(colors.neutral).size(12.0));
                            ui.label(RichText::new(next_up.format("%d/%m/%Y às %H:%M:%S UTC").to_string()).size(12.0).strong());
                            ui.end_row();
                        }
                        if let Some(num) = &c.crl_number {
                            ui.label(RichText::new("Número sequencial da CRL:").color(colors.neutral).size(12.0));
                            ui.label(RichText::new(num).monospace().size(12.0));
                            ui.end_row();
                        }
                        if let Some(issuer) = &c.issuer {
                            ui.label(RichText::new("Emissor da CRL:").color(colors.neutral).size(12.0));
                            ui.add(egui::Label::new(RichText::new(issuer).size(12.0)).wrap());
                            ui.end_row();
                        }
                        if let Some(err) = &c.error_message {
                            ui.label(RichText::new("Erro de Conexão:").color(colors.error).size(12.0));
                            ui.add(egui::Label::new(RichText::new(err).color(colors.error).size(12.0)).wrap());
                            ui.end_row();
                        }
                    });
            }
        });
}

fn render_ocsp_section(
    ui: &mut Ui,
    cert: &crate::certificate::CertificateInfo,
    summary: Option<&RevocationSummary>,
    colors: &ThemeColors,
) {
    Frame::NONE
        .fill(colors.card_bg)
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::same(12))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("⚡").size(16.0));
                ui.label(RichText::new("Protocolo OCSP (Online Certificate Status Protocol)").size(15.5).strong());
            });

            ui.add_space(3.0);
            ui.separator();
            ui.add_space(6.0);

            if cert.extensions.ocsp_servers.is_empty() {
                Frame::NONE
                    .fill(colors.warning.gamma_multiply(0.12))
                    .stroke(Stroke::new(1.0_f32, colors.warning.gamma_multiply(0.4)))
                    .corner_radius(CornerRadius::same(6))
                    .inner_margin(Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("ℹ").color(colors.warning).strong());
                            ui.add(egui::Label::new(
                                RichText::new("Nenhum endpoint de validação rápida OCSP informado na extensão Authority Info Access (AIA) deste certificado.")
                                    .color(colors.warning)
                                    .size(12.5),
                            ).wrap());
                        });
                    });
                return;
            }

            ui.label(
                RichText::new("Servidores OCSP para validação criptográfica instantânea do status do certificado:")
                    .size(12.5)
                    .color(colors.neutral),
            );
            ui.add_space(8.0);

            for (idx, url) in cert.extensions.ocsp_servers.iter().enumerate() {
                let check_match = summary.and_then(|s| {
                    s.ocsp_checks.iter().find(|o| &o.url == url || (s.ocsp_checks.len() == 1 && cert.extensions.ocsp_servers.len() == 1))
                });

                render_ocsp_card(ui, idx + 1, url, check_match, colors);
                ui.add_space(8.0);
            }
        });
}

fn render_ocsp_card(
    ui: &mut Ui,
    idx: usize,
    url: &str,
    check: Option<&crate::revocation::OcspDetails>,
    colors: &ThemeColors,
) {
    Frame::NONE
        .fill(colors.card_bg.gamma_multiply(0.7))
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            // Linha 1: Título e Botão de Cópia
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("⚡ Servidor OCSP #{}", idx)).strong().size(13.5));

                if let Some(c) = check {
                    let (status_text, status_color) = match c.status {
                        RevocationStatus::Good => ("✔ VÁLIDO (ATIVO)", colors.pass),
                        RevocationStatus::Revoked => ("❌ REVOGADO", colors.error),
                        RevocationStatus::Unavailable => ("⚠ INDISPONÍVEL", colors.warning),
                        RevocationStatus::Error => ("❌ ERRO", colors.error),
                        _ => ("⏳ PENDENTE", colors.neutral),
                    };

                    Frame::NONE
                        .fill(status_color.gamma_multiply(0.15))
                        .stroke(Stroke::new(1.0_f32, status_color))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::symmetric(6, 2))
                        .show(ui, |ui| {
                            ui.label(RichText::new(status_text).color(status_color).size(11.0).strong());
                        });
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(RichText::new("📋 Copiar URL").size(12.0)).clicked() {
                        ui.ctx().copy_text(url.to_string());
                    }
                });
            });

            ui.add_space(6.0);

            // Linha 2: Caixa da URL com quebra de linha (wrap)
            Frame::NONE
                .fill(colors.card_bg)
                .stroke(Stroke::new(1.0_f32, colors.border.gamma_multiply(0.6)))
                .corner_radius(CornerRadius::same(4))
                .inner_margin(Margin::symmetric(8, 6))
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(
                            RichText::new(url)
                                .monospace()
                                .size(12.0)
                                .color(colors.info),
                        )
                        .wrap(),
                    );
                });

            // Linha 3: Detalhes da Resposta OCSP
            if let Some(c) = check {
                ui.add_space(6.0);
                egui::Grid::new(ui.id().with(format!("ocsp_grid_{}", idx)))
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        if let Some(resp) = &c.responder_id {
                            ui.label(RichText::new("Identificação do Responder:").color(colors.neutral).size(12.0));
                            ui.add(egui::Label::new(RichText::new(resp).size(12.0)).wrap());
                            ui.end_row();
                        }
                        if let Some(prod) = &c.produced_at {
                            ui.label(RichText::new("Resposta gerada em:").color(colors.neutral).size(12.0));
                            ui.label(RichText::new(prod.format("%d/%m/%Y às %H:%M:%S UTC").to_string()).size(12.0).strong());
                            ui.end_row();
                        }
                        if let Some(this_up) = &c.this_update {
                            ui.label(RichText::new("Validade do status (thisUpdate):").color(colors.neutral).size(12.0));
                            ui.label(RichText::new(this_up.format("%d/%m/%Y às %H:%M:%S UTC").to_string()).size(12.0));
                            ui.end_row();
                        }
                        if let Some(err) = &c.error_message {
                            ui.label(RichText::new("Erro de Conexão:").color(colors.error).size(12.0));
                            ui.add(egui::Label::new(RichText::new(err).color(colors.error).size(12.0)).wrap());
                            ui.end_row();
                        }
                    });
            }
        });
}
