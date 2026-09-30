//! Painel de detalhes de validações técnicas X.509 e regras de negócio.

use crate::app::{AppCommand, AppState};
use crate::gui::theme::{render_status_badge, ThemeColors};
use crossbeam_channel::Sender;
use egui::{CornerRadius, Frame, Margin, RichText, Stroke, Ui};

pub fn render_validation_panel(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    let Some(cert) = state.selected_certificate().cloned() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    let Some(val) = state.validation_results.get(&cert.id).cloned() else {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(RichText::new("Validação técnica ainda não executada para este certificado.").color(colors.neutral));
            ui.add_space(8.0);
            if ui.button(RichText::new("⚡ Validar Certificado").strong()).clicked() {
                let _ = command_sender.send(AppCommand::ValidateCertificate { cert_id: cert.id.clone() });
            }
        });
        return;
    };

    // Cabeçalho da Aba de Conformidade
    ui.horizontal(|ui| {
        ui.label(RichText::new("🛡").size(20.0));
        ui.vertical(|ui| {
            ui.label(RichText::new("Conformidade Técnica e Normativa").size(16.5).strong());
            ui.label(
                RichText::new("Diagnóstico analítico segundo padrões RFC 5280, DOC-ICP-04 e requisitos da ICP-Brasil")
                    .size(12.0)
                    .color(colors.neutral),
            );
        });

        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(RichText::new("⚡ Revalidar Tudo").color(colors.pass).strong()).clicked() {
                let _ = command_sender.send(AppCommand::ValidateCertificate { cert_id: cert.id.clone() });
            }
        });
    });

    ui.add_space(6.0);

    // Contadores de Status Compactos
    ui.horizontal(|ui| {
        render_metric_pill(ui, "Aprovados", val.count_passed(), colors.pass, "✔");
        ui.add_space(6.0);
        render_metric_pill(ui, "Avisos", val.count_warnings(), colors.warning, "⚠");
        ui.add_space(6.0);
        render_metric_pill(ui, "Falhas", val.count_errors(), colors.error, "✖");
        ui.add_space(6.0);
        render_metric_pill(ui, "Info", val.count_info(), colors.info, "ℹ");
    });

    ui.add_space(8.0);
    ui.separator();
    ui.add_space(6.0);

    // Lista de Regras Técnicas Avaliadas (Sem ScrollArea aninhado)
    for check in &val.checks {
        Frame::NONE
            .fill(colors.card_bg)
            .stroke(Stroke::new(1.0_f32, colors.border))
            .corner_radius(CornerRadius::same(6))
            .inner_margin(Margin::symmetric(12, 8))
            .show(ui, |ui| {
                // Linha 1: Badge + Nome da Checagem + Categoria Normativa
                ui.horizontal(|ui| {
                    render_status_badge(ui, check.status, state.theme_mode);
                    ui.add_space(6.0);
                    ui.label(RichText::new(&check.name).strong().size(13.5));

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!("{}", check.category))
                                .size(11.5)
                                .color(colors.neutral),
                        );
                    });
                });

                ui.add_space(3.0);

                // Linha 2: Mensagem clara do diagnóstico
                ui.label(RichText::new(&check.message).size(13.0));

                // Linha 3: Detalhes Técnicos Avançados (se houver)
                if let Some(details) = &check.technical_details {
                    if !details.is_empty() {
                        ui.add_space(2.0);
                        ui.collapsing(
                            RichText::new("🔎 Detalhes Técnicos Normativos (ASN.1 / OID / RFC)")
                                .size(11.5)
                                .color(colors.neutral),
                            |ui| {
                                Frame::NONE
                                    .fill(colors.header_bg)
                                    .corner_radius(CornerRadius::same(4))
                                    .inner_margin(Margin::same(6))
                                    .show(ui, |ui| {
                                        ui.label(RichText::new(details).monospace().size(11.0));
                                    });
                            },
                        );
                    }
                }
            });

        ui.add_space(4.0);
    }
}

fn render_metric_pill(ui: &mut Ui, label: &str, count: usize, color: egui::Color32, icon: &str) {
    Frame::NONE
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.35)))
        .corner_radius(CornerRadius::same(5))
        .inner_margin(Margin::symmetric(10, 3))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(12.0));
                ui.label(RichText::new(count.to_string()).size(13.5).color(color).strong());
                ui.label(RichText::new(label).size(12.0).color(color));
            });
        });
}
