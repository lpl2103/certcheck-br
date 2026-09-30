//! Visualização de resumo técnico (Dashboard) e status final de conformidade com emojis e estilo Fluent.

use crate::app::{AppState, ThemeMode};
use crate::gui::theme::{render_status_badge, ThemeColors};
use crate::validation::{CheckCategory, CheckStatus, OverallStatus};
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke, Ui};

pub fn render_dashboard(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    let Some(cert) = state.selected_certificate().cloned() else {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.label(RichText::new("🔍").size(40.0));
            ui.add_space(6.0);
            ui.label(RichText::new("Nenhum certificado selecionado").size(18.0).color(colors.neutral).strong());
            ui.add_space(6.0);
            ui.label(
                RichText::new("Selecione um certificado na barra lateral à esquerda ou clique em '🔍 Procurar A1 no Windows'.")
                    .size(13.5)
                    .color(colors.neutral),
            );
        });
        return;
    };

    let validation = state.current_validation().cloned();
    let overall_status = validation.as_ref().and_then(|v| v.overall_status).unwrap_or(OverallStatus::NaoVerificado);

    // 1. Banner Superior de Veredito Geral (Compacto)
    render_verdict_banner(ui, overall_status, state.theme_mode);

    ui.add_space(6.0);

    // 2. Contadores Numéricos de Validação (Linha compacta de pills)
    if let Some(val) = &validation {
        render_summary_counters(ui, val, state.theme_mode);
        ui.add_space(6.0);
    }

    // 3. Card de Metadados do Certificado (Margens compactas)
    render_metadata_card(ui, &cert, &colors);

    ui.add_space(8.0);

    // 4. Card de Verificações de Conformidade (Margens compactas)
    render_compliance_card(ui, validation.as_ref(), state.theme_mode, &colors);

    ui.add_space(10.0);
}

/// Renderiza o banner de veredito executivo compacto.
fn render_verdict_banner(ui: &mut Ui, status: OverallStatus, mode: ThemeMode) {
    let colors = ThemeColors::for_mode(mode);
    let (bg, border_color, emoji_icon, title, subtitle) = match status {
        OverallStatus::AptoParaUso => (
            colors.pass.gamma_multiply(0.18),
            colors.pass,
            "✅",
            "CERTIFICADO APTO PARA USO",
            "Todas as validações de estrutura X.509, validade temporal, chaves e políticas ICP-Brasil foram aprovadas.",
        ),
        OverallStatus::ComRestricoes => (
            colors.warning.gamma_multiply(0.18),
            colors.warning,
            "⚠",
            "CERTIFICADO COM RESTRIÇÕES TÉCNICAS",
            "O certificado possui alertas ou restrições que requerem atenção antes do uso em transações críticas.",
        ),
        OverallStatus::Inapto => (
            colors.error.gamma_multiply(0.18),
            colors.error,
            "❌",
            "CERTIFICADO INAPTO / INVÁLIDO",
            "O certificado expirou, foi revogado ou falhou em verificações essenciais de segurança.",
        ),
        OverallStatus::NaoVerificado => (
            colors.neutral.gamma_multiply(0.18),
            colors.neutral,
            "⏳",
            "DIAGNÓSTICO PENDENTE DE EXECUÇÃO",
            "Aguardando execução da rotina de validação e verificação de revogação.",
        ),
    };

    Frame::NONE
        .fill(bg)
        .stroke(Stroke::new(1.2_f32, border_color))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(emoji_icon).size(22.0));
                ui.add_space(6.0);
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).size(15.0).color(border_color).strong());
                    ui.label(RichText::new(subtitle).size(12.0));
                });
            });
        });
}

/// Contadores com badges de status compactos em formato pill.
fn render_summary_counters(ui: &mut Ui, val: &crate::validation::ValidationResult, mode: ThemeMode) {
    let colors = ThemeColors::for_mode(mode);

    ui.horizontal(|ui| {
        render_counter_card(ui, "Aprovados", val.count_passed(), colors.pass, "✅");
        ui.add_space(6.0);
        render_counter_card(ui, "Avisos", val.count_warnings(), colors.warning, "⚠");
        ui.add_space(6.0);
        render_counter_card(ui, "Falhas", val.count_errors(), colors.error, "❌");
        ui.add_space(6.0);
        render_counter_card(ui, "Info", val.count_info(), colors.info, "ℹ");
    });
}

fn render_counter_card(ui: &mut Ui, title: &str, count: usize, color: Color32, icon: &str) {
    Frame::NONE
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.4)))
        .corner_radius(CornerRadius::same(5))
        .inner_margin(Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(13.0));
                ui.label(RichText::new(count.to_string()).size(14.5).color(color).strong());
                ui.label(RichText::new(title).size(12.5).color(color));
            });
        });
}

/// Renderiza o cartão com os dados e atributos essenciais do certificado com margens compactas e colunas perfeitamente alinhadas.
fn render_metadata_card(ui: &mut Ui, cert: &crate::certificate::CertificateInfo, colors: &ThemeColors) {
    Frame::NONE
        .fill(colors.card_bg)
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("📋").size(16.0));
                ui.label(RichText::new("Metadados do Certificado").size(15.5).strong());
            });

            ui.add_space(3.0);
            ui.separator();
            ui.add_space(4.0);

            egui::Grid::new("metadata_grid")
                .num_columns(3)
                .spacing([8.0, 4.0])
                .show(ui, |ui| {
                    let is_pj = cert.identity.cnpj.is_some();
                    if is_pj {
                        let company = cert.identity.company_name.as_deref().unwrap_or_else(|| cert.subject.clean_name());
                        render_metadata_row(ui, "🏢", "Razão Social:", company, colors);
                        if let Some(cnpj) = cert.identity.formatted_cnpj() {
                            render_metadata_row(ui, "🏢", "CNPJ Empresa:", &cnpj, colors);
                        }
                        if let Some(resp) = &cert.identity.holder_name {
                            render_metadata_row(ui, "👤", "Responsável Legal:", resp, colors);
                        }
                        if let Some(cpf) = cert.identity.formatted_cpf() {
                            render_metadata_row(ui, "🆔", "CPF Responsável:", &cpf, colors);
                        }
                    } else {
                        render_metadata_row(ui, "👤", "Titular:", cert.subject.clean_name(), colors);
                        if let Some(cpf) = cert.identity.formatted_cpf() {
                            render_metadata_row(ui, "🆔", "CPF Titular:", &cpf, colors);
                        }
                    }

                    render_metadata_row(ui, "🏛", "Emissor:", cert.issuer.display_name(), colors);
                    render_metadata_row(ui, "🔢", "Número de Série:", &cert.serial_number_hex, colors);
                    render_metadata_row(ui, "🔖", "Tipo de Certificado:", &format!("{}", cert.cert_type), colors);
                    render_metadata_row(ui, "🔑", "Parâmetros da Chave:", &format!("{}", cert.public_key), colors);
                    render_metadata_row(ui, "📅", "Validade Temporal:", &cert.validity_summary(chrono::Utc::now()), colors);
                    render_metadata_row(ui, "📍", "Origem / Repositório:", &format!("{}", cert.source), colors);
                });
        });
}

fn render_metadata_row(ui: &mut Ui, icon: &str, label: &str, value: &str, colors: &ThemeColors) {
    ui.label(RichText::new(icon).size(14.0));
    ui.label(RichText::new(label).strong().size(13.5).color(colors.neutral));
    ui.label(RichText::new(value).size(13.5).strong());
    ui.end_row();
}

/// Renderiza a lista de verificações de conformidade com badges e emojis em Grid alinhado e margens reduzidas.
fn render_compliance_card(
    ui: &mut Ui,
    validation: Option<&crate::validation::ValidationResult>,
    mode: ThemeMode,
    colors: &ThemeColors,
) {
    Frame::NONE
        .fill(colors.card_bg)
        .stroke(Stroke::new(1.0_f32, colors.border))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::symmetric(12, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("🛡").size(16.0));
                ui.label(RichText::new("Verificações de Conformidade Técnica").size(15.5).strong());
            });

            ui.add_space(3.0);
            ui.separator();
            ui.add_space(4.0);

            let check_items = [
                ("📐", "Estrutura X.509 ASN.1", CheckCategory::X509Structure),
                ("⏰", "Período de Validade", CheckCategory::ValidityPeriod),
                ("🔑", "Chave Pública Compatível", CheckCategory::KeyCharacteristics),
                ("📝", "Key Usage (Assinatura)", CheckCategory::KeyUsage),
                ("🌐", "Extended Key Usage (EKU)", CheckCategory::ExtendedKeyUsage),
                ("🏢", "Restrições Básicas (CA)", CheckCategory::BasicConstraints),
                ("🔗", "Cadeia de Confiança ICP-Brasil", CheckCategory::TrustChain),
                ("📜", "Políticas ICP-Brasil (DOC-ICP-04)", CheckCategory::IcpBrasilPolicy),
                ("🚫", "Consulta de Revogação (CRL)", CheckCategory::RevocationCrl),
                ("⚡", "Consulta de Revogação (OCSP)", CheckCategory::RevocationOcsp),
                ("🔏", "Operação de Assinatura Digital", CheckCategory::CryptographicSignature),
                ("🔐", "Provedor de Chave / Token", CheckCategory::HardwareProvider),
            ];

            egui::Grid::new("compliance_grid")
                .num_columns(4)
                .spacing([8.0, 4.0])
                .show(ui, |ui| {
                    for (icon, label, category) in check_items {
                        let (status, msg) = if let Some(val) = validation {
                            if let Some(c) = val.checks.iter().find(|chk| chk.category == category) {
                                (c.status, c.message.as_str())
                            } else {
                                (CheckStatus::NotChecked, "Aguardando verificação")
                            }
                        } else {
                            (CheckStatus::NotChecked, "Aguardando verificação")
                        };

                        // Coluna 1: Badge uniforme
                        render_status_badge(ui, status, mode);

                        // Coluna 2: Ícone alinhado
                        ui.label(RichText::new(icon).size(14.0));

                        // Coluna 3: Rótulo da verificação técnica
                        ui.label(RichText::new(label).strong().size(13.5));

                        // Coluna 4: Mensagem de diagnóstico detalhada
                        ui.label(RichText::new(msg).color(colors.neutral).size(12.5));

                        ui.end_row();
                    }
                });
        });
}
