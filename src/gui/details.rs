//! Visualizador detalhado com abas técnicas completas para o certificado selecionado.

use crate::app::{AppCommand, AppState, DetailTab};
use crate::gui::a3::render_a3_panel;
use crate::gui::dashboard::render_dashboard;
use crate::gui::diagnostics::render_diagnostics_panel;
use crate::gui::revocation::render_revocation_panel;
use crate::gui::signature::render_signature_panel;
use crate::gui::theme::ThemeColors;
use crate::gui::validation::render_validation_panel;
use crate::logging::LogLevel;
use crossbeam_channel::Sender;
use egui::{RichText, Ui};

pub fn render_certificate_details(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    // Cabeçalho Rápido do Certificado Ativo
    if let Some(cert) = state.selected_certificate().cloned() {
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add_space(4.0);
                if ui.button(RichText::new("⚡ Revalidar").color(colors.pass).strong()).clicked() {
                    let _ = command_sender.send(AppCommand::ValidateCertificate { cert_id: cert.id.clone() });
                }
                if ui.button(RichText::new("🚫 Revogação").strong()).clicked() {
                    let _ = command_sender.send(AppCommand::CheckRevocation { cert_id: cert.id.clone() });
                }
                if ui.button(RichText::new("✍ Assinar").strong()).clicked() {
                    let _ = command_sender.send(AppCommand::TestSignature {
                        cert_id: cert.id.clone(),
                        hash_alg: "SHA-256".to_string(),
                    });
                }

                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.label(RichText::new("📜").size(22.0));
                    ui.vertical(|ui| {
                        ui.add(egui::Label::new(RichText::new(cert.subject.clean_name()).size(16.0).strong()).truncate());
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("{} • Emissor: {}", cert.cert_type, cert.issuer.display_name()))
                                    .size(12.0)
                                    .color(colors.neutral),
                            )
                            .truncate(),
                        );
                    });
                });
            });
        });
        ui.add_space(6.0);
        ui.separator();
        ui.add_space(4.0);
    }

    // Barra de Navegação por Abas com Emojis Concisos
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 3.0;
        let tabs = [
            (DetailTab::Resumo, "📊 Resumo"),
            (DetailTab::Identidade, "👤 Identidade"),
            (DetailTab::Chave, "🔑 Chave"),
            (DetailTab::Extensoes, "🧩 Extensões"),
            (DetailTab::Cadeia, "🔗 Cadeia"),
            (DetailTab::Validacao, "✔ Conformidade"),
            (DetailTab::Revogacao, "🚫 Revogação"),
            (DetailTab::Assinatura, "✍ Assinatura"),
            (DetailTab::A3, "🔐 A3 Token"),
            (DetailTab::Diagnostico, "🩺 Diagnóstico"),
            (DetailTab::Logs, "📜 Logs"),
        ];

        for (tab, label) in tabs {
            let is_selected = state.active_tab == tab;
            if ui.selectable_label(is_selected, RichText::new(label).size(13.0)).clicked() {
                state.active_tab = tab;
            }
        }
    });

    ui.separator();
    ui.add_space(6.0);

    // Conteúdo da Aba Selecionada
    match state.active_tab {
        DetailTab::Resumo => render_dashboard(ui, state),
        DetailTab::Identidade => render_identity_tab(ui, state),
        DetailTab::Chave => render_key_tab(ui, state),
        DetailTab::Extensoes => render_extensions_tab(ui, state),
        DetailTab::Cadeia => render_chain_tab(ui, state),
        DetailTab::Validacao => render_validation_panel(ui, state, command_sender),
        DetailTab::Revogacao => render_revocation_panel(ui, state, command_sender),
        DetailTab::Assinatura => render_signature_panel(ui, state, command_sender),
        DetailTab::A3 => render_a3_panel(ui, state, command_sender),
        DetailTab::Diagnostico => render_diagnostics_panel(ui, state),
        DetailTab::Logs => render_logs_tab(ui, state),
    }
}

fn render_identity_tab(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);
    let Some(cert) = state.selected_certificate() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    ui.heading("Identificação do Titular e Emissor");
    ui.add_space(8.0);

    // Identidade ICP-Brasil decodificada
    ui.group(|ui| {
        ui.heading("Dados Normativos ICP-Brasil (Pessoa Física / Jurídica)");
        ui.add_space(6.0);

        egui::Grid::new("icp_identity_grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Tipo de Titular:").strong());
                let person_desc = cert.identity.person_type
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| "Não identificado nas extensões".to_string());
                ui.label(person_desc);
                ui.end_row();

                if let Some(cpf) = cert.identity.formatted_cpf() {
                    ui.label(RichText::new("CPF do Titular:").strong());
                    ui.label(RichText::new(cpf).monospace().strong());
                    ui.end_row();
                }

                if let Some(cnpj) = cert.identity.formatted_cnpj() {
                    ui.label(RichText::new("CNPJ da Empresa:").strong());
                    ui.label(RichText::new(cnpj).monospace().strong());
                    ui.end_row();
                }

                if let Some(name) = &cert.identity.holder_name {
                    ui.label(RichText::new("Nome do Titular:").strong());
                    ui.label(name);
                    ui.end_row();
                }

                if let Some(company) = &cert.identity.company_name {
                    ui.label(RichText::new("Razão Social:").strong());
                    ui.label(company);
                    ui.end_row();
                }

                if let Some(email) = &cert.identity.email {
                    ui.label(RichText::new("E-mail Cadastrado:").strong());
                    ui.label(email);
                    ui.end_row();
                }

                ui.label(RichText::new("Rastreabilidade da Fonte:").strong());
                let source_desc = if cert.identity.data_source_description.is_empty() {
                    "Campos extraídos de Subject e SAN (Subject Alternative Name)".to_string()
                } else {
                    cert.identity.data_source_description.clone()
                };
                ui.label(RichText::new(source_desc).color(colors.info));
                ui.end_row();
            });
    });

    ui.add_space(12.0);

    // Subject Distinguished Name (DN)
    ui.group(|ui| {
        ui.heading("Subject (Nome Distinto do Titular)");
        ui.add_space(6.0);

        egui::Grid::new("subject_dn_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Common Name (CN):").strong());
                ui.label(cert.subject.common_name.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("Organization (O):").strong());
                ui.label(cert.subject.organization.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("Organizational Unit (OU):").strong());
                ui.label(cert.subject.organizational_unit.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("Country (C):").strong());
                ui.label(cert.subject.country.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("State / Province (ST):").strong());
                ui.label(cert.subject.state_or_province.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("Locality (L):").strong());
                ui.label(cert.subject.locality.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("DN Completo:").strong());
                ui.label(RichText::new(&cert.subject.raw).monospace().size(11.0));
                ui.end_row();
            });
    });

    ui.add_space(12.0);

    // Issuer Distinguished Name (DN)
    ui.group(|ui| {
        ui.heading("Issuer (Autoridade Certificadora Emissora)");
        ui.add_space(6.0);

        egui::Grid::new("issuer_dn_grid")
            .num_columns(2)
            .spacing([16.0, 6.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Common Name (CN):").strong());
                ui.label(cert.issuer.common_name.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("Organization (O):").strong());
                ui.label(cert.issuer.organization.as_deref().unwrap_or("-"));
                ui.end_row();

                ui.label(RichText::new("DN Completo:").strong());
                ui.label(RichText::new(&cert.issuer.raw).monospace().size(11.0));
                ui.end_row();
            });
    });
}

fn render_key_tab(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);
    let Some(cert) = state.selected_certificate() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    ui.heading("Propriedades da Chave Pública e Algoritmos");
    ui.add_space(8.0);

    ui.group(|ui| {
        ui.heading("Chave Pública");
        ui.add_space(6.0);

        egui::Grid::new("public_key_grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Algoritmo:").strong());
                ui.label(format!("{}", cert.public_key));
                ui.end_row();

                ui.label(RichText::new("Algoritmo de Assinatura:").strong());
                ui.label(&cert.signature_algorithm);
                ui.end_row();

                ui.label(RichText::new("Armazenamento da Chave Privada:").strong());
                let storage_desc = if cert.is_hardware_backed {
                    "Dispositivo Criptográfico de Hardware (Token / Smart Card A3)"
                } else if cert.has_private_key {
                    "Software / Windows Certificate Store (A1)"
                } else {
                    "Chave privada ausente neste arquivo / armazém"
                };
                ui.label(storage_desc);
                ui.end_row();
            });
    });

    ui.add_space(12.0);

    ui.group(|ui| {
        ui.heading("Impressões Digitais (Fingerprints)");
        ui.add_space(6.0);

        egui::Grid::new("fingerprints_grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label(RichText::new("SHA-256:").strong());
                ui.label(RichText::new(&cert.fingerprints.sha256).monospace().color(colors.info));
                ui.end_row();

                ui.label(RichText::new("SHA-1 (Legado):").strong());
                ui.label(RichText::new(&cert.fingerprints.sha1).monospace().color(colors.neutral));
                ui.end_row();
            });
    });
}

fn render_extensions_tab(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);
    let Some(cert) = state.selected_certificate() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    ui.heading("Extensões Padrão X.509 (RFC 5280)");
    ui.add_space(8.0);

    // Key Usage
    ui.group(|ui| {
        ui.heading("Uso da Chave (Key Usage)");
        ui.add_space(6.0);

        if let Some(ku) = &cert.extensions.key_usage {
            let usages = [
                ("Digital Signature", ku.digital_signature),
                ("Non Repudiation / Content Commitment", ku.non_repudiation),
                ("Key Encipherment", ku.key_encipherment),
                ("Data Encipherment", ku.data_encipherment),
                ("Key Agreement", ku.key_agreement),
                ("Certificate Signing (Key Cert Sign)", ku.key_cert_sign),
                ("CRL Signing (crlSign)", ku.crl_sign),
                ("Encipher Only", ku.encipher_only),
                ("Decipher Only", ku.decipher_only),
            ];

            egui::Grid::new("key_usage_grid")
                .num_columns(2)
                .spacing([16.0, 4.0])
                .show(ui, |ui| {
                    for (name, enabled) in usages {
                        if enabled {
                            ui.label(RichText::new("✔").color(colors.pass).strong());
                            ui.label(RichText::new(name).strong());
                        } else {
                            ui.label(RichText::new("✖").color(colors.neutral));
                            ui.label(RichText::new(name).color(colors.neutral));
                        }
                        ui.end_row();
                    }
                });
        } else {
            ui.label(RichText::new("Extensão Key Usage ausente.").color(colors.neutral));
        }
    });

    ui.add_space(12.0);

    // EKU
    ui.group(|ui| {
        ui.heading("Uso Estendido da Chave (Extended Key Usage - EKU)");
        ui.add_space(6.0);

        if cert.extensions.extended_key_usages.is_empty() {
            ui.label(RichText::new("Extensão Extended Key Usage ausente.").color(colors.neutral));
        } else {
            for eku in &cert.extensions.extended_key_usages {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("✔").color(colors.pass).strong());
                    ui.label(RichText::new(&eku.name).strong());
                    ui.label(RichText::new(format!("({})", eku.oid)).color(colors.neutral).size(11.0));
                });
            }
        }
    });

    ui.add_space(12.0);

    // Basic Constraints
    ui.group(|ui| {
        ui.heading("Restrições Básicas (Basic Constraints)");
        ui.add_space(6.0);

        if let Some(bc) = &cert.extensions.basic_constraints {
            ui.horizontal(|ui| {
                ui.label(RichText::new("É Autoridade Certificadora (CA):").strong());
                if bc.is_ca {
                    ui.label(RichText::new("SIM (CA=TRUE)").color(colors.warning).strong());
                } else {
                    ui.label(RichText::new("NÃO (Certificado Final - CA=FALSE)").color(colors.pass).strong());
                }
            });
            if let Some(len) = bc.path_len_constraint {
                ui.label(format!("Restrição de Tamanho de Caminho (pathLenConstraint): {}", len));
            }
        } else {
            ui.label(RichText::new("Extensão Basic Constraints ausente.").color(colors.neutral));
        }
    });
}

fn render_chain_tab(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);
    let Some(cert) = state.selected_certificate() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    ui.heading("Construção e Validação da Cadeia de Confiança");
    ui.add_space(8.0);

    ui.group(|ui| {
        ui.heading("Hierarquia de Certificação");
        ui.add_space(8.0);

        ui.label(RichText::new("🏛 AC Raiz (Autoridade Certificadora Raiz)").strong());
        ui.indent("root_indent", |ui| {
            ui.label("↓ Assina e emite");
            ui.label(RichText::new(format!("🏢 AC Intermediária: {}", cert.issuer.display_name())).strong());
            ui.indent("leaf_indent", |ui| {
                ui.label("↓ Assina e emite");
                ui.label(RichText::new(format!("📄 Certificado Final: {}", cert.subject.display_name())).color(colors.pass).strong());
            });
        });
    });

    ui.add_space(12.0);

    ui.group(|ui| {
        ui.heading("Verificações Criptográficas da Cadeia");
        ui.add_space(6.0);

        ui.label("• Correspondência Issuer / Subject entre níveis;");
        ui.label("• Validação das assinaturas digitais intermediárias;");
        ui.label("• Verificação de datas de validade de todos os nós da cadeia;");
        ui.label("• Verificação de restrições de caminho (pathLenConstraint) e Basic Constraints;");
        ui.label("• Confiança na Autoridade Certificadora Raiz.");
    });
}

fn render_logs_tab(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    ui.horizontal(|ui| {
        ui.heading("Logs Técnicos da Sessão");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button("🗑 Limpar Logs").clicked() {
                state.log_buffer.clear();
            }

            if ui.button("📋 Copiar Logs").clicked() {
                ui.ctx().copy_text(state.log_buffer.export_text());
            }

            ui.separator();

            egui::ComboBox::from_label("Nível")
                .selected_text(format!("{}", state.log_min_level))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut state.log_min_level, LogLevel::Trace, "TRACE");
                    ui.selectable_value(&mut state.log_min_level, LogLevel::Debug, "DEBUG");
                    ui.selectable_value(&mut state.log_min_level, LogLevel::Info, "INFO");
                    ui.selectable_value(&mut state.log_min_level, LogLevel::Warn, "WARN");
                    ui.selectable_value(&mut state.log_min_level, LogLevel::Error, "ERROR");
                });

            ui.add(egui::TextEdit::singleline(&mut state.log_search).hint_text("Buscar nos logs..."));
        });
    });

    ui.add_space(8.0);

    let entries = state.log_buffer.get_filtered(state.log_min_level, &state.log_search);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if entries.is_empty() {
                ui.label(RichText::new("Nenhum registro de log para o filtro atual.").color(colors.neutral).italics());
                return;
            }

            for entry in entries.iter().rev() {
                let color = match entry.level {
                    LogLevel::Error => colors.error,
                    LogLevel::Warn => colors.warning,
                    LogLevel::Info => colors.info,
                    LogLevel::Debug | LogLevel::Trace => colors.neutral,
                };

                ui.horizontal(|ui| {
                    ui.label(RichText::new(entry.timestamp.format("%H:%M:%S%.3f").to_string()).color(colors.neutral).size(11.0));
                    ui.label(RichText::new(format!("[{:<5}]", entry.level)).color(color).strong().size(11.0));
                    ui.label(RichText::new(format!("[{}]", entry.target)).color(colors.neutral).size(11.0));
                    ui.label(RichText::new(&entry.message).monospace().size(11.0));
                });
            }
        });
}
