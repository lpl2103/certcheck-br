//! Aba de Ferramentas, Reparo Rápido, Diagnóstico de Ambiente e Conectividade.

use crate::app::{AppCommand, AppState};
use crate::gui::theme::ThemeColors;
use crossbeam_channel::Sender;
use egui::{Color32, CornerRadius, Frame, Margin, RichText, Stroke, Ui};

pub fn render_tools_tab(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    ui.horizontal(|ui| {
        ui.heading("🛠 Central de Ferramentas, Reparo e Conectividade");
    });
    ui.label(
        RichText::new("Ações em 1-clique para resolver falhas frequentes de SSL/TLS, instalar certificados raiz oficiais e testar a infraestrutura.")
            .color(colors.neutral)
            .size(13.0),
    );

    ui.add_space(8.0);

    // Mensagem de feedback de operação recente
    let mut dismiss_feedback = false;
    if let Some((success, ref msg)) = state.tool_feedback_message.clone() {
        let (bg, border_color, icon) = if success {
            (colors.pass.gamma_multiply(0.15), colors.pass, "✔")
        } else {
            (colors.error.gamma_multiply(0.15), colors.error, "✖")
        };

        Frame::NONE
            .fill(bg)
            .corner_radius(CornerRadius::same(6))
            .stroke(Stroke::new(1.0_f32, border_color))
            .inner_margin(Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(icon).color(border_color).strong().size(15.0));
                    ui.label(RichText::new(msg).size(13.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button("✕ Fechar").clicked() {
                            dismiss_feedback = true;
                        }
                    });
                });
            });
        ui.add_space(8.0);
    }
    if dismiss_feedback {
        state.tool_feedback_message = None;
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // ==========================================
            // SEÇÃO 1: Reparo Rápido (1-Clique)
            // ==========================================
            render_card(ui, &colors, "⚡ Reparo Rápido em 1-Clique", |ui| {
                ui.horizontal(|ui| {
                    let ssl_btn = egui::Button::new(
                        RichText::new("🧹 Limpar Estado SSL do Windows")
                            .strong()
                            .size(13.5),
                    )
                    .min_size(egui::vec2(240.0, 32.0));

                    if ui.add(ssl_btn).clicked() {
                        let _ = command_sender.send(AppCommand::ClearSslCache);
                    }

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Executa SslEmptyCacheW no subsistema nativo Schannel.")
                                .strong()
                                .size(12.5),
                        );
                        ui.label(
                            RichText::new("Resolve erro de sessão presa no navegador e bloqueios ao alternar certificados no e-CAC.")
                                .color(colors.neutral)
                                .size(12.0),
                        );
                    });
                });

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    let roots_btn = egui::Button::new(
                        RichText::new("📥 Instalar Cadeias AC Raiz ICP-Brasil")
                            .strong()
                            .size(13.5),
                    )
                    .min_size(egui::vec2(240.0, 32.0));

                    if ui.add(roots_btn).clicked() {
                        let _ = command_sender.send(AppCommand::InstallIcpBrasilRoots);
                    }

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Baixa e instala as Autoridades Raiz oficiais do ITI (v2, v5, v10, v11).")
                                .strong()
                                .size(12.5),
                        );
                        ui.label(
                            RichText::new("Corrige o erro 'Cadeia de certificação não confiável' em novos computadores ou formatações.")
                                .color(colors.neutral)
                                .size(12.0),
                        );
                    });
                });
            });

            ui.add_space(12.0);

            // ==========================================
            // SEÇÃO 2: Laudo Técnico HTML
            // ==========================================
            render_card(ui, &colors, "📑 Laudo Técnico de Diagnóstico e Homologação", |ui| {
                ui.horizontal(|ui| {
                    let report_btn = egui::Button::new(
                        RichText::new("📄 Gerar Laudo Técnico Formal (HTML)")
                            .color(Color32::WHITE)
                            .strong()
                            .size(13.5),
                    )
                    .fill(colors.accent)
                    .min_size(egui::vec2(240.0, 34.0));

                    let has_selected = state.selected_cert_id.is_some();

                    if ui.add_enabled(has_selected, report_btn).clicked() {
                        if let Some(cert) = state.selected_certificate().cloned() {
                            let default_filename = format!(
                                "Laudo_Tecnico_{}.html",
                                cert.subject.clean_name().replace([' ', '/', '\\', ':', '.'], "_")
                            );
                            let sender = command_sender.clone();
                            std::thread::spawn(move || {
                                if let Some(dest) = crate::gui::file_dialog::save_html_report(&default_filename) {
                                    let _ = sender.send(AppCommand::ExportReportHtml {
                                        cert_id: cert.id.clone(),
                                        destination: dest.clone(),
                                    });
                                    // Abre no navegador padrão
                                    let _ = std::process::Command::new("explorer").arg(&dest).spawn();
                                }
                            });
                        }
                    }

                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new("Emite documento técnico pronto para impressão com layout limpo e timbre.")
                                .strong()
                                .size(12.5),
                        );
                        ui.label(
                            RichText::new("Contém checklist normativo X.509/DOC-ICP-04, status de revogação, hardware A3 e campo para assinatura do técnico de TI.")
                                .color(colors.neutral)
                                .size(12.0),
                        );
                        if !has_selected {
                            ui.label(
                                RichText::new("⚠ Selecione um certificado na barra lateral para habilitar a emissão do laudo.")
                                    .color(colors.warning)
                                    .size(12.0),
                            );
                        }
                    });
                });
            });

            ui.add_space(12.0);

            // ==========================================
            // SEÇÃO 3: Diagnóstico de Drivers e Assinadores
            // ==========================================
            render_card(ui, &colors, "🔍 Diagnóstico do Ambiente e Softwares A3", |ui| {
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("🩺 Varrer Drivers, Softwares e Assinadores").strong().size(13.0)).clicked() {
                        let _ = command_sender.send(AppCommand::RunEnvironmentDiagnostic);
                    }
                    ui.label(
                        RichText::new("Verifica serviço Smart Card do Windows, middlewares (SafeSign, SAC, etc.) e portas dos assinadores judiciais.")
                            .color(colors.neutral)
                            .size(12.0),
                    );
                });

                if let Some(ref diag) = state.env_diagnostic {
                    ui.add_space(10.0);

                    // Status do Serviço SCardSvr
                    let svc = &diag.smart_card_service;
                    let (svc_color, svc_icon) = if svc.is_healthy {
                        (colors.pass, "✔")
                    } else {
                        (colors.error, "✖")
                    };

                    Frame::NONE
                        .fill(colors.card_bg)
                        .corner_radius(CornerRadius::same(6))
                        .inner_margin(Margin::same(8))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{svc_icon} Serviço do Windows:")) .strong().color(svc_color));
                                ui.label(RichText::new(&svc.display_name).strong());
                                ui.label(RichText::new(format!("({})", svc.status)).color(svc_color));
                                ui.label(RichText::new(&svc.details).color(colors.neutral).size(12.0));
                            });
                        });

                    ui.add_space(8.0);

                    // Assinadores Judiciais (PJeOffice e Shodō)
                    ui.label(RichText::new("Assinadores Locais de Tribunais:").strong().size(13.0));
                    ui.horizontal(|ui| {
                        for signer in &diag.signers {
                            let (badge_bg, text_color, icon) = if signer.is_running {
                                (colors.pass.gamma_multiply(0.2), colors.pass, "🟢")
                            } else {
                                (colors.neutral.gamma_multiply(0.15), colors.neutral, "⚪")
                            };

                            Frame::NONE
                                .fill(badge_bg)
                                .corner_radius(CornerRadius::same(6))
                                .stroke(Stroke::new(1.0_f32, text_color))
                                .inner_margin(Margin::symmetric(10, 6))
                                .show(ui, |ui| {
                                    ui.vertical(|ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(icon).size(11.0));
                                            ui.label(RichText::new(&signer.name).strong().color(text_color));
                                            ui.label(RichText::new(format!("(Porta {})", signer.expected_port)).size(11.0).color(colors.neutral));
                                        });
                                        ui.label(RichText::new(&signer.details).size(11.5).color(colors.neutral));
                                    });
                                });
                        }
                    });

                    ui.add_space(8.0);

                    // Middlewares Detectados
                    ui.label(RichText::new("Drivers e Middlewares de Cartão / Token Instalados:").strong().size(13.0));
                    let installed: Vec<_> = diag.middlewares.iter().filter(|m| m.installed).collect();
                    if installed.is_empty() {
                        ui.label(
                            RichText::new("Nenhum middleware padrão (SafeSign, SAC, ePass2003, etc.) detectado nos diretórios de sistema.")
                                .color(colors.warning)
                                .italics()
                                .size(12.0),
                        );
                    } else {
                        for m in installed {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("✔").color(colors.pass).strong());
                                ui.label(RichText::new(&m.name).strong());
                                ui.label(RichText::new(format!("({})", m.vendor)).color(colors.neutral).size(12.0));
                                if let Some(ref path) = m.path_found {
                                    ui.label(RichText::new(path).monospace().size(11.0).color(colors.neutral));
                                }
                            });
                        }
                    }
                }
            });

            ui.add_space(12.0);

            // ==========================================
            // SEÇÃO 4: Teste de Conectividade com Portais Governamentais
            // ==========================================
            render_card(ui, &colors, "🌐 Teste de Conectividade e Latência com Portais Governamentais", |ui| {
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("⚡ Testar Portais Agora").strong().size(13.0)).clicked() {
                        let _ = command_sender.send(AppCommand::RunConnectivityTest);
                    }
                    ui.label(
                        RichText::new("Testa resolução DNS, handshake TLS e latência contra e-CAC, PJe, Caixa e SEFAZ.")
                            .color(colors.neutral)
                            .size(12.0),
                    );
                });

                if !state.connectivity_results.is_empty() {
                    ui.add_space(10.0);

                    egui::Grid::new("connectivity_grid")
                        .striped(true)
                        .min_col_width(80.0)
                        .spacing([14.0, 6.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Portal / Órgão").strong());
                            ui.label(RichText::new("Endereço").strong());
                            ui.label(RichText::new("Status").strong());
                            ui.label(RichText::new("Latência").strong());
                            ui.label(RichText::new("Diagnóstico").strong());
                            ui.end_row();

                            for test in &state.connectivity_results {
                                ui.label(RichText::new(&test.name).strong());
                                ui.label(RichText::new(format!("{}:{}", test.host, test.port)).monospace().size(11.5));

                                if test.reachable {
                                    ui.label(RichText::new("✔ Online").color(colors.pass).strong());
                                } else {
                                    ui.label(RichText::new("✖ Falha").color(colors.error).strong());
                                }

                                if let Some(ms) = test.latency_ms {
                                    let lat_color = if ms < 150 {
                                        colors.pass
                                    } else if ms < 500 {
                                        colors.warning
                                    } else {
                                        colors.error
                                    };
                                    ui.label(RichText::new(format!("{ms} ms")).color(lat_color).strong());
                                } else {
                                    ui.label(RichText::new("—").color(colors.neutral));
                                }

                                ui.label(RichText::new(&test.status_message).size(12.0).color(colors.neutral));
                                ui.end_row();
                            }
                        });
                }
            });

            ui.add_space(12.0);

            // ==========================================
            // SEÇÃO 5: Assinatura de Arquivo Externo
            // ==========================================
            render_card(ui, &colors, "✍ Testar Assinatura Digital de Arquivo Externo", |ui| {
                ui.label(
                    RichText::new("Selecione qualquer arquivo do seu computador (PDF, documento, XML, planilha) para testar a assinatura criptográfica completa com a chave privada.")
                        .color(colors.neutral)
                        .size(12.5),
                );
                ui.add_space(6.0);

                let has_selected = state.selected_cert_id.is_some();

                ui.horizontal(|ui| {
                    let sign_btn = egui::Button::new(RichText::new("📂 Selecionar Arquivo para Assinar...").strong().size(13.0));
                    if ui.add_enabled(has_selected, sign_btn).clicked() {
                        if let Some(cert) = state.selected_certificate().cloned() {
                            let sender = command_sender.clone();
                            std::thread::spawn(move || {
                                if let Some(path) = crate::gui::file_dialog::pick_file_to_sign() {
                                    let _ = sender.send(AppCommand::SignTestFile {
                                        cert_id: cert.id.clone(),
                                        file_path: path,
                                    });
                                }
                            });
                        }
                    }

                    if !has_selected {
                        ui.label(
                            RichText::new("⚠ Selecione um certificado na barra lateral para assinar.")
                                .color(colors.warning)
                                .size(12.0),
                        );
                    }
                });

                if let Some(ref res) = state.file_signing_result {
                    ui.add_space(8.0);
                    let (status_color, status_text) = if res.success {
                        (colors.pass, "✔ Assinatura gerada e validada com sucesso!")
                    } else {
                        (colors.error, "✖ Falha ao assinar o arquivo.")
                    };

                    Frame::NONE
                        .fill(status_color.gamma_multiply(0.12))
                        .corner_radius(CornerRadius::same(6))
                        .stroke(Stroke::new(1.0_f32, status_color))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(RichText::new(status_text).color(status_color).strong().size(13.5));
                            ui.label(RichText::new(format!("Algoritmo: {} | Tempo de processamento: {} ms | Tamanho do arquivo: {} bytes", res.algorithm, res.execution_time_ms, res.input_size_bytes)).size(12.0));

                            if let Some(ref sig_hex) = res.signature_hex {
                                ui.add_space(4.0);
                                ui.label(RichText::new("Bytes da Assinatura Gerada:").strong().size(12.0));
                                ui.label(RichText::new(sig_hex).monospace().size(11.0).color(colors.neutral));
                            }

                            if let Some(ref err) = res.error_message {
                                ui.add_space(4.0);
                                ui.label(RichText::new(format!("Detalhes do erro: {err}")).color(colors.error).size(12.0));
                            }
                        });
                }
            });

            ui.add_space(20.0);
        });
}

fn render_card<R>(
    ui: &mut Ui,
    colors: &ThemeColors,
    title: &str,
    add_contents: impl FnOnce(&mut Ui) -> R,
) -> R {
    Frame::NONE
        .fill(colors.card_bg)
        .corner_radius(CornerRadius::same(8))
        .stroke(Stroke::new(1.0_f32, colors.border))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.label(RichText::new(title).strong().size(15.0));
            ui.add_space(6.0);
            add_contents(ui)
        })
        .inner
}
