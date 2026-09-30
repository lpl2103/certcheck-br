use crate::app::{AppCommand, AppState, ThemeMode};
use crate::gui::theme::configure_visuals;
use crossbeam_channel::Sender;
use egui::{RichText, Ui, Window};

pub fn render_settings_dialog(
    ctx: &egui::Context,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    if !state.settings_open {
        return;
    }

    let mut is_open = true;
    let mut close_requested = false;

    Window::new(RichText::new("⚙ Configurações do Sistema").strong())
        .open(&mut is_open)
        .resizable(false)
        .collapsible(false)
        .default_width(420.0)
        .show(ctx, |ui| {
            if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
                close_requested = true;
            }
            render_settings_content(ui, state, ctx, command_sender, &mut close_requested);
        });

    state.settings_open = is_open && !close_requested;
}

fn render_settings_content(
    ui: &mut Ui,
    state: &mut AppState,
    ctx: &egui::Context,
    command_sender: &Sender<AppCommand>,
    close_requested: &mut bool,
) {
    ui.group(|ui| {
        ui.heading("Tema e Aparência");
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            let is_dark = state.theme_mode == ThemeMode::Dark;
            if ui.selectable_label(is_dark, "🌙 Modo Escuro").clicked() {
                state.theme_mode = ThemeMode::Dark;
                configure_visuals(ctx, ThemeMode::Dark);
            }
            if ui.selectable_label(!is_dark, "☀ Modo Claro").clicked() {
                state.theme_mode = ThemeMode::Light;
                configure_visuals(ctx, ThemeMode::Light);
            }
        });
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.heading("Comportamento de Validação");
        ui.add_space(4.0);

        ui.checkbox(
            &mut state.config.auto_validate_chain,
            "Validar cadeia de certificação automaticamente",
        );
        ui.checkbox(
            &mut state.config.auto_check_ocsp,
            "Verificar revogação via OCSP automaticamente",
        );
        ui.checkbox(
            &mut state.config.auto_check_crl,
            "Verificar revogação via CRL automaticamente",
        );
        ui.checkbox(
            &mut state.config.advanced_technical_mode,
            "Modo Técnico Avançado (exibir OIDs, ASN.1 e detalhes internos)",
        );
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.heading("Rede e Conexão");
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("Timeout de Rede (segundos):");
            ui.add(egui::DragValue::new(&mut state.config.network_timeout_seconds).range(3..=60));
        });

        ui.label("Proxy:");
        ui.label(RichText::new("Utilizar configurações padrão do Windows (WinINet)").italics());
    });

    ui.add_space(10.0);

    ui.group(|ui| {
        ui.heading("🔄 Atualizações do Aplicativo");
        ui.add_space(4.0);

        ui.horizontal(|ui| {
            ui.label("Versão Instalada:");
            ui.label(
                RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                    .monospace()
                    .strong(),
            );
        });

        if let Some(ref info) = state.available_update {
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
                ui.add_space(2.0);
                ui.label(
                    RichText::new(&info.release_notes)
                        .small()
                        .italics()
                        .weak(),
                );
            }
        }

        ui.add_space(6.0);

        match state.update_status {
            crate::updater::UpdateStatus::Idle => {
                if let Some(ref info) = state.available_update {
                    let dl_url = info.download_url.clone();
                    let btn_update = egui::Button::new(
                        RichText::new(format!("⬇ Baixar e Atualizar para v{}", info.version))
                            .strong()
                            .color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(0, 140, 60));

                    if ui.add(btn_update).clicked() {
                        let _ = command_sender.send(AppCommand::TriggerAutoUpdate {
                            download_url: Some(dl_url),
                        });
                    }
                } else {
                    if ui.button("🔍 Verificar Atualizações no GitHub").clicked() {
                        let _ = command_sender.send(AppCommand::CheckForUpdates);
                    }
                }
            }
            crate::updater::UpdateStatus::Downloading(progress) => {
                ui.label(format!(
                    "Baixando nova versão... ({:.0}%)",
                    progress * 100.0
                ));
                ui.add(egui::ProgressBar::new(progress).animate(true));
            }
            crate::updater::UpdateStatus::Success(ref msg) => {
                ui.label(
                    RichText::new(msg)
                        .color(egui::Color32::from_rgb(0, 200, 80))
                        .strong(),
                );
            }
            crate::updater::UpdateStatus::Error(ref err) => {
                ui.label(
                    RichText::new(format!("Erro ao atualizar: {}", err))
                        .color(egui::Color32::RED)
                        .small(),
                );
                ui.add_space(4.0);
                if ui.button("Tentar Novamente").clicked() {
                    let dl_url = state
                        .available_update
                        .as_ref()
                        .map(|u| u.download_url.clone());
                    let _ = command_sender.send(AppCommand::TriggerAutoUpdate {
                        download_url: dl_url,
                    });
                }
            }
        }
    });

    ui.add_space(12.0);

    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if ui.button(RichText::new("✖ Fechar").strong()).clicked() {
            *close_requested = true;
        }
    });
}
