//! Painel de teste operacional de assinatura e verificação criptográfica.

use crate::app::{AppCommand, AppState};
use crate::gui::theme::ThemeColors;
use crossbeam_channel::Sender;
use egui::{RichText, Ui};

pub fn render_signature_panel(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    let Some(cert) = state.selected_certificate().cloned() else {
        ui.label(RichText::new("Nenhum certificado selecionado.").color(colors.neutral));
        return;
    };

    ui.heading("Teste de Assinatura Digital");
    ui.add_space(8.0);

    ui.group(|ui| {
        ui.heading("Parâmetros do Teste");
        ui.add_space(6.0);

        egui::Grid::new("sign_params_grid")
            .num_columns(2)
            .spacing([16.0, 8.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Disponibilidade da Chave:").strong());
                if cert.has_private_key {
                    let text = if cert.is_hardware_backed {
                        "Disponível em dispositivo A3 (Smart Card/Token)"
                    } else {
                        "Disponível em software (Arquivo A1 / Windows Store)"
                    };
                    ui.label(RichText::new(text).color(colors.pass));
                } else {
                    ui.label(RichText::new("Chave privada não disponível para este certificado").color(colors.error));
                }
                ui.end_row();

                ui.label(RichText::new("Algoritmo da Chave:").strong());
                ui.label(format!("{}", cert.public_key));
                ui.end_row();

                ui.label(RichText::new("Algoritmo de Hash:").strong());
                ui.label("SHA-256 (Padrão ICP-Brasil)");
                ui.end_row();

                ui.label(RichText::new("Tamanho da Carga de Teste:").strong());
                ui.label("1024 bytes (CSPRNG seguro gerado dinamicamente)");
                ui.end_row();
            });

        ui.add_space(12.0);

        ui.horizontal(|ui| {
            let can_sign = cert.has_private_key && !state.is_busy;

            if ui.add_enabled(can_sign, egui::Button::new(RichText::new("✍ Executar Teste de Assinatura").strong())).clicked() {
                let _ = command_sender.send(AppCommand::TestSignature {
                    cert_id: cert.id.clone(),
                    hash_alg: "SHA-256".to_string(),
                });
            }

            if !cert.has_private_key {
                ui.label(RichText::new("⚠ Operação indisponível sem chave privada.").color(colors.warning));
            }
        });
    });

    ui.add_space(16.0);

    // Fluxo da Operação
    ui.group(|ui| {
        ui.heading("Fluxo Criptográfico Seguro");
        ui.add_space(6.0);

        ui.label("1. Geração de desafio aleatório usando CSPRNG do sistema operacional;");
        ui.label("2. Cálculo do resumo criptográfico (Hash SHA-256);");
        ui.label("3. Envio do hash ao Provider do Windows / Token criptográfico (a chave privada não sai do dispositivo);");
        ui.label("4. O middleware do fabricante solicita o PIN caso seja certificado A3;");
        ui.label("5. Retorno da assinatura digital calculada;");
        ui.label("6. Verificação matemática independente usando a chave pública do certificado.");
    });
}
