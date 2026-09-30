//! Painel especializado em diagnóstico de dispositivos A3 (Tokens, Smart Cards e Leitores).

use crate::app::{AppCommand, AppState};
use crate::gui::theme::ThemeColors;
use crossbeam_channel::Sender;
use egui::{RichText, Ui};

pub fn render_a3_panel(
    ui: &mut Ui,
    state: &mut AppState,
    command_sender: &Sender<AppCommand>,
) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    ui.horizontal(|ui| {
        ui.heading("Diagnóstico de Certificados e Dispositivos A3");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.button(RichText::new("🔍 Redetectar Leitores e Tokens").strong()).clicked() {
                let _ = command_sender.send(AppCommand::DetectA3Hardware);
            }
        });
    });

    ui.add_space(8.0);

    let summary = state.a3_diagnostics.clone().unwrap_or_default();

    // Tabela de status dos componentes de hardware
    ui.group(|ui| {
        ui.heading("Status dos Componentes do Sistema");
        ui.add_space(6.0);

        egui::Grid::new("a3_status_grid")
            .num_columns(3)
            .spacing([24.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                let items = [
                    ("Leitor de Smart Card", summary.reader_detected, "Detectado pelo serviço WinSCard"),
                    ("Cartão Inteligente (Smart Card)", summary.smart_card_detected, "Cartão presente no leitor"),
                    ("Token Criptográfico USB", summary.token_detected, "Dispositivo USB reconhecido"),
                    ("Provedor Criptográfico (KSP/CSP)", summary.provider_detected, "Driver/Minidriver registrado no Windows"),
                    ("Certificado A3 Associado", summary.certificate_detected, "Certificado vinculado à chave no dispositivo"),
                    ("Acesso à Chave Privada", summary.private_key_accessible, "Operações criptográficas autorizadas"),
                    ("Teste de Assinatura Digital", summary.signature_test_passed, "Assinatura e verificação aprovadas"),
                ];

                for (name, detected, desc) in items {
                    ui.label(RichText::new(name).strong());
                    if detected {
                        ui.label(RichText::new("✔ Detectado").color(colors.pass).strong());
                    } else {
                        ui.label(RichText::new("✖ Não detectado").color(colors.neutral));
                    }
                    ui.label(RichText::new(desc).color(colors.neutral).size(12.0));
                    ui.end_row();
                }
            });
    });

    ui.add_space(12.0);

    // Lista de leitores detectados
    ui.group(|ui| {
        ui.heading("Leitores Conectados");
        ui.add_space(6.0);

        if summary.readers.is_empty() {
            ui.label(RichText::new("Nenhum leitor de cartão inteligente detectado no momento.").color(colors.neutral).italics());
        } else {
            for reader in &summary.readers {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(&reader.name).strong());
                    ui.separator();
                    if reader.is_card_present {
                        ui.label(RichText::new("Cartão Presente").color(colors.pass));
                        if let Some(atr) = &reader.card_atr_hex {
                            ui.label(RichText::new(format!("(ATR: {})", atr)).monospace().size(11.0));
                        }
                    } else {
                        ui.label(RichText::new("Sem cartão").color(colors.neutral));
                    }
                });
            }
        }
    });

    ui.add_space(12.0);

    // Guias de Solução de Problemas
    ui.group(|ui| {
        ui.heading("Diagnóstico de Causas de Falha Comuns em A3");
        ui.add_space(6.0);

        ui.label("• Token ou cartão bloqueado (tentativas de PIN excedidas);");
        ui.label("• Middleware ou driver do fabricante não instalado no Windows (ex.: SafeNet, Safesign, CryptoID);");
        ui.label("• Serviço 'Cartão Inteligente' (SCardSvr) do Windows desativado ou pausado;");
        ui.label("• Conflito de porta USB ou leitor sem alimentação suficiente;");
        ui.label("• Chave privada corrompida ou certificado desvinculado do container de hardware.");
    });
}
