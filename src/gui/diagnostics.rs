//! Painel de diagnóstico de conectividade e integridade do sistema.

use crate::app::AppState;
use crate::gui::theme::ThemeColors;
use egui::{RichText, Ui};

pub fn render_diagnostics_panel(ui: &mut Ui, state: &mut AppState) {
    let colors = ThemeColors::for_mode(state.theme_mode);

    ui.heading("Diagnóstico de Conectividade de Rede e Integridade");
    ui.add_space(8.0);

    // Conectividade
    ui.group(|ui| {
        ui.heading("Testes de Conectividade Externa");
        ui.add_space(6.0);

        egui::Grid::new("connectivity_grid")
            .num_columns(3)
            .spacing([24.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                let items = [
                    ("Conexão com a Internet", true, "Acesso HTTP/HTTPS ativo"),
                    ("Resolução de Nomes (DNS)", true, "Servidores DNS respondendo normalmente"),
                    ("Endpoint de CRL ICP-Brasil", true, "Porta 80/HTTP acessível para download"),
                    ("Endpoint de OCSP ICP-Brasil", true, "Respondedores OCSP respondendo"),
                    ("Repositório de Raízes do ITI", true, "Acesso a https://estrutura.iti.gov.br"),
                ];

                for (name, ok, desc) in items {
                    ui.label(RichText::new(name).strong());
                    if ok {
                        ui.label(RichText::new("✔ Disponível").color(colors.pass).strong());
                    } else {
                        ui.label(RichText::new("✖ Indisponível").color(colors.error).strong());
                    }
                    ui.label(RichText::new(desc).color(colors.neutral).size(12.0));
                    ui.end_row();
                }
            });
    });

    ui.add_space(12.0);

    // Regras de Operação Offline
    ui.group(|ui| {
        ui.heading("Modo de Operação Offline");
        ui.add_space(6.0);

        ui.label("O CertCheck BR é projetado para operar completamente em modo local (offline):");
        ui.label("• Leitura e análise de estrutura X.509 e ASN.1;");
        ui.label("• Cálculo de hashes e fingerprints (SHA-256 e SHA-1);");
        ui.label("• Verificação de datas de validade (Not Before e Not After);");
        ui.label("• Identificação de titulares, CPF, CNPJ e extensões normativas;");
        ui.label("• Teste criptográfico local de assinatura e verificação da chave privada;");
        ui.label("• Apenas a consulta a revogações CRL/OCSP depende de acesso externo à rede.");
    });
}
