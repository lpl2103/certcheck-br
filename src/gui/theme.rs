//! Cores, estilos, tipografia nativa do Windows (Segoe UI) e padronização visual.

use crate::app::ThemeMode;
use crate::validation::CheckStatus;
use egui::{Color32, CornerRadius, Margin, Stroke, Visuals};

pub struct ThemeColors {
    pub pass: Color32,
    pub warning: Color32,
    pub error: Color32,
    pub info: Color32,
    pub accent: Color32,
    pub neutral: Color32,
    pub card_bg: Color32,
    pub border: Color32,
    pub header_bg: Color32,
}

impl ThemeColors {
    pub fn for_mode(mode: ThemeMode) -> Self {
        match mode {
            ThemeMode::Dark => Self {
                pass: Color32::from_rgb(52, 211, 153),      // Esmeralda claro
                warning: Color32::from_rgb(251, 191, 36),   // Âmbar
                error: Color32::from_rgb(248, 113, 113),    // Carmesim
                info: Color32::from_rgb(96, 165, 250),      // Azul claro
                accent: Color32::from_rgb(59, 130, 246),    // Azul Real
                neutral: Color32::from_rgb(156, 163, 175),  // Cinza médio
                card_bg: Color32::from_rgb(30, 41, 59),     // Slate 800
                border: Color32::from_rgb(51, 65, 85),      // Slate 700
                header_bg: Color32::from_rgb(15, 23, 42),   // Slate 900
            },
            ThemeMode::Light => Self {
                pass: Color32::from_rgb(16, 149, 93),       // Verde escuro
                warning: Color32::from_rgb(180, 83, 9),     // Laranja escuro
                error: Color32::from_rgb(220, 38, 38),      // Vermelho
                info: Color32::from_rgb(29, 78, 216),       // Azul
                accent: Color32::from_rgb(37, 99, 235),     // Azul Real
                neutral: Color32::from_rgb(107, 114, 128),  // Cinza
                card_bg: Color32::from_rgb(248, 250, 252),  // Slate 50
                border: Color32::from_rgb(226, 232, 240),   // Slate 200
                header_bg: Color32::from_rgb(241, 245, 249),// Slate 100
            },
        }
    }
}

/// Configura as fontes nativas do Windows (Segoe UI e Segoe UI Emoji) e aumenta a escala do texto.
pub fn configure_native_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // 1. Tenta carregar a fonte padrão do Windows: Segoe UI
    let segoe_path = "C:\\Windows\\Fonts\\segoeui.ttf";
    if let Ok(font_data) = std::fs::read(segoe_path) {
        fonts.font_data.insert(
            "segoe_ui".to_owned(),
            std::sync::Arc::new(egui::FontData::from_owned(font_data)),
        );
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .insert(0, "segoe_ui".to_owned());
    }

    // 2. Tenta carregar a fonte de emojis nativa do Windows: Segoe UI Emoji
    let emoji_path = "C:\\Windows\\Fonts\\seguiemj.ttf";
    if let Ok(emoji_data) = std::fs::read(emoji_path) {
        fonts.font_data.insert(
            "segoe_ui_emoji".to_owned(),
            std::sync::Arc::new(egui::FontData::from_owned(emoji_data)),
        );
        // Coloca como fallback para glifos e símbolos emojis
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push("segoe_ui_emoji".to_owned());
    }

    ctx.set_fonts(fonts);

    // 3. Ajusta e aumenta a escala dos estilos de texto para maior conforto e legibilidade
    ctx.style_mut(|style| {
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(22.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(15.5, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(15.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            egui::FontId::new(13.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(14.0, egui::FontFamily::Monospace),
        );

        // Espaçamento confortável entre itens
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 6.0);
    });

    // Zoom leve para deixar toda a interface mais legível
    ctx.set_zoom_factor(1.05);
}

pub fn configure_visuals(ctx: &egui::Context, mode: ThemeMode) {
    let mut visuals = match mode {
        ThemeMode::Dark => Visuals::dark(),
        ThemeMode::Light => Visuals::light(),
    };

    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);

    ctx.set_visuals(visuals);
}

/// Desenha uma badge colorida indicando o status com símbolo e texto legível.
pub fn render_status_badge(ui: &mut egui::Ui, status: CheckStatus, mode: ThemeMode) {
    let colors = ThemeColors::for_mode(mode);
    let (bg, text_color, label) = match status {
        CheckStatus::Pass => (colors.pass.gamma_multiply(0.18), colors.pass, "✔ PASS"),
        CheckStatus::Warning => (colors.warning.gamma_multiply(0.18), colors.warning, "⚠ AVISO"),
        CheckStatus::Error => (colors.error.gamma_multiply(0.18), colors.error, "✖ FALHA"),
        CheckStatus::Info => (colors.info.gamma_multiply(0.18), colors.info, "ℹ INFO"),
        CheckStatus::NotChecked => (colors.neutral.gamma_multiply(0.15), colors.neutral, "⏳ PENDENTE"),
        CheckStatus::NotApplicable => (colors.neutral.gamma_multiply(0.10), colors.neutral, "⚪ N/A"),
    };

    let frame = egui::Frame::NONE
        .fill(bg)
        .corner_radius(CornerRadius::same(4))
        .stroke(Stroke::new(1.0_f32, text_color))
        .inner_margin(Margin::symmetric(8, 2));

    frame.show(ui, |ui| {
        ui.label(egui::RichText::new(label).color(text_color).strong().size(11.5));
    });
}
