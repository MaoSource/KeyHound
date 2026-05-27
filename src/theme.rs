use egui::{epaint, style, Color32, FontFamily, FontId, Rounding, Stroke, Style, Visuals};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Density {
    Compact,
    Regular,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RadiusStyle {
    Sharp,
    Soft,
    Pill,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccentChoice {
    Rust,
    Blue,
    Green,
    Purple,
}

impl AccentChoice {
    pub fn color(self) -> Color32 {
        match self {
            AccentChoice::Rust => Color32::from_rgb(0xc2, 0x5a, 0x2e),
            AccentChoice::Blue => Color32::from_rgb(0x2a, 0x6f, 0xdb),
            AccentChoice::Green => Color32::from_rgb(0x1f, 0x8a, 0x5b),
            AccentChoice::Purple => Color32::from_rgb(0x7a, 0x5a, 0xe0),
        }
    }
}

#[derive(Clone)]
pub struct Tokens {
    pub bg: Color32,
    pub bg_sunken: Color32,
    pub surface: Color32,
    pub surface_2: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub divider: Color32,
    pub ink_1: Color32,
    pub ink_2: Color32,
    pub ink_3: Color32,
    pub ink_4: Color32,
    pub accent: Color32,
    pub accent_soft: Color32,
    pub accent_ink: Color32,
    pub ok: Color32,
    pub ok_soft: Color32,
    pub warn: Color32,
    pub warn_soft: Color32,
    pub err: Color32,
    pub err_soft: Color32,
    pub info: Color32,
    pub info_soft: Color32,
    pub dark: bool,
    pub r_sm: f32,
    pub r_md: f32,
    pub r_lg: f32,
    pub r_xl: f32,
    pub pad: f32,
    pub row: f32,
    pub gap: f32,
}

fn blend(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let inv = 1.0 - t;
    Color32::from_rgb(
        ((a.r() as f32 * inv) + (b.r() as f32 * t)) as u8,
        ((a.g() as f32 * inv) + (b.g() as f32 * t)) as u8,
        ((a.b() as f32 * inv) + (b.b() as f32 * t)) as u8,
    )
}

impl Tokens {
    pub fn light(accent: Color32, density: Density, radius: RadiusStyle) -> Self {
        let surface = Color32::from_rgb(0xff, 0xff, 0xff);
        let accent_soft = blend(surface, accent, 0.14);
        let ink_1 = Color32::from_rgb(0x1a, 0x18, 0x16);
        let accent_ink = blend(ink_1, accent, 0.78);
        let (pad, row, gap) = density_metrics(density);
        let (r_sm, r_md, r_lg, r_xl) = radius_metrics(radius);
        Self {
            bg: Color32::from_rgb(0xfa, 0xfa, 0xf8),
            bg_sunken: Color32::from_rgb(0xf4, 0xf3, 0xef),
            surface,
            surface_2: Color32::from_rgb(0xfa, 0xf9, 0xf6),
            border: Color32::from_rgb(0xe8, 0xe6, 0xe0),
            border_strong: Color32::from_rgb(0xd7, 0xd4, 0xcc),
            divider: Color32::from_rgb(0xec, 0xec, 0xea),
            ink_1,
            ink_2: Color32::from_rgb(0x4a, 0x47, 0x42),
            ink_3: Color32::from_rgb(0x8a, 0x85, 0x7d),
            ink_4: Color32::from_rgb(0xb8, 0xb4, 0xab),
            accent,
            accent_soft,
            accent_ink,
            ok: Color32::from_rgb(0x3a, 0x8c, 0x5a),
            ok_soft: Color32::from_rgb(0xe6, 0xf3, 0xea),
            warn: Color32::from_rgb(0xc7, 0x97, 0x36),
            warn_soft: Color32::from_rgb(0xf8, 0xee, 0xd6),
            err: Color32::from_rgb(0xc4, 0x4a, 0x3a),
            err_soft: Color32::from_rgb(0xf8, 0xe1, 0xdc),
            info: Color32::from_rgb(0x4a, 0x7a, 0xc4),
            info_soft: Color32::from_rgb(0xe1, 0xea, 0xf6),
            dark: false,
            r_sm,
            r_md,
            r_lg,
            r_xl,
            pad,
            row,
            gap,
        }
    }

    pub fn dark(accent: Color32, density: Density, radius: RadiusStyle) -> Self {
        // accent in dark mode is brighter
        let accent_bright = lighten(accent, 0.10);
        let surface = Color32::from_rgb(0x1a, 0x18, 0x16);
        let accent_soft = blend(surface, accent_bright, 0.28);
        let ink_1 = Color32::from_rgb(0xf3, 0xf1, 0xec);
        let accent_ink = blend(ink_1, accent_bright, 0.65);
        let (pad, row, gap) = density_metrics(density);
        let (r_sm, r_md, r_lg, r_xl) = radius_metrics(radius);
        Self {
            bg: Color32::from_rgb(0x13, 0x12, 0x10),
            bg_sunken: Color32::from_rgb(0x0d, 0x0c, 0x0b),
            surface,
            surface_2: Color32::from_rgb(0x20, 0x1d, 0x1a),
            border: Color32::from_rgb(0x2b, 0x28, 0x23),
            border_strong: Color32::from_rgb(0x3a, 0x36, 0x30),
            divider: Color32::from_rgb(0x24, 0x21, 0x20),
            ink_1,
            ink_2: Color32::from_rgb(0xc0, 0xbc, 0xb3),
            ink_3: Color32::from_rgb(0x80, 0x7c, 0x74),
            ink_4: Color32::from_rgb(0x54, 0x50, 0x49),
            accent: accent_bright,
            accent_soft,
            accent_ink,
            ok: Color32::from_rgb(0x5e, 0xc7, 0x8d),
            ok_soft: Color32::from_rgb(0x1f, 0x3a, 0x2a),
            warn: Color32::from_rgb(0xe6, 0xbc, 0x6a),
            warn_soft: Color32::from_rgb(0x3a, 0x30, 0x18),
            err: Color32::from_rgb(0xe8, 0x70, 0x5b),
            err_soft: Color32::from_rgb(0x3d, 0x21, 0x1c),
            info: Color32::from_rgb(0x76, 0xa0, 0xe2),
            info_soft: Color32::from_rgb(0x1b, 0x2a, 0x3d),
            dark: true,
            r_sm,
            r_md,
            r_lg,
            r_xl,
            pad,
            row,
            gap,
        }
    }
}

fn lighten(c: Color32, amount: f32) -> Color32 {
    let a = amount.clamp(0.0, 1.0);
    Color32::from_rgb(
        (c.r() as f32 + (255.0 - c.r() as f32) * a) as u8,
        (c.g() as f32 + (255.0 - c.g() as f32) * a) as u8,
        (c.b() as f32 + (255.0 - c.b() as f32) * a) as u8,
    )
}

fn density_metrics(density: Density) -> (f32, f32, f32) {
    match density {
        Density::Compact => (10.0, 26.0, 8.0),
        Density::Regular => (14.0, 32.0, 12.0),
    }
}

fn radius_metrics(radius: RadiusStyle) -> (f32, f32, f32, f32) {
    match radius {
        RadiusStyle::Sharp => (2.0, 3.0, 4.0, 6.0),
        RadiusStyle::Soft => (4.0, 6.0, 8.0, 12.0),
        RadiusStyle::Pill => (6.0, 10.0, 14.0, 18.0),
    }
}

pub fn apply_style(ctx: &egui::Context, t: &Tokens) {
    let mut style: Style = (*ctx.style()).clone();
    let mut visuals = if t.dark { Visuals::dark() } else { Visuals::light() };

    visuals.override_text_color = Some(t.ink_1);
    visuals.window_fill = t.surface;
    visuals.panel_fill = t.bg;
    visuals.faint_bg_color = t.bg_sunken;
    visuals.extreme_bg_color = t.bg_sunken;
    visuals.code_bg_color = t.bg_sunken;
    visuals.window_stroke = Stroke::new(1.0, t.border);
    visuals.window_rounding = Rounding::same(t.r_lg);
    visuals.menu_rounding = Rounding::same(t.r_md);
    visuals.selection.bg_fill = t.accent_soft;
    visuals.selection.stroke = Stroke::new(1.0, t.accent);
    visuals.hyperlink_color = t.accent_ink;

    let widget = &mut visuals.widgets;
    widget.noninteractive.bg_fill = t.surface;
    widget.noninteractive.weak_bg_fill = t.surface;
    widget.noninteractive.bg_stroke = Stroke::new(1.0, t.divider);
    widget.noninteractive.fg_stroke = Stroke::new(1.0, t.ink_2);
    widget.noninteractive.rounding = Rounding::same(t.r_md);

    widget.inactive.bg_fill = t.surface;
    widget.inactive.weak_bg_fill = t.surface;
    widget.inactive.bg_stroke = Stroke::new(1.0, t.border);
    widget.inactive.fg_stroke = Stroke::new(1.0, t.ink_1);
    widget.inactive.rounding = Rounding::same(t.r_md);

    widget.hovered.bg_fill = t.bg_sunken;
    widget.hovered.weak_bg_fill = t.bg_sunken;
    widget.hovered.bg_stroke = Stroke::new(1.0, t.border_strong);
    widget.hovered.fg_stroke = Stroke::new(1.0, t.ink_1);
    widget.hovered.rounding = Rounding::same(t.r_md);

    widget.active.bg_fill = t.accent_soft;
    widget.active.weak_bg_fill = t.accent_soft;
    widget.active.bg_stroke = Stroke::new(1.0, t.accent);
    widget.active.fg_stroke = Stroke::new(1.0, t.ink_1);
    widget.active.rounding = Rounding::same(t.r_md);

    widget.open.bg_fill = t.surface;
    widget.open.weak_bg_fill = t.surface;
    widget.open.bg_stroke = Stroke::new(1.0, t.border);
    widget.open.fg_stroke = Stroke::new(1.0, t.ink_1);
    widget.open.rounding = Rounding::same(t.r_md);

    style.visuals = visuals;
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(10.0, 4.0);
    style.spacing.interact_size = egui::vec2(40.0, t.row);
    style.spacing.icon_width = 14.0;
    style.spacing.icon_spacing = 6.0;
    style.spacing.menu_margin = egui::Margin::same(6.0);
    style.spacing.window_margin = egui::Margin::same(8.0);
    style.spacing.scroll.floating = true;
    style.spacing.scroll.bar_width = 6.0;
    style.spacing.scroll.floating_allocated_width = 0.0;
    style.spacing.scroll.bar_inner_margin = 0.0;
    style.spacing.scroll.bar_outer_margin = 0.0;

    style.text_styles = [
        (
            egui::TextStyle::Heading,
            FontId::new(15.0, FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Body,
            FontId::new(13.0, FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Button,
            FontId::new(12.5, FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Small,
            FontId::new(11.0, FontFamily::Proportional),
        ),
        (
            egui::TextStyle::Monospace,
            FontId::new(11.5, FontFamily::Monospace),
        ),
    ]
    .into();

    style.visuals.widgets.noninteractive.bg_fill = t.bg;

    ctx.set_style(style);

    // make the global background match
    let mut visuals = ctx.style().visuals.clone();
    visuals.panel_fill = t.bg;
    ctx.set_visuals(visuals);

    // suppress unused import warnings
    let _ = (epaint::Shadow::NONE, style::HandleShape::Circle);
}
