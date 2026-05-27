mod app;
mod data;
mod engine;
mod theme;

use app::App;

fn main() -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([1280.0, 760.0])
        .with_title("算法推算工具 · Rust");

    let native_options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "算法推算工具",
        native_options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
