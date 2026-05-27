// release 构建在 Windows 上隐藏控制台窗口 (GUI 程序); debug 构建仍保留控制台便于看 panic / log
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod data;
mod engine;
mod theme;

use app::App;

fn load_icon() -> egui::IconData {
    let bytes = include_bytes!("../assets/icon.png");
    let img = image::load_from_memory(bytes)
        .expect("内置 icon.png 必须能解码")
        .into_rgba8();
    let (width, height) = img.dimensions();
    egui::IconData {
        rgba: img.into_raw(),
        width,
        height,
    }
}

fn main() -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1440.0, 900.0])
        .with_min_inner_size([1280.0, 760.0])
        .with_icon(load_icon())
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
