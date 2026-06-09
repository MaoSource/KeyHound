use crate::data::{
    default_rules, default_selection, AlgoGroup, HistStatus, Rule, ALGO_TREE, SAMPLE_HISTORY,
};
use crate::engine::{self, EngineHandle, EngineMsg, MsgLvl};
use crate::theme::{apply_style, AccentChoice, Density, RadiusStyle, Tokens};
use egui::{
    Align, Color32, FontFamily, FontId, Layout, Margin, Rect, Response, RichText, Rounding,
    ScrollArea, Sense, Stroke, TextEdit, Ui, Vec2, Widget,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

pub enum LoadMsg {
    Started { name: String, total: u64 },
    Progress { name: String, read: u64 },
    Done { name: String, bytes: Vec<u8> },
    Err { name: String, err: String },
}

#[derive(Clone)]
pub struct LoadProgress {
    pub name: String,
    pub read: u64,
    pub total: u64,
}

fn install_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    let cjk_candidates = [
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "C:\\Windows\\Fonts\\msyh.ttc",
    ];
    for path in cjk_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let data = egui::FontData {
                font: std::borrow::Cow::Owned(bytes),
                index: 0,
                tweak: egui::FontTweak::default(),
            };
            fonts.font_data.insert("cjk".into(), data);
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .push("cjk".into());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .push("cjk".into());
            break;
        }
    }

    let mono_candidates = [
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/SFNSMono.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
    ];
    for path in mono_candidates {
        if let Ok(bytes) = std::fs::read(path) {
            let data = egui::FontData {
                font: std::borrow::Cow::Owned(bytes),
                index: 0,
                tweak: egui::FontTweak::default(),
            };
            fonts.font_data.insert("mono".into(), data);
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, "mono".into());
            break;
        }
    }

    ctx.set_fonts(fonts);
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LenMode {
    Any,
    Common,
    Custom,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RightTab {
    Log,
    Results,
    History,
    Rules,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogLvl {
    Info,
    Ok,
    Warn,
    Err,
}

impl LogLvl {
    pub fn label(self) -> &'static str {
        match self {
            LogLvl::Info => "INFO",
            LogLvl::Ok => "OK",
            LogLvl::Warn => "WARN",
            LogLvl::Err => "ERR",
        }
    }
}

#[derive(Clone)]
pub struct LogEntry {
    pub t: String,
    pub lvl: LogLvl,
    pub msg: String,
    pub accent: bool,
}

#[derive(Clone)]
pub struct ResultCard {
    pub algo: String,
    pub elapsed: String,
    pub hit: bool,
    pub key: String,
    pub iv: Option<String>,
    pub plain: Option<String>,
    /// 完整明文字节, 给"导出原文"用 (preview 是 UI 截断版)
    pub plain_full: Option<Vec<u8>>,
    /// 命中判据说明 (e.g. "JSON 结构 · IV 已恢复"、"关键字命中")
    pub reason: String,
    pub pinned: bool,
}

#[derive(Clone, Copy)]
enum CardAction {
    CopyKey,
    CopyIv,
    ExportPlain,
    TogglePin,
}

#[derive(Clone)]
pub struct DumpFile {
    pub name: String,
    pub size: String,
    pub weight: u8,
    /// Arc 包裹避免大文件被深拷贝。clone() = 引用计数 +1, O(1)
    pub bytes: Arc<Vec<u8>>,
}

pub struct App {
    // --- Tweaks ---
    pub accent_choice: AccentChoice,
    pub dark: bool,
    pub density: Density,
    pub radius: RadiusStyle,
    pub show_rail_counts: bool,
    pub tokens: Tokens,
    pub show_tweaks: bool,

    // --- Workspace form state ---
    pub files: Vec<DumpFile>,
    pub ciphertext: String,
    pub plain_contains: String,
    pub known_plaintext: String,
    pub deep_search: bool,
    pub ascii_only: bool,
    pub dedup: bool,
    pub key_encode: bool,
    pub key_lens: String,
    pub len_mode: LenMode,
    pub len_min: String,
    pub len_max: String,
    pub threads: String,
    pub try_hard: bool,

    // --- Sidebar ---
    pub search: String,
    pub selected: HashMap<String, bool>,
    pub group_open: HashMap<String, bool>,

    // --- Right panel ---
    pub tab: RightTab,
    pub log: Vec<LogEntry>,
    pub results: Vec<ResultCard>,
    pub log_filters: HashMap<LogLvl, bool>,
    pub auto_scroll: bool,
    pub rules: Vec<Rule>,

    // --- Run state ---
    pub running: bool,
    pub progress: f32,
    pub run_started: Option<Instant>,
    pub phase_emitted: usize,
    pub engine: Option<EngineHandle>,

    // --- Async file loading ---
    pub load_tx: mpsc::Sender<LoadMsg>,
    pub load_rx: mpsc::Receiver<LoadMsg>,
    pub active_loads: Vec<LoadProgress>,
}

impl Default for App {
    fn default() -> Self {
        let accent_choice = AccentChoice::Rust;
        let density = Density::Regular;
        let radius = RadiusStyle::Soft;
        let tokens = Tokens::light(accent_choice.color(), density, radius);

        let mut group_open = HashMap::new();
        group_open.insert("hash".into(), true);
        group_open.insert("hmac".into(), true);
        group_open.insert("sym".into(), true);
        group_open.insert("asym".into(), false);

        let mut log_filters = HashMap::new();
        log_filters.insert(LogLvl::Info, true);
        log_filters.insert(LogLvl::Ok, true);
        log_filters.insert(LogLvl::Warn, true);
        log_filters.insert(LogLvl::Err, true);

        let now = chrono_now();
        let detected = default_thread_count();
        let init_log = vec![
            LogEntry {
                t: now.clone(),
                lvl: LogLvl::Info,
                msg: "应用启动 · core v0.4.2 (rust 1.78)".into(),
                accent: false,
            },
            LogEntry {
                t: now.clone(),
                lvl: LogLvl::Info,
                msg: "加载算法插件:6 组 · 34 项".into(),
                accent: false,
            },
            LogEntry {
                t: now,
                lvl: LogLvl::Ok,
                msg: format!(
                    "检测到系统 {} 个逻辑核, 线程池默认使用全部",
                    detected
                ),
                accent: false,
            },
        ];

        Self {
            accent_choice,
            dark: false,
            density,
            radius,
            show_rail_counts: true,
            tokens,
            show_tweaks: false,

            files: Vec::new(),
            ciphertext: String::new(),
            plain_contains: String::new(),
            known_plaintext: String::new(),
            deep_search: false,
            ascii_only: false,
            dedup: true,
            key_encode: true,
            key_lens: "8, 16, 24, 32".into(),
            len_mode: LenMode::Common,
            len_min: "8".into(),
            len_max: "16".into(),
            threads: default_thread_count_str(),
            try_hard: true,

            search: String::new(),
            selected: default_selection(),
            group_open,

            tab: RightTab::Log,
            log: init_log,
            results: Vec::new(),
            log_filters,
            auto_scroll: true,
            rules: default_rules(),

            running: false,
            progress: 0.0,
            run_started: None,
            phase_emitted: 0,
            engine: None,

            load_tx: {
                let (tx, _rx) = mpsc::channel();
                tx
            },
            load_rx: mpsc::channel().1,
            active_loads: Vec::new(),
        }
        .install_load_channel()
    }
}

impl App {
    fn install_load_channel(mut self) -> Self {
        // Default::default() 里的占位 channel 互不相通, 这里用真正的一对替换
        let (tx, rx) = mpsc::channel();
        self.load_tx = tx;
        self.load_rx = rx;
        self
    }
}

fn chrono_now() -> String {
    // simple HH:MM:SS using std time; std::time::SystemTime is enough but not formatted
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = (secs % 60) as u32;
    let m = ((secs / 60) % 60) as u32;
    let h = ((secs / 3600) % 24) as u32;
    format!("{:02}:{:02}:{:02}", h, m, s)
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        install_fonts(&cc.egui_ctx);
        let s = Self::default();
        apply_style(&cc.egui_ctx, &s.tokens);
        s
    }

    fn refresh_theme(&mut self, ctx: &egui::Context) {
        let accent = self.accent_choice.color();
        self.tokens = if self.dark {
            Tokens::dark(accent, self.density, self.radius)
        } else {
            Tokens::light(accent, self.density, self.radius)
        };
        apply_style(ctx, &self.tokens);
    }

    fn selected_count(&self) -> usize {
        self.selected.values().filter(|v| **v).count()
    }

    fn start_run(&mut self) {
        // 加载未完成 → 拒绝启动
        if !self.active_loads.is_empty() {
            self.append_log(
                LogLvl::Warn,
                format!("仍有 {} 个文件加载中, 等待完成后再推算", self.active_loads.len()),
                false,
            );
            return;
        }

        // 1. 解析密文
        let ct = match engine::parse_ciphertext(&self.ciphertext) {
            Ok(b) => b,
            Err(e) => {
                self.append_log(LogLvl::Err, format!("密文解析失败: {e}"), false);
                return;
            }
        };

        // 2. 选中的算法 id
        let algo_ids: Vec<String> = self
            .selected
            .iter()
            .filter_map(|(k, v)| if *v { Some(k.clone()) } else { None })
            .collect();
        if algo_ids.is_empty() {
            self.append_log(LogLvl::Err, "未选择任何算法", false);
            return;
        }

        // 3. 候选长度集合: 从 "候选长度" + "KEY 长度" 两个字段合并
        let mut lens = parse_lens_csv(&self.key_lens);
        match self.len_mode {
            LenMode::Custom => {
                let a = self.len_min.trim().parse::<usize>().unwrap_or(0);
                let b = self.len_max.trim().parse::<usize>().unwrap_or(0);
                if a > 0 && b >= a {
                    for n in a..=b {
                        if !lens.contains(&n) {
                            lens.push(n);
                        }
                    }
                }
            }
            LenMode::Common => {
                for n in [8usize, 16, 24, 32] {
                    if !lens.contains(&n) {
                        lens.push(n);
                    }
                }
            }
            LenMode::Any => {
                for n in [5usize, 6, 7, 8, 10, 12, 16, 20, 24, 32] {
                    if !lens.contains(&n) {
                        lens.push(n);
                    }
                }
            }
        }
        if lens.is_empty() {
            self.append_log(LogLvl::Err, "候选 KEY 长度集合为空", false);
            return;
        }

        let threads = self
            .threads
            .trim()
            .parse::<usize>()
            .unwrap_or_else(|_| default_thread_count())
            .max(1)
            .min(256);

        // 4. 数据源字节 (Arc clone = 引用计数 +1, 不拷贝实际字节)
        let file_bytes: Vec<Arc<Vec<u8>>> =
            self.files.iter().map(|f| f.bytes.clone()).collect();

        let cfg = engine::EngineConfig {
            algo_ids,
            key_lens: lens,
            ascii_only: self.ascii_only,
            dedup: self.dedup,
            key_encode: self.key_encode,
            deep_search: self.deep_search,
            plain_contains: self.plain_contains.clone(),
            known_plaintext: self.known_plaintext.clone(),
            threads,
        };

        let handle = engine::spawn(cfg, file_bytes, ct);
        self.engine = Some(handle);
        self.running = true;
        self.progress = 0.0;
        self.run_started = Some(Instant::now());
        self.phase_emitted = 0;
        self.tab = RightTab::Log;
        self.append_log(LogLvl::Info, "推算已启动", true);
    }

    fn stop_run(&mut self) {
        if let Some(h) = &self.engine {
            h.stop.store(true, Ordering::Relaxed);
            self.append_log(LogLvl::Warn, "请求停止...", false);
        } else {
            self.running = false;
            self.progress = 0.0;
            self.run_started = None;
        }
    }

    fn apply_card_action(&mut self, ctx: &egui::Context, idx: usize, action: CardAction) {
        if idx >= self.results.len() {
            return;
        }
        match action {
            CardAction::CopyKey => {
                let key = self.results[idx].key.clone();
                ctx.copy_text(key.clone());
                self.append_log(LogLvl::Ok, format!("已复制 KEY 到剪贴板: {}", key), false);
            }
            CardAction::CopyIv => {
                let Some(iv) = self.results[idx].iv.clone() else { return };
                ctx.copy_text(iv.clone());
                self.append_log(LogLvl::Ok, format!("已复制 IV 到剪贴板: {}", iv), false);
            }
            CardAction::ExportPlain => {
                let r = &self.results[idx];
                let algo = r.algo.clone();
                let key = r.key.clone();
                let iv = r.iv.clone();
                let plain_bytes: Option<Vec<u8>> = r.plain_full.clone();
                let plain_preview = r.plain.clone();
                let ciphertext_raw = self.ciphertext.trim().to_string();
                let ciphertext_hex = match engine::parse_ciphertext(&ciphertext_raw) {
                    Ok(bytes) => Some(hex::encode(bytes)),
                    Err(_) => None,
                };

                // hex 解码后, 字节全可打印 ASCII → 原样, 否则标注二进制。
                let as_ascii = |h: &str| -> String {
                    match hex::decode(h) {
                        Ok(bytes) if !bytes.is_empty()
                            && bytes.iter().all(|&b| (0x20..=0x7e).contains(&b)) =>
                        {
                            String::from_utf8(bytes).unwrap_or_else(|_| "(二进制, 非 ASCII)".into())
                        }
                        _ => "(二进制, 非 ASCII)".into(),
                    }
                };

                let mut out = String::new();
                out.push_str(&format!("算法: {}\n", algo));
                out.push_str(&format!("Key (hex):   {}\n", key));
                out.push_str(&format!("Key (ASCII): {}\n", as_ascii(&key)));
                if let Some(iv) = &iv {
                    out.push_str(&format!("IV  (hex):   {}\n", iv));
                    out.push_str(&format!("IV  (ASCII): {}\n", as_ascii(iv)));
                }
                out.push_str("\n");
                out.push_str("密文 (原始输入):\n");
                out.push_str(&ciphertext_raw);
                out.push_str("\n");
                if let Some(hexed) = &ciphertext_hex {
                    out.push_str("\n密文 (hex 规范化):\n");
                    out.push_str(hexed);
                    out.push_str("\n");
                }
                out.push_str("\n明文:\n");
                if let Some(bytes) = &plain_bytes {
                    out.push_str(&String::from_utf8_lossy(bytes));
                    out.push_str("\n\n明文 (hex):\n");
                    out.push_str(&hex::encode(bytes));
                    out.push_str("\n");
                } else if let Some(s) = &plain_preview {
                    out.push_str(s);
                    out.push_str("\n");
                } else {
                    out.push_str("(无)\n");
                }

                let suggested = format!("{}_report.txt", algo.replace('/', "_"));
                let picked = rfd::FileDialog::new()
                    .set_file_name(&suggested)
                    .add_filter("text", &["txt"])
                    .add_filter("any", &["*"])
                    .save_file();
                if let Some(path) = picked {
                    match std::fs::write(&path, out.as_bytes()) {
                        Ok(_) => self.append_log(
                            LogLvl::Ok,
                            format!("已导出报告 ({} 字节) 到 {}", out.len(), path.display()),
                            true,
                        ),
                        Err(e) => self.append_log(
                            LogLvl::Err,
                            format!("导出失败: {}", e),
                            false,
                        ),
                    }
                }
            }
            CardAction::TogglePin => {
                let pinned = !self.results[idx].pinned;
                self.results[idx].pinned = pinned;
                let algo = self.results[idx].algo.clone();
                self.append_log(
                    LogLvl::Info,
                    if pinned { format!("已固定 {}", algo) } else { format!("已取消固定 {}", algo) },
                    false,
                );
            }
        }
    }

    fn pick_dump_files(&mut self) {
        let picked = rfd::FileDialog::new()
            .add_filter("dump / binary", &["dmp", "bin", "so", "dll", "dat", "raw"])
            .add_filter("any", &["*"])
            .pick_files();
        let Some(paths) = picked else { return };
        self.dispatch_path_loads(paths);
    }

    fn ingest_dropped(&mut self, ctx: &egui::Context) {
        let dropped: Vec<egui::DroppedFile> =
            ctx.input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }

        enum Src {
            Inline(Arc<[u8]>),
            Path(PathBuf),
        }
        let mut jobs: Vec<(String, Src)> = Vec::new();
        for d in dropped {
            let name = if !d.name.is_empty() {
                d.name.clone()
            } else {
                d.path
                    .as_ref()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "dropped".into())
            };
            if let Some(arc) = d.bytes {
                jobs.push((name, Src::Inline(arc)));
            } else if let Some(p) = d.path.clone() {
                jobs.push((name, Src::Path(p)));
            }
        }
        if jobs.is_empty() {
            return;
        }

        self.append_log(
            LogLvl::Info,
            format!("后台加载 {} 个拖入文件 (UI 不阻塞)", jobs.len()),
            false,
        );
        let tx = self.load_tx.clone();
        std::thread::spawn(move || {
            for (name, src) in jobs {
                match src {
                    Src::Inline(arc) => {
                        let total = arc.len() as u64;
                        let _ = tx.send(LoadMsg::Started {
                            name: name.clone(),
                            total,
                        });
                        let bytes = arc.to_vec();
                        let _ = tx.send(LoadMsg::Done { name, bytes });
                    }
                    Src::Path(p) => {
                        load_path_chunked(&p, name, &tx);
                    }
                }
            }
        });
    }

    fn dispatch_path_loads(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        self.append_log(
            LogLvl::Info,
            format!("后台加载 {} 个文件 (UI 不阻塞)", paths.len()),
            false,
        );
        let tx = self.load_tx.clone();
        std::thread::spawn(move || {
            for p in paths {
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "dump".into());
                load_path_chunked(&p, name, &tx);
            }
        });
    }

    fn drain_loads(&mut self, ctx: &egui::Context) {
        let mut msgs = Vec::new();
        while let Ok(m) = self.load_rx.try_recv() {
            msgs.push(m);
        }
        if msgs.is_empty() {
            // 仍有未完成加载: 保持周期重绘以更新进度条
            if !self.active_loads.is_empty() {
                ctx.request_repaint_after(std::time::Duration::from_millis(80));
            }
            return;
        }
        for m in msgs {
            match m {
                LoadMsg::Started { name, total } => {
                    self.active_loads.push(LoadProgress {
                        name,
                        read: 0,
                        total,
                    });
                }
                LoadMsg::Progress { name, read } => {
                    if let Some(lp) =
                        self.active_loads.iter_mut().find(|lp| lp.name == name)
                    {
                        lp.read = read;
                    }
                }
                LoadMsg::Done { name, bytes } => {
                    self.active_loads.retain(|lp| lp.name != name);
                    let size = humanize_bytes(bytes.len());
                    let weight = pick_weight(&bytes);
                    self.append_log(
                        LogLvl::Ok,
                        format!("已加载 {} ({})", name, size),
                        false,
                    );
                    self.files.push(DumpFile {
                        name,
                        size,
                        weight,
                        bytes: Arc::new(bytes),
                    });
                }
                LoadMsg::Err { name, err } => {
                    self.active_loads.retain(|lp| lp.name != name);
                    self.append_log(
                        LogLvl::Err,
                        format!("加载失败 {}: {}", name, err),
                        false,
                    );
                }
            }
        }
        if !self.active_loads.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
    }

    fn append_log(&mut self, lvl: LogLvl, msg: impl Into<String>, accent: bool) {
        self.log.push(LogEntry {
            t: chrono_now(),
            lvl,
            msg: msg.into(),
            accent,
        });
    }

    fn drive_run(&mut self, ctx: &egui::Context) {
        // 先把 channel 抽干到本地 Vec, 再处理, 避免对 self 的双重借用
        let mut pending: Vec<EngineMsg> = Vec::new();
        if let Some(handle) = self.engine.as_ref() {
            while let Ok(msg) = handle.rx.try_recv() {
                pending.push(msg);
            }
        }

        let mut done = false;
        for msg in pending {
            match msg {
                EngineMsg::Log { lvl, msg, accent } => {
                    self.append_log(map_msg_lvl(lvl), msg, accent);
                }
                EngineMsg::Progress { pct, current: _ } => {
                    self.progress = pct;
                }
                EngineMsg::Hit {
                    algo,
                    key_hex,
                    iv_hex,
                    plain_preview,
                    plain_full,
                    reason,
                    elapsed_ms,
                } => {
                    let dup = self
                        .results
                        .iter()
                        .any(|x| x.algo == algo && x.key == key_hex);
                    if !dup {
                        self.results.push(ResultCard {
                            algo,
                            elapsed: format!("+{:.1}s", elapsed_ms as f32 / 1000.0),
                            hit: true,
                            key: key_hex,
                            iv: iv_hex,
                            plain: plain_preview,
                            plain_full,
                            reason,
                            pinned: false,
                        });
                        self.tab = RightTab::Results;
                    }
                }
                EngineMsg::Done { .. } => {
                    done = true;
                }
            }
        }

        if done {
            self.running = false;
            self.progress = 100.0;
            self.engine = None;
        }

        if self.running {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
    }
}

fn map_msg_lvl(l: MsgLvl) -> LogLvl {
    match l {
        MsgLvl::Info => LogLvl::Info,
        MsgLvl::Ok => LogLvl::Ok,
        MsgLvl::Warn => LogLvl::Warn,
        MsgLvl::Err => LogLvl::Err,
    }
}

fn parse_lens_csv(s: &str) -> Vec<usize> {
    let mut out: Vec<usize> = s
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|t| {
            let t = t.trim();
            if t.is_empty() {
                None
            } else {
                t.parse::<usize>().ok()
            }
        })
        .filter(|&n| n > 0 && n <= 256)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn humanize_bytes(n: usize) -> String {
    let kb = 1024.0_f64;
    let mb = kb * 1024.0;
    let gb = mb * 1024.0;
    let f = n as f64;
    if f >= gb {
        format!("{:.1} GB", f / gb)
    } else if f >= mb {
        format!("{:.1} MB", f / mb)
    } else if f >= kb {
        format!("{:.1} KB", f / kb)
    } else {
        format!("{} B", n)
    }
}

fn load_path_chunked(path: &PathBuf, name: String, tx: &mpsc::Sender<LoadMsg>) {
    use std::io::Read;
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            let _ = tx.send(LoadMsg::Err {
                name,
                err: e.to_string(),
            });
            return;
        }
    };
    let total = file.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = tx.send(LoadMsg::Started {
        name: name.clone(),
        total,
    });

    // 大块直读到最终 Vec，无 BufReader / 中间 chunk，单次拷贝。
    // 对大文件（>= 16MB）系统分配器会走 mmap(MAP_ANONYMOUS)，零页惰性映射，
    // 这里的 vec![0; total] 在 macOS / Linux 上是常数时间。
    let total_usz = total as usize;
    let mut bytes: Vec<u8> = vec![0u8; total_usz];
    const CHUNK: usize = 16 * 1024 * 1024; // 16 MB
    let mut offset: usize = 0;
    let mut last_report = std::time::Instant::now();

    while offset < total_usz {
        let end = (offset + CHUNK).min(total_usz);
        match file.read(&mut bytes[offset..end]) {
            Ok(0) => {
                // 提前 EOF：截断为已读长度
                bytes.truncate(offset);
                break;
            }
            Ok(n) => {
                offset += n;
                if last_report.elapsed() >= std::time::Duration::from_millis(100) {
                    let _ = tx.send(LoadMsg::Progress {
                        name: name.clone(),
                        read: offset as u64,
                    });
                    last_report = std::time::Instant::now();
                }
            }
            Err(e) => {
                let _ = tx.send(LoadMsg::Err {
                    name,
                    err: e.to_string(),
                });
                return;
            }
        }
    }

    let _ = tx.send(LoadMsg::Done { name, bytes });
}

fn default_thread_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8)
}

fn default_thread_count_str() -> String {
    default_thread_count().to_string()
}

fn pick_weight(b: &[u8]) -> u8 {
    // 启发式权重: 文件大且 ASCII 含量高 → 权重高
    if b.is_empty() {
        return 1;
    }
    let printable = b
        .iter()
        .take(4096)
        .filter(|&&c| (0x20..=0x7e).contains(&c))
        .count();
    let r = printable as f32 / b.len().min(4096) as f32;
    if r > 0.6 {
        3
    } else if r > 0.3 {
        2
    } else {
        1
    }
}

// ─────────────────────────────────────────────────────────────────
// eframe entry
// ─────────────────────────────────────────────────────────────────

impl eframe::App for App {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        let c = self.tokens.bg;
        [
            c.r() as f32 / 255.0,
            c.g() as f32 / 255.0,
            c.b() as f32 / 255.0,
            1.0,
        ]
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ingest_dropped(ctx);
        self.drain_loads(ctx);
        self.drive_run(ctx);

        let t = self.tokens.clone();

        // Top titlebar
        egui::TopBottomPanel::top("titlebar")
            .exact_height(44.0)
            .frame(panel_frame(&t, t.surface, true, false))
            .show(ctx, |ui| {
                self.titlebar_ui(ui, &t);
            });

        // Bottom statusbar
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(26.0)
            .frame(panel_frame(&t, t.surface, false, true))
            .show(ctx, |ui| {
                self.statusbar_ui(ui, &t);
            });

        // Left rail
        egui::SidePanel::left("rail")
            .resizable(false)
            .exact_width(252.0)
            .frame(panel_frame(&t, t.surface, false, false))
            .show(ctx, |ui| {
                self.rail_ui(ui, &t);
            });

        // Right pane
        egui::SidePanel::right("logpane")
            .resizable(true)
            .min_width(360.0)
            .default_width(380.0)
            .frame(panel_frame(&t, t.surface, false, false))
            .show(ctx, |ui| {
                self.right_pane_ui(ui, &t);
            });

        // Center workspace
        egui::CentralPanel::default()
            .frame(egui::Frame {
                fill: t.bg,
                stroke: Stroke::NONE,
                ..Default::default()
            })
            .show(ctx, |ui| {
                self.workspace_ui(ui, &t);
            });

        // Tweaks floating window
        if self.show_tweaks {
            let mut open = self.show_tweaks;
            egui::Window::new(RichText::new("调整 · Tweaks").size(13.0).color(t.ink_1))
                .open(&mut open)
                .resizable(false)
                .collapsible(false)
                .default_width(280.0)
                .anchor(egui::Align2::RIGHT_BOTTOM, [-16.0, -40.0])
                .show(ctx, |ui| {
                    self.tweaks_ui(ui, &t);
                });
            self.show_tweaks = open;
        }
    }
}

fn panel_frame(t: &Tokens, fill: Color32, bottom_border: bool, top_border: bool) -> egui::Frame {
    let mut stroke = Stroke::NONE;
    let _ = (bottom_border, top_border, &stroke);
    egui::Frame {
        fill,
        inner_margin: Margin::ZERO,
        outer_margin: Margin::ZERO,
        stroke: Stroke::new(0.0, t.border),
        rounding: Rounding::ZERO,
        shadow: egui::epaint::Shadow::NONE,
    }
}

// ─────────────────────────────────────────────────────────────────
// Titlebar
// ─────────────────────────────────────────────────────────────────

impl App {
    fn titlebar_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        // bottom border line
        let rect = ui.max_rect();
        ui.painter().line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            Stroke::new(1.0, t.border),
        );

        ui.horizontal_centered(|ui| {
            ui.add_space(14.0);
            // brand mark — orange gradient square with R cutout (matches design)
            let (mark_rect, _) =
                ui.allocate_exact_size(Vec2::new(18.0, 18.0), Sense::hover());
            draw_brand_mark(ui, t, mark_rect);

            ui.add_space(8.0);
            ui.label(
                RichText::new("算法推算工具")
                    .size(13.0)
                    .strong()
                    .color(t.ink_1),
            );
            ui.add_space(4.0);
            chip(ui, t, "v0.4.2 · rust", t.ink_3, t.bg_sunken);

            // command palette trigger (centered-ish; use spacer pattern)
            ui.add_space(16.0);
            ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                // We won't truly center; place it inline after some space.
                ui.add_space(ui.available_width() * 0.18);
                let resp = command_trigger(ui, t);
                if resp.clicked() {
                    self.show_tweaks = !self.show_tweaks;
                }
            });

            // right-aligned status pills
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(14.0);
                status_pill(
                    ui,
                    t,
                    if self.running { "推算中" } else { "空闲" },
                    if self.running { t.accent } else { t.ok },
                );
                ui.add_space(6.0);
                let n = self.threads.trim().parse::<usize>().unwrap_or_else(|_| default_thread_count());
                status_pill(ui, t, &format!("{} / {} 线程", n, default_thread_count()), t.ink_3);
            });
        });
    }
}

fn chip(ui: &mut Ui, t: &Tokens, text: &str, color: Color32, fill: Color32) -> Response {
    let font = FontId::new(11.0, FontFamily::Monospace);
    let galley = ui.painter().layout_no_wrap(text.into(), font, color);
    let pad = Vec2::new(6.0, 2.0);
    let size = galley.size() + pad * 2.0;
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(
        rect,
        Rounding::same(t.r_sm),
        fill,
        Stroke::new(1.0, t.border),
    );
    ui.painter()
        .galley(rect.min + pad, galley, color);
    resp
}

fn draw_brand_mark(ui: &Ui, t: &Tokens, rect: Rect) {
    let painter = ui.painter();
    // simulated 135deg gradient using two halves
    let top_color = t.accent;
    let bottom_color = lighten_warm(t.accent);
    // base — top half
    painter.rect_filled(
        Rect::from_min_max(rect.min, egui::pos2(rect.max.x, rect.center().y)),
        Rounding {
            nw: 5.0,
            ne: 5.0,
            sw: 0.0,
            se: 0.0,
        },
        top_color,
    );
    painter.rect_filled(
        Rect::from_min_max(egui::pos2(rect.min.x, rect.center().y), rect.max),
        Rounding {
            nw: 0.0,
            ne: 0.0,
            sw: 5.0,
            se: 5.0,
        },
        bottom_color,
    );
    // inner R-like notch: light "R" letterform
    painter.text(
        rect.center() + Vec2::new(0.0, -0.5),
        egui::Align2::CENTER_CENTER,
        "R",
        FontId::new(11.5, FontFamily::Proportional),
        Color32::from_rgba_unmultiplied(255, 255, 255, 235),
    );
}

fn lighten_warm(c: Color32) -> Color32 {
    // pushes orange toward a warmer / lighter shade (mimics oklch(0.68 0.16 50))
    Color32::from_rgb(
        c.r().saturating_add(20),
        c.g().saturating_add(10),
        c.b().saturating_sub(0),
    )
}

fn status_pill(ui: &mut Ui, t: &Tokens, text: &str, dot_color: Color32) -> Response {
    let font = FontId::new(11.5, FontFamily::Proportional);
    let galley = ui
        .painter()
        .layout_no_wrap(text.into(), font, t.ink_2);
    let pad_x = 9.0;
    let pad_y = 4.0;
    let dot_w = 13.0;
    let size = Vec2::new(galley.size().x + dot_w + pad_x * 2.0, galley.size().y + pad_y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(
        rect,
        Rounding::same(999.0),
        t.bg_sunken,
        Stroke::new(1.0, t.border),
    );
    let dot_center = egui::pos2(rect.min.x + pad_x + 3.5, rect.center().y);
    ui.painter().circle_filled(dot_center, 3.5, dot_color);
    ui.painter().galley(
        egui::pos2(rect.min.x + pad_x + dot_w, rect.min.y + pad_y),
        galley,
        t.ink_2,
    );
    resp
}

fn command_trigger(ui: &mut Ui, t: &Tokens) -> Response {
    let h = 26.0;
    let w = ui.available_width().min(280.0).max(220.0);
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let bg = if resp.hovered() { t.surface } else { t.bg_sunken };
    let border = if resp.hovered() { t.border_strong } else { t.border };
    ui.painter()
        .rect(rect, Rounding::same(t.r_md), bg, Stroke::new(1.0, border));

    let painter = ui.painter();
    // search icon (just draw a small circle + tail)
    let icon_center = egui::pos2(rect.min.x + 14.0, rect.center().y);
    painter.circle_stroke(icon_center, 4.0, Stroke::new(1.4, t.ink_3));
    painter.line_segment(
        [
            egui::pos2(icon_center.x + 3.0, icon_center.y + 3.0),
            egui::pos2(icon_center.x + 6.0, icon_center.y + 6.0),
        ],
        Stroke::new(1.4, t.ink_3),
    );

    let label_font = FontId::new(12.0, FontFamily::Proportional);
    painter.text(
        egui::pos2(rect.min.x + 26.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        "搜索算法、命令、文件…",
        label_font,
        t.ink_3,
    );

    // kbd hint on right
    let kbd_y = rect.center().y;
    let mut x = rect.max.x - 8.0;
    for ch in ["K", "⌘"] {
        let g = painter.layout_no_wrap(
            ch.to_string(),
            FontId::new(10.5, FontFamily::Monospace),
            t.ink_3,
        );
        let pad = Vec2::new(5.0, 1.0);
        let kbd_size = g.size() + pad * 2.0;
        let kbd_rect = Rect::from_min_size(
            egui::pos2(x - kbd_size.x, kbd_y - kbd_size.y / 2.0),
            kbd_size,
        );
        painter.rect(
            kbd_rect,
            Rounding::same(3.0),
            t.surface,
            Stroke::new(1.0, t.border),
        );
        painter.galley(kbd_rect.min + pad, g, t.ink_3);
        x -= kbd_size.x + 4.0;
    }

    resp
}

// ─────────────────────────────────────────────────────────────────
// Statusbar
// ─────────────────────────────────────────────────────────────────

impl App {
    fn statusbar_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        let rect = ui.max_rect();
        ui.painter().line_segment(
            [rect.left_top(), rect.right_top()],
            Stroke::new(1.0, t.border),
        );
        ui.horizontal_centered(|ui| {
            ui.add_space(14.0);
            let dot_color = if self.running { t.accent } else { t.ok };
            let (dot_rect, _) = ui.allocate_exact_size(Vec2::splat(7.0), Sense::hover());
            ui.painter()
                .circle_filled(dot_rect.center(), 3.5, dot_color);
            let main = if self.running {
                format!("推算中 {:.0}%", self.progress)
            } else {
                "就绪".into()
            };
            ui.label(
                RichText::new(main)
                    .color(t.accent_ink)
                    .size(11.5)
                    .family(FontFamily::Monospace),
            );
            sep(ui, t);
            mono(ui, t, &format!("算法 {}", self.selected_count()));
            sep(ui, t);
            mono(ui, t, &format!("索引 {}", self.files.len()));
            sep(ui, t);
            let n = self.threads.trim().parse::<usize>().unwrap_or_else(|_| default_thread_count());
            mono(ui, t, &format!("线程 {}/{}", n, default_thread_count()));

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(14.0);
                mono(ui, t, "© 本地工具 · 非联网");
                sep(ui, t);
                mono(ui, t, "rust 1.78 (stable)");
                sep(ui, t);
                mono(ui, t, "core v0.4.2");
            });
        });
    }
}

fn sep(ui: &mut Ui, t: &Tokens) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(1.0, 12.0), Sense::hover());
    ui.painter()
        .line_segment([rect.center_top(), rect.center_bottom()], Stroke::new(1.0, t.divider));
}

fn mono(ui: &mut Ui, t: &Tokens, text: &str) {
    ui.label(
        RichText::new(text)
            .color(t.ink_3)
            .family(FontFamily::Monospace)
            .size(11.5),
    );
}

// ─────────────────────────────────────────────────────────────────
// Left rail – algorithm tree
// ─────────────────────────────────────────────────────────────────

impl App {
    fn rail_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        let rect = ui.max_rect();
        let rail_right = rect.max.x;
        ui.painter().line_segment(
            [rect.right_top(), rect.right_bottom()],
            Stroke::new(1.0, t.border),
        );

        // Header
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            ui.add_space(14.0);
            ui.label(
                RichText::new("算法范围")
                    .size(11.0)
                    .strong()
                    .color(t.ink_3),
            );
        });
        ui.add_space(8.0);
        // Search input — custom-framed (sunken bg + 1px border + leading icon)
        ui.horizontal(|ui| {
            ui.add_space(10.0);
            let search_w = ui.available_width() - 10.0;
            let search_h = 28.0;
            let (frame_rect, _) =
                ui.allocate_exact_size(Vec2::new(search_w, search_h), Sense::hover());
            ui.painter().rect(
                frame_rect,
                Rounding::same(t.r_md),
                t.bg_sunken,
                Stroke::new(1.0, t.border),
            );
            // leading magnifier icon
            let icon_c = egui::pos2(frame_rect.min.x + 14.0, frame_rect.center().y);
            ui.painter()
                .circle_stroke(icon_c, 4.0, Stroke::new(1.4, t.ink_3));
            ui.painter().line_segment(
                [
                    egui::pos2(icon_c.x + 3.0, icon_c.y + 3.0),
                    egui::pos2(icon_c.x + 6.0, icon_c.y + 6.0),
                ],
                Stroke::new(1.4, t.ink_3),
            );
            // TextEdit (frameless) inside the framed rect, padded so it clears the icon
            let edit_rect = Rect::from_min_max(
                egui::pos2(frame_rect.min.x + 26.0, frame_rect.min.y + 3.0),
                egui::pos2(frame_rect.max.x - 8.0, frame_rect.max.y - 3.0),
            );
            let mut sui =
                ui.new_child(egui::UiBuilder::new().max_rect(edit_rect).layout(
                    Layout::left_to_right(Align::Center),
                ));
            sui.add(
                TextEdit::singleline(&mut self.search)
                    .hint_text("搜索算法 · AES / SHA / SM …")
                    .font(FontId::new(12.0, FontFamily::Proportional))
                    .frame(false)
                    .desired_width(edit_rect.width()),
            );
        });

        ui.add_space(6.0);
        // divider
        let div_y = ui.cursor().min.y;
        ui.painter().line_segment(
            [
                egui::pos2(rect.min.x, div_y),
                egui::pos2(rail_right, div_y),
            ],
            Stroke::new(1.0, t.divider),
        );
        ui.add_space(4.0);

        let q = self.search.to_lowercase();
        let q_trim = q.trim().to_string();

        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .show(ui, |ui| {
                // Ensure painter clip extends to the full rail width so right-aligned
                // tags drawn near the panel edge aren't cut by the ScrollArea's tighter viewport.
                let cur = ui.clip_rect();
                let wider = Rect::from_min_max(
                    cur.min,
                    egui::pos2(rail_right, cur.max.y),
                );
                ui.set_clip_rect(wider);
                ui.add_space(2.0);
                for g in ALGO_TREE {
                    let filtered_items: Vec<&_> = g
                        .items
                        .iter()
                        .filter(|it| {
                            if q_trim.is_empty() {
                                true
                            } else {
                                it.name.to_lowercase().contains(&q_trim)
                                    || g.name.contains(&self.search)
                                    || g.en.to_lowercase().contains(&q_trim)
                            }
                        })
                        .collect();
                    if !q_trim.is_empty() && filtered_items.is_empty() {
                        continue;
                    }
                    self.draw_group(ui, t, g, &filtered_items, rail_right);
                }
            });
    }

    fn draw_group(
        &mut self,
        ui: &mut Ui,
        t: &Tokens,
        g: &AlgoGroup,
        items: &[&crate::data::AlgoItem],
        rail_right: f32,
    ) {
        let is_open = *self.group_open.get(g.id).unwrap_or(&true);
        let all = g.items.iter().all(|it| *self.selected.get(it.id).unwrap_or(&false));
        let some = g.items.iter().any(|it| *self.selected.get(it.id).unwrap_or(&false));
        let group_state: TriState = if all {
            TriState::On
        } else if some {
            TriState::Mixed
        } else {
            TriState::Off
        };
        let sel_count = g.items.iter().filter(|it| *self.selected.get(it.id).unwrap_or(&false)).count();

        // Header row
        let (row_rect, row_resp) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), 26.0),
            Sense::click(),
        );
        if row_resp.hovered() {
            ui.painter().rect_filled(
                row_rect.shrink2(Vec2::new(6.0, 1.0)),
                Rounding::same(t.r_sm),
                t.bg_sunken,
            );
        }
        let painter = ui.painter();
        // chevron
        let chev_x = row_rect.min.x + 12.0;
        let chev_c = egui::pos2(chev_x, row_rect.center().y);
        let chev_color = t.ink_3;
        if is_open {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(chev_c.x - 3.0, chev_c.y - 3.0),
                    egui::pos2(chev_c.x + 3.0, chev_c.y),
                    egui::pos2(chev_c.x - 3.0, chev_c.y + 3.0),
                ]
                .into_iter()
                .map(|p| egui::pos2(p.x, p.y + 1.0))
                .collect(),
                chev_color,
                Stroke::NONE,
            ));
            // rotate by drawing downward
            let _ = chev_color;
        } else {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    egui::pos2(chev_c.x - 3.0, chev_c.y - 3.0),
                    egui::pos2(chev_c.x + 3.0, chev_c.y),
                    egui::pos2(chev_c.x - 3.0, chev_c.y + 3.0),
                ],
                chev_color,
                Stroke::NONE,
            ));
        }

        // checkbox (custom)
        let cb_rect = Rect::from_min_size(
            egui::pos2(row_rect.min.x + 22.0, row_rect.center().y - 7.0),
            Vec2::splat(14.0),
        );
        let cb_resp = ui.interact(cb_rect, ui.id().with(("group_cb", g.id)), Sense::click());
        draw_checkbox(ui, t, cb_rect, group_state);

        // label
        let name_pos = egui::pos2(cb_rect.max.x + 8.0, row_rect.center().y);
        ui.painter().text(
            name_pos,
            egui::Align2::LEFT_CENTER,
            g.name,
            FontId::new(12.5, FontFamily::Proportional),
            t.ink_1,
        );

        // count badge on right
        if self.show_rail_counts {
            let txt = format!("{}/{}", sel_count, g.items.len());
            let font = FontId::new(10.5, FontFamily::Monospace);
            let galley = ui.painter().layout_no_wrap(txt, font, t.ink_3);
            let pad = Vec2::new(6.0, 1.0);
            let size = galley.size() + pad * 2.0;
            let pos = egui::pos2(rail_right - size.x - 20.0, row_rect.center().y - size.y / 2.0);
            let badge_rect = Rect::from_min_size(pos, size);
            let (fill, fg) = if is_open {
                (t.accent_soft, t.accent_ink)
            } else {
                (t.bg_sunken, t.ink_3)
            };
            ui.painter().rect_filled(badge_rect, Rounding::same(999.0), fill);
            ui.painter().galley(badge_rect.min + pad, galley, fg);
            let _ = (fill, fg);
        }

        // Handle clicks: chevron / row toggles open. Checkbox toggles selection.
        if cb_resp.clicked() {
            let new_state = !all;
            for it in g.items {
                self.selected.insert(it.id.into(), new_state);
            }
        } else if row_resp.clicked() {
            self.group_open
                .insert(g.id.into(), !is_open);
        }

        // Items
        if is_open {
            let left = row_rect.min.x + 28.0;
            // vertical guide
            for (idx, it) in items.iter().enumerate() {
                let (irow, iresp) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 22.0),
                    Sense::click(),
                );
                if iresp.hovered() {
                    ui.painter().rect_filled(
                        irow.shrink2(Vec2::new(6.0, 0.0)),
                        Rounding::same(t.r_sm),
                        t.bg_sunken,
                    );
                }
                // guide line
                ui.painter().line_segment(
                    [
                        egui::pos2(left, irow.min.y),
                        egui::pos2(left, irow.max.y),
                    ],
                    Stroke::new(1.0, t.divider),
                );
                // horizontal tick
                ui.painter().line_segment(
                    [
                        egui::pos2(left, irow.center().y),
                        egui::pos2(left + 8.0, irow.center().y),
                    ],
                    Stroke::new(1.0, t.divider),
                );

                let cb_rect = Rect::from_min_size(
                    egui::pos2(left + 12.0, irow.center().y - 7.0),
                    Vec2::splat(14.0),
                );
                let on = *self.selected.get(it.id).unwrap_or(&false);
                draw_checkbox(
                    ui,
                    t,
                    cb_rect,
                    if on { TriState::On } else { TriState::Off },
                );

                ui.painter().text(
                    egui::pos2(cb_rect.max.x + 8.0, irow.center().y),
                    egui::Align2::LEFT_CENTER,
                    it.name,
                    FontId::new(11.5, FontFamily::Monospace),
                    if on { t.ink_1 } else { t.ink_2 },
                );

                let tag_font = FontId::new(10.0, FontFamily::Monospace);
                let g_tag = ui
                    .painter()
                    .layout_no_wrap(it.tag.into(), tag_font, t.ink_4);
                let tag_pos = egui::pos2(rail_right - g_tag.size().x - 20.0, irow.center().y - g_tag.size().y / 2.0);
                ui.painter().galley(tag_pos, g_tag, t.ink_4);

                if iresp.clicked() {
                    self.selected.insert(it.id.into(), !on);
                }
                let _ = idx;
            }
        }
        ui.add_space(2.0);
    }
}

#[derive(Clone, Copy)]
enum TriState { Off, On, Mixed }

fn draw_checkbox(ui: &Ui, t: &Tokens, rect: Rect, state: TriState) {
    let painter = ui.painter();
    let (fill, stroke) = match state {
        TriState::Off => (t.surface, t.border_strong),
        TriState::On | TriState::Mixed => (t.accent, t.accent),
    };
    painter.rect(
        rect,
        Rounding::same(3.0),
        fill,
        Stroke::new(1.0, stroke),
    );
    match state {
        TriState::On => {
            // checkmark
            let c = rect.center();
            painter.add(egui::Shape::line(
                vec![
                    egui::pos2(c.x - 3.5, c.y),
                    egui::pos2(c.x - 1.0, c.y + 2.5),
                    egui::pos2(c.x + 3.5, c.y - 2.5),
                ],
                Stroke::new(1.8, Color32::WHITE),
            ));
        }
        TriState::Mixed => {
            painter.line_segment(
                [
                    egui::pos2(rect.center().x - 3.5, rect.center().y),
                    egui::pos2(rect.center().x + 3.5, rect.center().y),
                ],
                Stroke::new(1.6, Color32::WHITE),
            );
        }
        TriState::Off => {}
    }
}

// ─────────────────────────────────────────────────────────────────
// Center workspace
// ─────────────────────────────────────────────────────────────────

impl App {
    fn workspace_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        // split: scroll area + bottom action bar
        let bar_h = 56.0;
        let avail = ui.available_rect_before_wrap();
        let scroll_rect = Rect::from_min_max(
            avail.min,
            egui::pos2(avail.max.x, avail.max.y - bar_h),
        );
        let bar_rect = Rect::from_min_max(
            egui::pos2(avail.min.x, avail.max.y - bar_h),
            avail.max,
        );

        // Scroll content
        let mut sui = ui.child_ui(scroll_rect, Layout::top_down(Align::Min), None);
        sui.set_clip_rect(scroll_rect);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .show(&mut sui, |ui| {
                ui.add_space(16.0);
                // horizontal padding wrapper — gives a visible gap between rail
                // and section cards, and matches the design's `padding: 16px 18px`
                ui.horizontal(|ui| {
                    ui.add_space(18.0);
                    ui.vertical(|ui| {
                        ui.set_width(ui.available_width() - 18.0);
                        self.load_banner(ui, t);
                        if self.running {
                            self.run_banner(ui, t);
                        }
                        self.section_index(ui, t);
                        self.section_cipher(ui, t);
                        self.section_params(ui, t);
                        ui.add_space(8.0);
                    });
                });
            });

        // Bottom action bar
        let pui = ui.painter();
        // soft upward shadow (matches `box-shadow: 0 -8px 16px -12px rgba(20,18,16,0.06)`)
        for i in 0..6 {
            let alpha = (10u8).saturating_sub(i * 2);
            let y = bar_rect.min.y - (i as f32);
            pui.line_segment(
                [
                    egui::pos2(bar_rect.min.x, y),
                    egui::pos2(bar_rect.max.x, y),
                ],
                Stroke::new(1.0, Color32::from_rgba_unmultiplied(20, 18, 16, alpha)),
            );
        }
        pui.rect_filled(bar_rect, Rounding::ZERO, t.surface_2);
        pui.line_segment(
            [bar_rect.left_top(), bar_rect.right_top()],
            Stroke::new(1.0, t.border),
        );

        let mut bui = ui.child_ui(bar_rect.shrink2(Vec2::new(18.0, 12.0)), Layout::left_to_right(Align::Center), None);
        self.action_bar_ui(&mut bui, t);
    }

    fn load_banner(&mut self, ui: &mut Ui, t: &Tokens) {
        if self.active_loads.is_empty() {
            return;
        }
        let loads = self.active_loads.clone();
        let header_h = 26.0;
        let row_h = 22.0;
        let pad = 10.0;
        let total_h = header_h + row_h * loads.len() as f32 + pad * 2.0;
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), total_h),
            Sense::hover(),
        );
        let stroke = Stroke::new(1.0, blend_for_border(t));
        ui.painter()
            .rect(rect, Rounding::same(t.r_md), t.accent_soft, stroke);

        // 头部
        let total_read: u64 = loads.iter().map(|lp| lp.read).sum();
        let total_bytes: u64 = loads.iter().map(|lp| lp.total).sum();
        let header_label = format!(
            "正在加载 {} 个文件 · {} / {}  (加载完成前 '推算' 按钮已禁用)",
            loads.len(),
            humanize_bytes(total_read as usize),
            humanize_bytes(total_bytes as usize),
        );
        ui.painter().text(
            egui::pos2(rect.min.x + 14.0, rect.min.y + pad + header_h / 2.0 - 3.0),
            egui::Align2::LEFT_CENTER,
            header_label,
            FontId::new(12.0, FontFamily::Proportional),
            t.accent_ink,
        );

        // 每行: 名字 + 进度条 + 大小
        let mut y = rect.min.y + pad + header_h;
        for lp in &loads {
            let row = Rect::from_min_size(
                egui::pos2(rect.min.x + 14.0, y),
                Vec2::new(rect.width() - 28.0, row_h),
            );

            // 名字 (限定最大宽度 220)
            let name_max = 220.0;
            let name_galley = ui.painter().layout_no_wrap(
                lp.name.clone(),
                FontId::new(11.0, FontFamily::Monospace),
                t.ink_1,
            );
            let name_w = name_galley.size().x.min(name_max);
            ui.painter().galley(
                egui::pos2(row.min.x, row.center().y - name_galley.size().y / 2.0),
                name_galley,
                t.ink_1,
            );

            // 进度条
            let size_text = format!(
                "{} / {}",
                humanize_bytes(lp.read as usize),
                humanize_bytes(lp.total as usize)
            );
            let size_galley = ui.painter().layout_no_wrap(
                size_text,
                FontId::new(10.5, FontFamily::Monospace),
                t.ink_2,
            );
            let size_w = size_galley.size().x;
            let bar_h = 6.0;
            let bar_left = row.min.x + name_w + 12.0;
            let bar_right = row.max.x - size_w - 8.0;
            if bar_right > bar_left + 20.0 {
                let bar_rect = Rect::from_min_size(
                    egui::pos2(bar_left, row.center().y - bar_h / 2.0),
                    Vec2::new(bar_right - bar_left, bar_h),
                );
                ui.painter()
                    .rect_filled(bar_rect, Rounding::same(3.0), t.surface);
                let pct = if lp.total > 0 {
                    (lp.read as f32 / lp.total as f32).clamp(0.0, 1.0)
                } else {
                    0.0
                };
                let fill_w = bar_rect.width() * pct;
                if fill_w > 0.5 {
                    let fill_rect = Rect::from_min_size(
                        bar_rect.min,
                        Vec2::new(fill_w, bar_h),
                    );
                    ui.painter()
                        .rect_filled(fill_rect, Rounding::same(3.0), t.accent);
                }
            }

            // 大小文字 (右侧)
            ui.painter().galley(
                egui::pos2(row.max.x - size_w, row.center().y - size_galley.size().y / 2.0),
                size_galley,
                t.ink_2,
            );

            y += row_h;
        }
        ui.add_space(12.0);
    }

    fn run_banner(&mut self, ui: &mut Ui, t: &Tokens) {
        let h = 38.0;
        let (rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), h),
            Sense::hover(),
        );
        let stroke = Stroke::new(1.0, blend_for_border(t));
        ui.painter().rect(
            rect,
            Rounding::same(t.r_md),
            t.accent_soft,
            stroke,
        );
        // spinner: rotating segment
        let time = ui.input(|i| i.time);
        let angle = (time * 4.0) as f32;
        let sc = egui::pos2(rect.min.x + 16.0, rect.center().y);
        ui.painter().circle_stroke(sc, 7.0, Stroke::new(2.0, blend_for_border(t)));
        let p0 = sc + Vec2::angled(angle) * 7.0;
        let p1 = sc + Vec2::angled(angle + 1.2) * 7.0;
        ui.painter().line_segment([p0, p1], Stroke::new(2.0, t.accent));

        let sel = self.selected_count();
        ui.painter().text(
            egui::pos2(rect.min.x + 32.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            format!("正在推算 · {sel} 种算法"),
            FontId::new(12.5, FontFamily::Proportional),
            t.accent_ink,
        );

        let n = self.threads.trim().parse::<usize>().unwrap_or_else(|_| default_thread_count());
        let detail = format!(
            "{:.0}%  ·  {} 线程  ·  已用 {}",
            self.progress,
            n,
            human_elapsed(self.run_started),
        );
        ui.painter().text(
            egui::pos2(rect.min.x + 200.0, rect.center().y),
            egui::Align2::LEFT_CENTER,
            detail,
            FontId::new(11.0, FontFamily::Monospace),
            t.ink_3,
        );

        // stop button on right
        let btn_w = 60.0;
        let btn_h = 26.0;
        let btn_rect = Rect::from_min_size(
            egui::pos2(rect.max.x - btn_w - 10.0, rect.center().y - btn_h / 2.0),
            Vec2::new(btn_w, btn_h),
        );
        let resp = ui.interact(btn_rect, ui.id().with("stop_btn"), Sense::click());
        let bg = if resp.hovered() { t.bg_sunken } else { t.surface };
        ui.painter().rect(
            btn_rect,
            Rounding::same(t.r_sm),
            bg,
            Stroke::new(1.0, t.border),
        );
        ui.painter().text(
            btn_rect.center(),
            egui::Align2::CENTER_CENTER,
            "■ 停止",
            FontId::new(11.5, FontFamily::Proportional),
            t.ink_1,
        );
        if resp.clicked() {
            self.stop_run();
        }

        ui.add_space(12.0);
    }

    fn section_index(&mut self, ui: &mut Ui, t: &Tokens) {
        section_card(ui, t, "01", "索引文件", Some("拖放 .dmp / .bin / .so 至下方,或使用按钮添加"), |ui| {
            field(ui, t, "文件列表", |ui| {
                let avail_w = ui.available_width();
                ui.vertical(|ui| {
                    ui.set_width(avail_w - 90.0);
                    self.draw_file_list(ui, t);
                });
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    if mini_btn(ui, t, "＋", false).clicked() {
                        self.pick_dump_files();
                    }
                    if mini_btn(ui, t, "🗑", true).clicked() {
                        self.files.clear();
                    }
                    mini_btn(ui, t, "↑", false);
                    mini_btn(ui, t, "↓", false);
                });
            });

            // toggle grid 2x2
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let half = (ui.available_width() - 20.0) / 2.0;
                ui.vertical(|ui| {
                    ui.set_width(half);
                    toggle_row(ui, t, &mut self.deep_search, "深度搜索 (+)").on_hover_text(
                        "扫描步长从 key 长度的一半改为 1 字节, 检查 dump 里每一个起始位置。\n\
                         • 关闭(默认): step=8 或更大, 命中 8/16 字节对齐放置的 key (绝大多数堆/栈 key 都对齐)\n\
                         • 打开: step=1, 命中任意未对齐位置的 key, 但速度变慢 ~8 倍\n\n\
                         建议先关闭跑一遍, 找不到再开。",
                    );
                    toggle_row(ui, t, &mut self.dedup, "剔除重复").on_hover_text(
                        "对扫描出的候选 key 用 64-bit 内容哈希去重, 避免同一段内存里重复的字串各算一遍。\n\
                         默认开启, 通常没必要关。",
                    );
                });
                ui.add_space(20.0);
                ui.vertical(|ui| {
                    ui.set_width(half);
                    toggle_row(ui, t, &mut self.ascii_only, "限定 ASCII (−)").on_hover_text(
                        "只用 ASCII 可打印字串作为候选 key (类似 strings 命令)。\n\
                         • 打开: 大幅减少候选量, 速度更快, 但漏掉二进制 key (如 SecureRandom 生成的)\n\
                         • 关闭(默认): 接受任意字节, 包含二进制 key",
                    );
                    toggle_row(ui, t, &mut self.key_encode, "编码 KEY (+)").on_hover_text(
                        "为候选 key 额外尝试常见编码变体 (Base64 / Hex 解码后的字节)。\n\
                         开启会增加候选数量但能覆盖那些以编码字符串形式存在内存里的 key。",
                    );
                });
            });

            field(ui, t, "候选长度", |ui| {
                ui.add(
                    TextEdit::singleline(&mut self.key_lens)
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .margin(egui::Margin::symmetric(10.0, 8.0))
                        .desired_width(ui.available_width() - 110.0),
                );
                ui.add_space(8.0);
                ui.label(RichText::new("逗号分隔").size(11.0).color(t.ink_3));
            });
        });
    }

    fn draw_file_list(&mut self, ui: &mut Ui, t: &Tokens) {
        if self.files.is_empty() {
            let (rect, _) = ui.allocate_exact_size(
                Vec2::new(ui.available_width(), 72.0),
                Sense::hover(),
            );
            ui.painter().rect(
                rect,
                Rounding::same(t.r_md),
                t.bg_sunken,
                Stroke {
                    width: 1.0,
                    color: t.border_strong,
                },
            );
            ui.painter().text(
                egui::pos2(rect.center().x, rect.center().y - 8.0),
                egui::Align2::CENTER_CENTER,
                "可以拖放多个文件到列表",
                FontId::new(12.0, FontFamily::Proportional),
                t.ink_3,
            );
            ui.painter().text(
                egui::pos2(rect.center().x, rect.center().y + 10.0),
                egui::Align2::CENTER_CENTER,
                ".dmp · .bin · .so · .dll · .dat",
                FontId::new(11.0, FontFamily::Monospace),
                t.ink_4,
            );
            return;
        }

        let mut remove: Option<usize> = None;
        // 只克隆显示用的元数据 (String 是堆字符串, clone 廉价; weight 是 u8)。
        // 关键: 不要 self.files.clone(), 因为 DumpFile.bytes 可能是几 GB
        let meta: Vec<(String, String, u8)> = self
            .files
            .iter()
            .map(|f| (f.name.clone(), f.size.clone(), f.weight))
            .collect();
        let mut idx = 0;
        ui.vertical(|ui| {
            // outer dashed container
            let (rect, _) = ui.allocate_exact_size(
                Vec2::new(ui.available_width(), meta.len() as f32 * 28.0 + 8.0),
                Sense::hover(),
            );
            ui.painter().rect(
                rect,
                Rounding::same(t.r_md),
                t.bg_sunken,
                Stroke {
                    width: 1.0,
                    color: t.border_strong,
                },
            );
            let inner = rect.shrink(4.0);
            let mut y = inner.min.y;
            for (name, size, weight) in &meta {
                let row = Rect::from_min_size(
                    egui::pos2(inner.min.x, y),
                    Vec2::new(inner.width(), 26.0),
                );
                ui.painter().rect(
                    row,
                    Rounding::same(t.r_sm),
                    t.surface,
                    Stroke::new(1.0, t.border),
                );
                ui.painter().text(
                    egui::pos2(row.min.x + 10.0, row.center().y),
                    egui::Align2::LEFT_CENTER,
                    format!("📄 {}", name),
                    FontId::new(11.5, FontFamily::Monospace),
                    t.ink_1,
                );
                ui.painter().text(
                    egui::pos2(row.max.x - 80.0, row.center().y),
                    egui::Align2::RIGHT_CENTER,
                    size,
                    FontId::new(10.5, FontFamily::Monospace),
                    t.ink_3,
                );
                ui.painter().text(
                    egui::pos2(row.max.x - 24.0, row.center().y),
                    egui::Align2::RIGHT_CENTER,
                    format!("权重 {}", weight),
                    FontId::new(10.5, FontFamily::Monospace),
                    t.ink_3,
                );
                let x_rect = Rect::from_min_size(
                    egui::pos2(row.max.x - 18.0, row.center().y - 8.0),
                    Vec2::splat(16.0),
                );
                let xresp = ui.interact(x_rect, ui.id().with(("x", idx)), Sense::click());
                let xcolor = if xresp.hovered() { t.err } else { t.ink_3 };
                ui.painter().line_segment(
                    [
                        x_rect.min + Vec2::splat(3.5),
                        x_rect.max - Vec2::splat(3.5),
                    ],
                    Stroke::new(1.2, xcolor),
                );
                ui.painter().line_segment(
                    [
                        egui::pos2(x_rect.max.x - 3.5, x_rect.min.y + 3.5),
                        egui::pos2(x_rect.min.x + 3.5, x_rect.max.y - 3.5),
                    ],
                    Stroke::new(1.2, xcolor),
                );
                if xresp.clicked() {
                    remove = Some(idx);
                }
                idx += 1;
                y += 28.0;
            }
        });
        if let Some(i) = remove {
            self.files.remove(i);
        }
    }

    fn section_cipher(&mut self, ui: &mut Ui, t: &Tokens) {
        section_card(ui, t, "02", "密文", Some("待破译的目标密文(HEX / Base64 自动识别)"), |ui| {
            // textarea
            ui.scope(|ui| {
                ui.style_mut().visuals.extreme_bg_color = t.bg_sunken;
                ui.add(
                    TextEdit::multiline(&mut self.ciphertext)
                        .desired_rows(6)
                        .desired_width(f32::INFINITY)
                        .font(FontId::new(11.5, FontFamily::Monospace)),
                );
            });
            ui.horizontal(|ui| {
                let cleaned: String = self.ciphertext.chars().filter(|c| !c.is_whitespace()).collect();
                let len = cleaned.len();
                let bytes = len / 2;
                ui.label(RichText::new("编码: HEX").family(FontFamily::Monospace).size(11.0).color(t.ink_3));
                ui.add_space(10.0);
                ui.label(RichText::new(format!("长度: {} chars", len)).family(FontFamily::Monospace).size(11.0).color(t.ink_3));
                ui.add_space(10.0);
                ui.label(RichText::new(format!("字节: {} B", bytes)).family(FontFamily::Monospace).size(11.0).color(t.ink_3));
                ui.add_space(10.0);
                ui.label(RichText::new("● 格式有效").family(FontFamily::Monospace).size(11.0).color(t.ok));
            });
        });
    }

    fn section_params(&mut self, ui: &mut Ui, t: &Tokens) {
        section_card(ui, t, "03", "推算参数", Some("KEY 长度策略、原文约束、并发"), |ui| {
            field(ui, t, "KEY 长度", |ui| {
                len_pill(ui, t, "不限长度", &mut self.len_mode, LenMode::Any);
                ui.add_space(6.0);
                len_pill(ui, t, "算法常用长度", &mut self.len_mode, LenMode::Common);
                ui.add_space(6.0);
                len_pill(ui, t, "指定长度", &mut self.len_mode, LenMode::Custom);
                ui.add_space(6.0);
                let enabled = self.len_mode == LenMode::Custom;
                ui.add_enabled_ui(enabled, |ui| {
                    let (rect, _) = ui.allocate_exact_size(Vec2::new(110.0, 28.0), Sense::hover());
                    ui.painter().rect(rect, Rounding::same(t.r_md), t.surface, Stroke::new(1.0, t.border));
                    let mut child = ui.child_ui(rect.shrink2(Vec2::new(0.0, 2.0)), Layout::left_to_right(Align::Center), None);
                    child.style_mut().visuals.extreme_bg_color = t.surface;
                    child.add(TextEdit::singleline(&mut self.len_min).font(FontId::new(11.5, FontFamily::Monospace)).frame(false).horizontal_align(Align::Center).margin(egui::Margin::symmetric(4.0, 5.0)).desired_width(44.0));
                    child.label(RichText::new("—").color(t.ink_4).size(11.5));
                    child.add(TextEdit::singleline(&mut self.len_max).font(FontId::new(11.5, FontFamily::Monospace)).frame(false).horizontal_align(Align::Center).margin(egui::Margin::symmetric(4.0, 5.0)).desired_width(44.0));
                });
            });
            field(ui, t, "已知明文", |ui| {
                ui.add(
                    TextEdit::singleline(&mut self.known_plaintext)
                        .hint_text("哈希反查 / HMAC message: hash(此值) ?= 密文")
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .margin(egui::Margin::symmetric(10.0, 8.0))
                        .desired_width(ui.available_width() - 10.0),
                );
            });
            field(ui, t, "原文包含", |ui| {
                ui.add(
                    TextEdit::singleline(&mut self.plain_contains)
                        .hint_text("解密结果中应出现的子串 (e.g. token=) · 用作命中过滤器")
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .margin(egui::Margin::symmetric(10.0, 8.0))
                        .desired_width(ui.available_width() - 10.0),
                );
            });
            field(ui, t, "并发", |ui| {
                ui.label(RichText::new("线程数").size(11.0).color(t.ink_3));
                ui.add(
                    TextEdit::singleline(&mut self.threads)
                        .font(FontId::new(11.5, FontFamily::Monospace))
                        .horizontal_align(Align::Center)
                        .margin(egui::Margin::symmetric(10.0, 8.0))
                        .desired_width(64.0),
                );
                ui.add_space(10.0);
                toggle_row(ui, t, &mut self.try_hard, "同时尝试硬解 (CPU+GPU)");
                ui.add_space(10.0);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let sel = self.selected_count();
                    ui.label(RichText::new(format!("· 预估 ~38s")).color(t.ink_3).size(11.0));
                    ui.label(RichText::new(format!("已选 {} 种算法 ", sel)).color(t.ink_3).size(11.0));
                });
            });
        });
    }

    fn action_bar_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        ghost_button(ui, t, "⚙ 高级");
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            let loading = !self.active_loads.is_empty();
            let disabled = self.running || loading;
            let _chev = primary_chevron(ui, t, disabled);
            let label = if self.running {
                "▮▮ 推算中…"
            } else if loading {
                "⌛ 等待加载…"
            } else {
                "▶ 推算计算"
            };
            let resp = primary_button_split(ui, t, label, disabled);
            if resp.clicked() && !disabled {
                self.start_run();
            }
            ui.add_space(10.0);
            kbd_cap(ui, t, "⌘");
            ui.add_space(2.0);
            ui.label(RichText::new("+").color(t.ink_4).size(11.0));
            ui.add_space(2.0);
            kbd_cap(ui, t, "Enter");
            ui.add_space(4.0);
            ui.label(RichText::new("开始推算").color(t.ink_3).size(11.0));
        });
    }
}

fn human_elapsed(start: Option<Instant>) -> String {
    match start {
        Some(s) => {
            let e = s.elapsed().as_secs();
            format!("{}:{:02}", e / 60, e % 60)
        }
        None => "0:00".into(),
    }
}

fn blend_for_border(t: &Tokens) -> Color32 {
    // approximate color-mix(in oklch, accent 25%, transparent) — desaturate accent into surface
    Color32::from_rgba_unmultiplied(t.accent.r(), t.accent.g(), t.accent.b(), 110)
}

fn section_card(
    ui: &mut Ui,
    t: &Tokens,
    ix: &str,
    title: &str,
    sub: Option<&str>,
    body: impl FnOnce(&mut Ui),
) {
    egui::Frame {
        fill: t.surface,
        stroke: Stroke::new(1.0, t.border),
        rounding: Rounding::same(t.r_lg),
        inner_margin: Margin::ZERO,
        outer_margin: Margin {
            left: 0.0,
            right: 0.0,
            top: 0.0,
            bottom: 14.0,
        },
        shadow: egui::epaint::Shadow::NONE,
    }
    .show(ui, |ui| {
        // Header
        let hd_h = 38.0;
        let (hd_rect, _) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), hd_h),
            Sense::hover(),
        );
        ui.painter().rect_filled(hd_rect, Rounding {
            nw: t.r_lg, ne: t.r_lg, sw: 0.0, se: 0.0,
        }, t.surface_2);
        ui.painter().line_segment(
            [hd_rect.left_bottom(), hd_rect.right_bottom()],
            Stroke::new(1.0, t.divider),
        );

        // ix badge
        let ix_rect = Rect::from_min_size(
            egui::pos2(hd_rect.min.x + 14.0, hd_rect.center().y - 9.0),
            Vec2::splat(18.0),
        );
        ui.painter().rect(
            ix_rect,
            Rounding::same(t.r_sm),
            t.bg_sunken,
            Stroke::NONE,
        );
        ui.painter().text(
            ix_rect.center(),
            egui::Align2::CENTER_CENTER,
            ix,
            FontId::new(10.0, FontFamily::Monospace),
            t.ink_3,
        );

        ui.painter().text(
            egui::pos2(ix_rect.max.x + 8.0, hd_rect.center().y),
            egui::Align2::LEFT_CENTER,
            title,
            FontId::new(12.5, FontFamily::Proportional),
            t.ink_1,
        );

        if let Some(sub) = sub {
            let title_w = ui.painter().layout_no_wrap(
                title.into(),
                FontId::new(12.5, FontFamily::Proportional),
                t.ink_1,
            ).size().x;
            ui.painter().text(
                egui::pos2(ix_rect.max.x + 8.0 + title_w + 6.0, hd_rect.center().y),
                egui::Align2::LEFT_CENTER,
                format!("· {sub}"),
                FontId::new(11.5, FontFamily::Proportional),
                t.ink_3,
            );
        }

        // body
        ui.add_space(0.0);
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), 0.0),
            Layout::top_down(Align::Min),
            |ui| {
                ui.add_space(8.0);
                ui.scope(|ui| {
                    let inner = ui.available_rect_before_wrap();
                    let mut iu = ui.child_ui(
                        Rect::from_min_max(
                            egui::pos2(inner.min.x + 14.0, inner.min.y),
                            egui::pos2(inner.max.x - 14.0, inner.max.y),
                        ),
                        Layout::top_down(Align::Min),
                        None,
                    );
                    body(&mut iu);
                    let used = iu.min_rect().height();
                    ui.add_space(used + 12.0);
                });
            },
        );
    });
}

fn field(ui: &mut Ui, t: &Tokens, label: &str, content: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        let (lrect, _) = ui.allocate_exact_size(Vec2::new(76.0, t.row), Sense::hover());
        ui.painter().text(
            egui::pos2(lrect.max.x - 4.0, lrect.center().y),
            egui::Align2::RIGHT_CENTER,
            label,
            FontId::new(12.0, FontFamily::Proportional),
            t.ink_2,
        );
        ui.add_space(8.0);
        ui.allocate_ui_with_layout(
            Vec2::new(ui.available_width(), t.row),
            Layout::left_to_right(Align::Center),
            |ui| {
                content(ui);
            },
        );
    });
    ui.add_space(4.0);
}

fn primary_button(ui: &mut Ui, t: &Tokens, label: &str, disabled: bool) -> Response {
    let font = FontId::new(12.5, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.into(), font, Color32::WHITE);
    let h = t.row;
    let w = galley.size().x + 24.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let bg = if disabled {
        blend_for_border(t)
    } else if resp.hovered() {
        darken(t.accent, 0.08)
    } else {
        t.accent
    };
    ui.painter().rect(
        rect,
        Rounding::same(t.r_md),
        bg,
        Stroke::new(1.0, bg),
    );
    let pos = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, Color32::WHITE);
    resp
}

fn primary_button_split(ui: &mut Ui, t: &Tokens, label: &str, disabled: bool) -> Response {
    let font = FontId::new(12.5, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.into(), font, Color32::WHITE);
    let h = t.row;
    let w = galley.size().x + 24.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let bg = if disabled {
        blend_for_border(t)
    } else if resp.hovered() {
        darken(t.accent, 0.08)
    } else {
        t.accent
    };
    ui.painter().rect(
        rect,
        Rounding {
            nw: t.r_md,
            ne: 0.0,
            sw: t.r_md,
            se: 0.0,
        },
        bg,
        Stroke::new(1.0, bg),
    );
    let pos = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, Color32::WHITE);
    resp
}

fn primary_chevron(ui: &mut Ui, t: &Tokens, disabled: bool) -> Response {
    let h = t.row;
    let w = 26.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
    let bg = if disabled {
        blend_for_border(t)
    } else if resp.hovered() {
        darken(t.accent, 0.08)
    } else {
        t.accent
    };
    ui.painter().rect(
        rect,
        Rounding {
            nw: 0.0,
            ne: t.r_md,
            sw: 0.0,
            se: t.r_md,
        },
        bg,
        Stroke::new(1.0, bg),
    );
    // 1px divider between primary and chevron
    ui.painter().line_segment(
        [
            egui::pos2(rect.min.x, rect.min.y + 6.0),
            egui::pos2(rect.min.x, rect.max.y - 6.0),
        ],
        Stroke::new(1.0, Color32::from_rgba_unmultiplied(255, 255, 255, 64)),
    );
    // chevron
    let c = rect.center();
    ui.painter().add(egui::Shape::convex_polygon(
        vec![
            egui::pos2(c.x - 4.0, c.y - 2.0),
            egui::pos2(c.x + 4.0, c.y - 2.0),
            egui::pos2(c.x, c.y + 3.0),
        ],
        Color32::WHITE,
        Stroke::NONE,
    ));
    resp
}

fn kbd_cap(ui: &mut Ui, t: &Tokens, text: &str) -> Response {
    let font = FontId::new(10.5, FontFamily::Monospace);
    let galley = ui.painter().layout_no_wrap(text.into(), font, t.ink_3);
    let pad = Vec2::new(5.0, 1.0);
    let size = galley.size() + pad * 2.0;
    let (rect, resp) = ui.allocate_exact_size(size, Sense::hover());
    ui.painter().rect(
        rect,
        Rounding::same(3.0),
        t.bg_sunken,
        Stroke::new(1.0, t.border),
    );
    ui.painter().galley(rect.min + pad, galley, t.ink_3);
    resp
}

fn ghost_button(ui: &mut Ui, t: &Tokens, label: &str) -> Response {
    let font = FontId::new(12.5, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.into(), font, t.ink_2);
    let w = galley.size().x + 24.0;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, t.row), Sense::click());
    if resp.hovered() {
        ui.painter().rect_filled(rect, Rounding::same(t.r_md), t.bg_sunken);
    }
    let pos = egui::pos2(rect.center().x - galley.size().x / 2.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, t.ink_2);
    resp
}

fn mini_btn(ui: &mut Ui, t: &Tokens, label: &str, danger: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(26.0, 26.0), Sense::click());
    let bg = if resp.hovered() {
        if danger { t.err_soft } else { t.bg_sunken }
    } else {
        t.surface
    };
    let stroke = Stroke::new(
        1.0,
        if resp.hovered() && danger { t.err } else { t.border },
    );
    ui.painter().rect(rect, Rounding::same(t.r_sm), bg, stroke);
    let color = if resp.hovered() && danger { t.err } else { t.ink_2 };
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        FontId::new(13.0, FontFamily::Proportional),
        color,
    );
    resp
}

fn darken(c: Color32, amount: f32) -> Color32 {
    let a = (1.0 - amount).clamp(0.0, 1.0);
    Color32::from_rgb(
        ((c.r() as f32) * a) as u8,
        ((c.g() as f32) * a) as u8,
        ((c.b() as f32) * a) as u8,
    )
}

fn toggle_row(ui: &mut Ui, t: &Tokens, on: &mut bool, label: &str) -> Response {
    let font = FontId::new(12.0, FontFamily::Proportional);
    let galley = ui.painter().layout_no_wrap(label.into(), font, t.ink_2);
    let w = 28.0 + 8.0 + galley.size().x;
    let (rect, resp) = ui.allocate_exact_size(Vec2::new(w, 22.0), Sense::click());
    // toggle background
    let tg_rect = Rect::from_min_size(
        egui::pos2(rect.min.x, rect.center().y - 8.0),
        Vec2::new(28.0, 16.0),
    );
    let bg = if *on { t.accent } else { t.border_strong };
    ui.painter().rect_filled(tg_rect, Rounding::same(999.0), bg);
    // thumb
    let thumb_x = if *on { tg_rect.max.x - 8.0 } else { tg_rect.min.x + 8.0 };
    ui.painter().circle_filled(
        egui::pos2(thumb_x, tg_rect.center().y),
        6.0,
        Color32::WHITE,
    );
    let pos = egui::pos2(rect.min.x + 28.0 + 8.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, t.ink_2);
    if resp.clicked() {
        *on = !*on;
    }
    ui.add_space(2.0);
    resp
}

fn len_pill(ui: &mut Ui, t: &Tokens, label: &str, binding: &mut LenMode, value: LenMode) {
    let on = *binding == value;
    let font = FontId::new(11.5, FontFamily::Monospace);
    let color = if on { t.accent_ink } else { t.ink_2 };
    let galley = ui.painter().layout_no_wrap(label.into(), font, color);
    let pad = Vec2::new(10.0, 4.0);
    let size = Vec2::new(galley.size().x + 14.0 + pad.x * 2.0, galley.size().y + pad.y * 2.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let (fill, stroke) = if on {
        (t.accent_soft, blend_for_border(t))
    } else {
        (t.surface, t.border)
    };
    ui.painter().rect(rect, Rounding::same(999.0), fill, Stroke::new(1.0, stroke));
    // check icon if on
    if on {
        let c = egui::pos2(rect.min.x + pad.x + 4.0, rect.center().y);
        ui.painter().add(egui::Shape::line(
            vec![
                egui::pos2(c.x - 3.0, c.y),
                egui::pos2(c.x - 1.0, c.y + 2.5),
                egui::pos2(c.x + 3.5, c.y - 2.5),
            ],
            Stroke::new(1.6, t.accent),
        ));
    }
    let pos = egui::pos2(rect.min.x + pad.x + 14.0, rect.center().y - galley.size().y / 2.0);
    ui.painter().galley(pos, galley, color);
    if resp.clicked() {
        *binding = value;
    }
}

// ─────────────────────────────────────────────────────────────────
// Right pane: log/results/history/rules
// ─────────────────────────────────────────────────────────────────

impl App {
    fn right_pane_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        // left border
        let rect = ui.max_rect();
        ui.painter().line_segment(
            [rect.left_top(), rect.left_bottom()],
            Stroke::new(1.0, t.border),
        );

        // tabs
        let tabs_h = 38.0;
        let (tabs_rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), tabs_h), Sense::hover());
        ui.painter().rect_filled(tabs_rect, Rounding::ZERO, t.surface_2);
        ui.painter().line_segment(
            [tabs_rect.left_bottom(), tabs_rect.right_bottom()],
            Stroke::new(1.0, t.divider),
        );

        let mut x = tabs_rect.min.x + 4.0;
        let hits = self.results.iter().filter(|r| r.hit).count();
        let tabs: [(RightTab, &str, Option<String>); 4] = [
            (RightTab::Log, "日志", Some(self.log.len().to_string())),
            (
                RightTab::Results,
                "结果",
                if hits > 0 { Some(hits.to_string()) } else { None },
            ),
            (RightTab::History, "历史", None),
            (RightTab::Rules, "匹配规则", None),
        ];
        for (tab, label, badge) in tabs.iter() {
            let font = FontId::new(12.0, FontFamily::Proportional);
            let g = ui.painter().layout_no_wrap(
                (*label).into(),
                font.clone(),
                t.ink_3,
            );
            let badge_w = if badge.is_some() { 28.0 } else { 0.0 };
            let w = g.size().x + 24.0 + badge_w;
            let r = Rect::from_min_size(
                egui::pos2(x, tabs_rect.min.y),
                Vec2::new(w, tabs_h),
            );
            let resp = ui.interact(r, ui.id().with(label), Sense::click());
            let on = self.tab == *tab;
            let color = if on { t.ink_1 } else if resp.hovered() { t.ink_1 } else { t.ink_3 };
            let label_font = FontId::new(12.0, if on { FontFamily::Proportional } else { FontFamily::Proportional });
            ui.painter().text(
                egui::pos2(r.min.x + 12.0, r.center().y),
                egui::Align2::LEFT_CENTER,
                *label,
                label_font,
                color,
            );
            if let Some(bd) = badge {
                let bd_font = FontId::new(10.0, FontFamily::Monospace);
                let bdg = ui.painter().layout_no_wrap(bd.clone(), bd_font, t.ink_3);
                let pad = Vec2::new(5.0, 1.0);
                let bsize = bdg.size() + pad * 2.0;
                let bx = r.min.x + 12.0 + g.size().x + 6.0;
                let brect = Rect::from_min_size(
                    egui::pos2(bx, r.center().y - bsize.y / 2.0),
                    Vec2::new(bsize.x.max(18.0), bsize.y),
                );
                let (bf, bg_color) = if on { (t.accent_soft, t.accent_ink) } else { (t.bg_sunken, t.ink_3) };
                ui.painter().rect_filled(brect, Rounding::same(999.0), bf);
                ui.painter().galley(
                    egui::pos2(brect.center().x - bdg.size().x / 2.0, brect.min.y + pad.y),
                    bdg,
                    bg_color,
                );
            }
            if on {
                ui.painter().line_segment(
                    [r.left_bottom() + Vec2::new(10.0, -1.0), r.right_bottom() + Vec2::new(-10.0, -1.0)],
                    Stroke::new(2.0, t.accent),
                );
            }
            if resp.clicked() {
                self.tab = *tab;
            }
            x = r.max.x;
        }

        match self.tab {
            RightTab::Log => self.tab_log(ui, t),
            RightTab::Results => self.tab_results(ui, t),
            RightTab::History => self.tab_history(ui, t),
            RightTab::Rules => self.tab_rules(ui, t),
        }
    }

    fn tab_log(&mut self, ui: &mut Ui, t: &Tokens) {
        // filter chips row
        let tools_h = 34.0;
        let (tools_rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), tools_h), Sense::hover());
        ui.painter().line_segment(
            [tools_rect.left_bottom(), tools_rect.right_bottom()],
            Stroke::new(1.0, t.divider),
        );
        let mut x = tools_rect.min.x + 10.0;
        for k in [LogLvl::Info, LogLvl::Ok, LogLvl::Warn, LogLvl::Err] {
            let on = *self.log_filters.get(&k).unwrap_or(&true);
            let label = k.label();
            let font = FontId::new(10.5, FontFamily::Monospace);
            let color = if on { t.accent_ink } else { t.ink_3 };
            let g = ui.painter().layout_no_wrap(label.into(), font, color);
            let pad = Vec2::new(8.0, 2.0);
            let size = g.size() + pad * 2.0;
            let rect = Rect::from_min_size(
                egui::pos2(x, tools_rect.center().y - size.y / 2.0),
                size,
            );
            let resp = ui.interact(rect, ui.id().with(("flt", label)), Sense::click());
            let (fill, stroke) = if on {
                (t.accent_soft, blend_for_border(t))
            } else {
                (t.surface, t.border)
            };
            ui.painter().rect(rect, Rounding::same(999.0), fill, Stroke::new(1.0, stroke));
            ui.painter().galley(rect.min + pad, g, color);
            if resp.clicked() {
                self.log_filters.insert(k, !on);
            }
            x += size.x + 6.0;
        }
        // right: auto scroll + clear
        let mut x = tools_rect.max.x - 10.0;
        // clear
        let clear_w = 26.0;
        let clear_rect = Rect::from_min_size(
            egui::pos2(x - clear_w, tools_rect.center().y - 13.0),
            Vec2::new(clear_w, 26.0),
        );
        let cresp = ui.interact(clear_rect, ui.id().with("clear_log"), Sense::click());
        let bg = if cresp.hovered() { t.bg_sunken } else { Color32::TRANSPARENT };
        ui.painter().rect_filled(clear_rect, Rounding::same(t.r_sm), bg);
        ui.painter().text(
            clear_rect.center(),
            egui::Align2::CENTER_CENTER,
            "🗑",
            FontId::new(12.0, FontFamily::Proportional),
            t.ink_3,
        );
        if cresp.clicked() {
            self.log.clear();
        }
        x -= clear_w + 8.0;
        // auto scroll toggle (text only)
        let label = "自动滚动";
        let font = FontId::new(11.0, FontFamily::Proportional);
        let g = ui.painter().layout_no_wrap(label.into(), font, t.ink_2);
        let w = g.size().x + 38.0;
        let tr = Rect::from_min_size(
            egui::pos2(x - w, tools_rect.center().y - 11.0),
            Vec2::new(w, 22.0),
        );
        let tresp = ui.interact(tr, ui.id().with("auto_scroll"), Sense::click());
        let tg_rect = Rect::from_min_size(
            egui::pos2(tr.min.x, tr.center().y - 8.0),
            Vec2::new(28.0, 16.0),
        );
        ui.painter().rect_filled(
            tg_rect,
            Rounding::same(999.0),
            if self.auto_scroll { t.accent } else { t.border_strong },
        );
        let thumb_x = if self.auto_scroll {
            tg_rect.max.x - 8.0
        } else {
            tg_rect.min.x + 8.0
        };
        ui.painter()
            .circle_filled(egui::pos2(thumb_x, tg_rect.center().y), 6.0, Color32::WHITE);
        ui.painter().galley(
            egui::pos2(tg_rect.max.x + 8.0, tr.center().y - g.size().y / 2.0),
            g,
            t.ink_2,
        );
        if tresp.clicked() {
            self.auto_scroll = !self.auto_scroll;
        }

        // log lines
        let body_rect = Rect::from_min_max(
            egui::pos2(ui.max_rect().min.x, tools_rect.max.y),
            ui.max_rect().max,
        );
        let mut bui = ui.child_ui(body_rect, Layout::top_down(Align::Min), None);
        bui.set_clip_rect(body_rect);
        let filters = self.log_filters.clone();
        let lines: Vec<_> = self
            .log
            .iter()
            .filter(|l| *filters.get(&l.lvl).unwrap_or(&true))
            .cloned()
            .collect();
        let line_count = lines.len();
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
            .stick_to_bottom(self.auto_scroll)
            .show(&mut bui, |ui| {
                ui.add_space(8.0);
                for (idx, l) in lines.iter().enumerate() {
                    log_line(ui, t, l, idx == line_count - 1);
                }
                if self.running {
                    log_pending(ui, t);
                }
                ui.add_space(60.0);
            });
    }

    fn tab_results(&mut self, ui: &mut Ui, t: &Tokens) {
        // stats row
        let h = 50.0;
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h), Sense::hover());
        ui.painter().rect_filled(rect, Rounding::ZERO, t.surface_2);
        ui.painter().line_segment(
            [rect.left_bottom(), rect.right_bottom()],
            Stroke::new(1.0, t.divider),
        );
        let hits = self.results.iter().filter(|r| r.hit).count();
        let pct = if !self.results.is_empty() {
            (hits as f32 / self.results.len() as f32 * 100.0) as u32
        } else {
            0
        };
        let items = [
            (hits.to_string(), "命中", true),
            (self.results.len().to_string(), "候选", false),
            (format!("{}%", pct), "命中率", false),
            (
                if self.running { "运行中".to_string() } else { "已停止".to_string() },
                "状态",
                false,
            ),
        ];
        let mut x = rect.min.x + 14.0;
        for (num, label, accent) in items {
            let nf = FontId::new(13.0, FontFamily::Monospace);
            let nc = if accent { t.accent_ink } else { t.ink_1 };
            ui.painter().text(
                egui::pos2(x, rect.center().y - 6.0),
                egui::Align2::LEFT_CENTER,
                &num,
                nf,
                nc,
            );
            ui.painter().text(
                egui::pos2(x, rect.center().y + 10.0),
                egui::Align2::LEFT_CENTER,
                label,
                FontId::new(11.0, FontFamily::Proportional),
                t.ink_3,
            );
            x += 70.0;
        }

        let body_rect = Rect::from_min_max(
            egui::pos2(ui.max_rect().min.x, rect.max.y),
            ui.max_rect().max,
        );
        let mut bui = ui.child_ui(body_rect, Layout::top_down(Align::Min), None);
        bui.set_clip_rect(body_rect);
        // 渲染顺序：固定卡置顶，其余按命中先后
        let mut order: Vec<usize> = (0..self.results.len()).collect();
        order.sort_by_key(|&i| if self.results[i].pinned { 0 } else { 1 });
        let results = self.results.clone();
        let running = self.running;
        let mut pending: Vec<(usize, CardAction)> = Vec::new();
        ScrollArea::vertical().auto_shrink([false, false]).scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden).show(&mut bui, |ui| {
            ui.add_space(10.0);
            if results.is_empty() {
                ui.add_space(40.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("🔑").size(24.0).color(t.ink_4));
                    ui.add_space(8.0);
                    ui.label(RichText::new("尚无结果").color(t.ink_3));
                    ui.label(
                        RichText::new(if running { "推算中…" } else { "点击「推算计算」开始" })
                            .color(t.ink_4)
                            .size(11.0),
                    );
                });
                return;
            }
            for &i in &order {
                if let Some(act) = result_card(ui, t, &results[i]) {
                    pending.push((i, act));
                }
                ui.add_space(8.0);
            }
        });
        for (i, act) in pending {
            self.apply_card_action(ui.ctx(), i, act);
        }
    }

    fn tab_history(&mut self, ui: &mut Ui, t: &Tokens) {
        let body_rect = ui.available_rect_before_wrap();
        let mut bui = ui.child_ui(body_rect, Layout::top_down(Align::Min), None);
        bui.set_clip_rect(body_rect);
        ScrollArea::vertical().auto_shrink([false, false]).scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden).show(&mut bui, |ui| {
            ui.add_space(8.0);
            for h in SAMPLE_HISTORY {
                let (row, resp) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 44.0),
                    Sense::hover(),
                );
                if resp.hovered() {
                    ui.painter().rect_filled(row, Rounding::same(t.r_sm), t.bg_sunken);
                }
                ui.painter().text(
                    egui::pos2(row.min.x + 12.0, row.center().y),
                    egui::Align2::LEFT_CENTER,
                    h.when,
                    FontId::new(10.5, FontFamily::Monospace),
                    t.ink_3,
                );
                ui.painter().text(
                    egui::pos2(row.min.x + 100.0, row.center().y - 8.0),
                    egui::Align2::LEFT_CENTER,
                    h.title,
                    FontId::new(12.0, FontFamily::Proportional),
                    t.ink_1,
                );
                ui.painter().text(
                    egui::pos2(row.min.x + 100.0, row.center().y + 8.0),
                    egui::Align2::LEFT_CENTER,
                    h.sub,
                    FontId::new(11.0, FontFamily::Proportional),
                    t.ink_3,
                );
                let (lbl, color, fill) = match h.status {
                    HistStatus::Ok => ("命中", t.ok, t.ok_soft),
                    HistStatus::Warn => ("取消", t.warn, t.warn_soft),
                };
                let font = FontId::new(10.5, FontFamily::Monospace);
                let g = ui.painter().layout_no_wrap(lbl.into(), font, color);
                let pad = Vec2::new(8.0, 2.0);
                let size = g.size() + pad * 2.0;
                let r = Rect::from_min_size(
                    egui::pos2(row.max.x - size.x - 12.0, row.center().y - size.y / 2.0),
                    size,
                );
                ui.painter().rect_filled(r, Rounding::same(999.0), fill);
                ui.painter().galley(r.min + pad, g, color);
            }
        });
    }

    fn tab_rules(&mut self, ui: &mut Ui, t: &Tokens) {
        let body_rect = ui.available_rect_before_wrap();
        let mut bui = ui.child_ui(body_rect, Layout::top_down(Align::Min), None);
        bui.set_clip_rect(body_rect);
        // local snapshot for iteration
        let mut rules = std::mem::take(&mut self.rules);
        ScrollArea::vertical().auto_shrink([false, false]).scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden).show(&mut bui, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(format!("共 {} 条 URL 匹配规则", rules.len()))
                        .color(t.ink_3)
                        .size(11.0),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(10.0);
                    ghost_button(ui, t, "＋ 新建规则");
                });
            });
            ui.add_space(6.0);
            for r in rules.iter_mut() {
                let (row, resp) = ui.allocate_exact_size(
                    Vec2::new(ui.available_width(), 42.0),
                    Sense::hover(),
                );
                if resp.hovered() {
                    ui.painter().rect_filled(row, Rounding::same(t.r_sm), t.bg_sunken);
                }
                let cb_rect = Rect::from_min_size(
                    egui::pos2(row.min.x + 12.0, row.center().y - 7.0),
                    Vec2::splat(14.0),
                );
                let cresp = ui.interact(cb_rect, ui.id().with(("rule_cb", r.name)), Sense::click());
                draw_checkbox(ui, t, cb_rect, if r.on { TriState::On } else { TriState::Off });
                if cresp.clicked() {
                    r.on = !r.on;
                }
                ui.painter().text(
                    egui::pos2(cb_rect.max.x + 10.0, row.center().y - 8.0),
                    egui::Align2::LEFT_CENTER,
                    r.name,
                    FontId::new(12.0, FontFamily::Proportional),
                    t.ink_1,
                );
                ui.painter().text(
                    egui::pos2(cb_rect.max.x + 10.0, row.center().y + 8.0),
                    egui::Align2::LEFT_CENTER,
                    r.pat,
                    FontId::new(10.5, FontFamily::Monospace),
                    t.ink_3,
                );
            }
        });
        self.rules = rules;
    }

    fn tweaks_ui(&mut self, ui: &mut Ui, t: &Tokens) {
        let mut changed = false;

        ui.label(RichText::new("外观").color(t.ink_3).size(11.0).strong());
        ui.add_space(4.0);
        if ui.checkbox(&mut self.dark, "深色模式").changed() {
            changed = true;
        }

        ui.add_space(6.0);
        ui.label(RichText::new("密度").color(t.ink_3).size(11.0));
        ui.horizontal(|ui| {
            if ui.selectable_label(self.density == Density::Compact, "Compact").clicked() {
                self.density = Density::Compact;
                changed = true;
            }
            if ui.selectable_label(self.density == Density::Regular, "Regular").clicked() {
                self.density = Density::Regular;
                changed = true;
            }
        });

        ui.add_space(6.0);
        ui.label(RichText::new("强调色").color(t.ink_3).size(11.0));
        ui.horizontal(|ui| {
            for choice in [
                AccentChoice::Rust,
                AccentChoice::Blue,
                AccentChoice::Green,
                AccentChoice::Purple,
            ] {
                let (r, resp) = ui.allocate_exact_size(Vec2::splat(22.0), Sense::click());
                let on = self.accent_choice == choice;
                ui.painter().rect(
                    r,
                    Rounding::same(t.r_sm),
                    choice.color(),
                    if on {
                        Stroke::new(2.0, t.ink_1)
                    } else {
                        Stroke::new(1.0, t.border_strong)
                    },
                );
                if resp.clicked() {
                    self.accent_choice = choice;
                    changed = true;
                }
            }
        });

        ui.add_space(6.0);
        ui.label(RichText::new("圆角").color(t.ink_3).size(11.0));
        ui.horizontal(|ui| {
            if ui.selectable_label(self.radius == RadiusStyle::Sharp, "Sharp").clicked() {
                self.radius = RadiusStyle::Sharp;
                changed = true;
            }
            if ui.selectable_label(self.radius == RadiusStyle::Soft, "Soft").clicked() {
                self.radius = RadiusStyle::Soft;
                changed = true;
            }
            if ui.selectable_label(self.radius == RadiusStyle::Pill, "Pill").clicked() {
                self.radius = RadiusStyle::Pill;
                changed = true;
            }
        });

        ui.add_space(8.0);
        ui.separator();
        ui.label(RichText::new("侧栏").color(t.ink_3).size(11.0).strong());
        ui.checkbox(&mut self.show_rail_counts, "显示算法计数");

        if changed {
            let ctx = ui.ctx().clone();
            self.refresh_theme(&ctx);
        }
    }
}

fn log_line(ui: &mut Ui, t: &Tokens, l: &LogEntry, _is_last: bool) {
    let lvl_color = match l.lvl {
        LogLvl::Info => t.info,
        LogLvl::Ok => t.ok,
        LogLvl::Warn => t.warn,
        LogLvl::Err => t.err,
    };
    let msg_color = if l.accent { t.accent_ink } else { t.ink_2 };
    // horizontal_top: 顶部对齐, 这样消息换行时时间戳仍贴在第一行
    ui.horizontal_top(|ui| {
        ui.add_space(10.0);
        ui.label(
            RichText::new(&l.t)
                .family(FontFamily::Monospace)
                .size(11.0)
                .color(t.ink_4),
        );
        ui.label(RichText::new("·").color(lvl_color).size(11.0));
        // 关键: Label::wrap() 让长消息按面板宽度自动换行
        ui.add(
            egui::Label::new(
                RichText::new(&l.msg)
                    .family(FontFamily::Monospace)
                    .size(11.0)
                    .color(msg_color),
            )
            .wrap(),
        );
    });
}

fn log_pending(ui: &mut Ui, t: &Tokens) {
    ui.horizontal(|ui| {
        ui.add_space(10.0);
        ui.label(
            RichText::new("--:--:--")
                .family(FontFamily::Monospace)
                .size(11.0)
                .color(t.ink_4),
        );
        ui.label(RichText::new("·").color(t.accent).size(11.0));
        ui.label(
            RichText::new("● 工作中…")
                .family(FontFamily::Monospace)
                .size(11.0)
                .color(t.ink_3),
        );
    });
}

fn result_card(ui: &mut Ui, t: &Tokens, r: &ResultCard) -> Option<CardAction> {
    let mut action: Option<CardAction> = None;
    let frame = egui::Frame {
        fill: if r.hit { t.accent_soft } else { t.surface_2 },
        stroke: Stroke::new(
            1.0,
            if r.pinned { t.warn } else if r.hit { t.accent } else { t.border },
        ),
        rounding: Rounding::same(t.r_md),
        inner_margin: Margin::same(10.0),
        outer_margin: Margin {
            left: 10.0,
            right: 10.0,
            top: 0.0,
            bottom: 0.0,
        },
        shadow: egui::epaint::Shadow::NONE,
    };
    frame.show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&r.algo)
                    .family(FontFamily::Monospace)
                    .size(12.0)
                    .strong()
                    .color(t.ink_1),
            );
            let (fill, color) = if r.hit {
                (t.accent, Color32::WHITE)
            } else {
                (t.bg_sunken, t.ink_3)
            };
            let font = FontId::new(10.0, FontFamily::Monospace);
            let label = if r.hit { "命中" } else { "候选" };
            let g = ui.painter().layout_no_wrap(label.into(), font, color);
            let pad = Vec2::new(6.0, 1.0);
            let size = g.size() + pad * 2.0;
            let (br, _) = ui.allocate_exact_size(size, Sense::hover());
            ui.painter().rect_filled(br, Rounding::same(999.0), fill);
            ui.painter().galley(br.min + pad, g, color);

            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(&r.elapsed)
                        .family(FontFamily::Monospace)
                        .size(10.5)
                        .color(t.ink_3),
                );
            });
        });

        // 判据说明: 为什么这条算命中 (e.g. "JSON 结构 · IV 已恢复")
        if r.hit && !r.reason.is_empty() {
            ui.add_space(3.0);
            // 首块未知/IV 已恢复用 warn 色提示, 其余用次要文字色
            let color = if r.reason.contains("首块未知") {
                t.warn
            } else {
                t.ink_2
            };
            ui.label(
                RichText::new(format!("· {}", r.reason))
                    .size(10.5)
                    .color(color),
            );
        }

        let box_frame = |hit: bool, t: &Tokens| egui::Frame {
            fill: if hit { t.surface } else { t.bg_sunken },
            stroke: if hit { Stroke::new(1.0, blend_for_border(t)) } else { Stroke::NONE },
            rounding: Rounding::same(t.r_sm),
            inner_margin: Margin::symmetric(8.0, 6.0),
            ..Default::default()
        };
        let mono_label = |s: &str, t: &Tokens| {
            RichText::new(s)
                .family(FontFamily::Monospace)
                .size(10.5)
                .color(t.ink_3)
        };

        ui.add_space(6.0);
        ui.label(mono_label("Key", t));
        ui.add_space(2.0);
        box_frame(r.hit, t).show(ui, |ui| {
            ui.label(
                RichText::new(&r.key)
                    .family(FontFamily::Monospace)
                    .size(11.0)
                    .color(t.ink_1),
            );
        });
        if let Some(iv) = &r.iv {
            ui.add_space(4.0);
            ui.label(mono_label("IV", t));
            ui.add_space(2.0);
            box_frame(r.hit, t).show(ui, |ui| {
                ui.label(
                    RichText::new(iv)
                        .family(FontFamily::Monospace)
                        .size(11.0)
                        .color(t.ink_1),
                );
            });
        }
        if let Some(p) = &r.plain {
            ui.add_space(4.0);
            ui.label(mono_label("原文", t));
            ui.add_space(2.0);
            let plain_frame = egui::Frame {
                fill: t.surface,
                stroke: Stroke {
                    width: 1.0,
                    color: t.border_strong,
                },
                rounding: Rounding::same(t.r_sm),
                inner_margin: Margin::symmetric(8.0, 6.0),
                ..Default::default()
            };
            plain_frame.show(ui, |ui| {
                ui.label(
                    RichText::new(p)
                        .family(FontFamily::Monospace)
                        .size(11.0)
                        .color(t.ink_2),
                );
            });
        }
        if r.hit {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ghost_button(ui, t, "📋 复制 KEY").clicked() {
                    action = Some(CardAction::CopyKey);
                }
                if r.iv.is_some() {
                    if ghost_button(ui, t, "📋 复制 IV").clicked() {
                        action = Some(CardAction::CopyIv);
                    }
                }
                let export_enabled = r.plain.is_some();
                let resp = ghost_button(ui, t, "📄 导出原文");
                if export_enabled && resp.clicked() {
                    action = Some(CardAction::ExportPlain);
                }
                let pin_label = if r.pinned { "📌 取消固定" } else { "📌 固定" };
                if ghost_button(ui, t, pin_label).clicked() {
                    action = Some(CardAction::TogglePin);
                }
            });
        }
    });
    action
}

// suppress unused warnings for traits we kept in scope
#[allow(dead_code)]
fn _unused(_: HashSet<()>) {}

// suppress unused widget trait
#[allow(dead_code)]
fn _w(_w: impl Widget) {}
