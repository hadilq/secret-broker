//! The dialog window: one wlr-layer-shell surface on the Overlay layer with
//! exclusive keyboard focus, drawn in software into wl_shm. No toolkit.
//!
//! There is deliberately no clickable "approve": approval is a PIN typed
//! here (checked by the broker) or a hardware factor the broker verifies
//! itself. The pointer isn't even bound.
//!
//! Keys in the secret field: Ctrl+V / Shift+Insert paste from the clipboard
//! (wl_data_device), Ctrl+H shows/hides what was typed, Ctrl+U clears,
//! Ctrl+W / Ctrl+Backspace delete a word.
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use crate::render::{Canvas, Fonts};
use crate::theme::{Rgb, Theme};
use smithay_client_toolkit::reexports::client::{
    globals::registry_queue_init,
    protocol::{
        wl_data_device::WlDataDevice, wl_data_device_manager::DndAction, wl_keyboard, wl_output, wl_seat, wl_shm,
        wl_surface,
    },
    Connection, EventQueue, QueueHandle,
};
use smithay_client_toolkit::{
    compositor::{CompositorHandler, CompositorState},
    data_device_manager::{
        data_device::{DataDevice, DataDeviceHandler},
        data_offer::{DataOfferHandler, DragOffer},
        DataDeviceManagerState, ReadPipe,
    },
    delegate_registry,
    output::{OutputHandler, OutputState},
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::{
        keyboard::{KeyEvent, KeyboardHandler, Keysym, Modifiers, RawModifiers},
        Capability, SeatHandler, SeatState,
    },
    shell::{
        wlr_layer::{
            KeyboardInteractivity, Layer, LayerShell, LayerShellHandler, LayerSurface,
            LayerSurfaceConfigure,
        },
        WaylandSurface,
    },
    shm::{slot::SlotPool, Shm, ShmHandler},
};
use std::collections::VecDeque;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const MAX_INPUT: usize = 128;
/// Most bytes read from the clipboard for one paste.
pub const MAX_PASTE: usize = 4096;
/// Give up on a clipboard owner that doesn't answer.
const PASTE_TIMEOUT: Duration = Duration::from_secs(2);
/// Clipboard types we accept, best first.
const TEXT_MIMES: [&str; 4] = ["text/plain;charset=utf-8", "UTF8_STRING", "text/plain", "STRING"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Normal,
    Muted,
    Accent,
    Warn,
    Error,
}

#[derive(Debug, Clone, Default)]
pub struct View {
    pub title: String,
    /// (label, value, tone of value)
    pub rows: Vec<(String, String, Tone)>,
    /// Free text paragraph (pinentry description).
    pub body: String,
    pub phrase: String,
    /// Show a masked input field with this label.
    pub field: Option<String>,
    pub hints: Vec<String>,
    pub message: Option<(String, Tone)>,
    pub footer: String,
    pub deadline: Option<Instant>,
    pub busy: bool,
    /// Full details (label, value, tone), shown with Tab, scrolled with
    /// the arrow keys. Values are wrapped.
    pub details: Vec<(String, String, Tone)>,
    pub show_details: bool,
    pub scroll: usize,
}

#[derive(Debug)]
pub enum UiEvent {
    Submit(Zeroizing<String>),
    Cancel,
    /// The extra fd passed to `wait` is readable.
    Readable,
    Tick,
    Closed,
}

struct App {
    registry_state: RegistryState,
    seat_state: SeatState,
    output_state: OutputState,
    shm: Shm,
    pool: SlotPool,
    layer: LayerSurface,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    ctrl: bool,
    shift: bool,
    data_devices: Option<DataDeviceManagerState>,
    data_device: Option<DataDevice>,
    paste: Option<Paste>,
    /// Show the secret field in plain text (Ctrl+H). Off by default.
    reveal: bool,
    configured: bool,
    scale: i32,
    width: u32,
    height: u32,
    input: Zeroizing<String>,
    events: VecDeque<UiEvent>,
    dirty: bool,
    view: View,
    theme: Theme,
    fonts: Fonts,
}

/// A clipboard read in flight: the pipe is polled by `Ui::wait` together
/// with the Wayland socket, so a slow clipboard owner can't freeze the dialog.
struct Paste {
    pipe: ReadPipe,
    buf: Zeroizing<Vec<u8>>,
    started: Instant,
}

/// What the secret field shows: dots, or (revealed) the text itself.
#[derive(Clone, Copy)]
pub struct Field<'a> {
    pub len: usize,
    pub plain: Option<&'a str>,
}

fn new_input() -> Zeroizing<String> {
    // Reserve once, so typing or pasting never reallocates and leaves a
    // stale copy of the secret behind in freed memory.
    Zeroizing::new(String::with_capacity(MAX_INPUT * 4))
}

/// Pick the clipboard type to ask for.
fn pick_mime(offered: &[String]) -> Option<&'static str> {
    TEXT_MIMES.into_iter().find(|m| offered.iter().any(|o| o.eq_ignore_ascii_case(m)))
}

/// Clipboard bytes to the text to insert: UTF-8, trailing newlines dropped,
/// no other control characters (a multi-line paste is refused, not joined).
fn clean_paste(bytes: &[u8]) -> Result<&str, &'static str> {
    let text = std::str::from_utf8(bytes).map_err(|_| "clipboard text is not UTF-8")?;
    let text = text.trim_end_matches(['\n', '\r']);
    if text.is_empty() {
        return Err("clipboard is empty");
    }
    if text.chars().any(char::is_control) {
        return Err("clipboard has line breaks or control characters");
    }
    Ok(text)
}

/// Ctrl+W: drop trailing spaces, then the word before them.
fn delete_word(s: &mut String) {
    while s.ends_with(char::is_whitespace) {
        s.pop();
    }
    while s.chars().next_back().is_some_and(|c| !c.is_whitespace()) {
        s.pop();
    }
}

pub struct Ui {
    _conn: Connection,
    queue: EventQueue<App>,
    app: App,
}

const W: u32 = 560;

impl Ui {
    pub fn open(theme: Theme, fonts: Fonts) -> Result<Ui, String> {
        let conn = Connection::connect_to_env().map_err(|e| format!("wayland: {e}"))?;
        let (globals, queue) = registry_queue_init::<App>(&conn).map_err(|e| format!("wayland: {e}"))?;
        let qh = queue.handle();
        let compositor = CompositorState::bind(&globals, &qh).map_err(|e| format!("wl_compositor: {e}"))?;
        let layer_shell = LayerShell::bind(&globals, &qh)
            .map_err(|e| format!("this compositor has no wlr-layer-shell: {e}"))?;
        let shm = Shm::bind(&globals, &qh).map_err(|e| format!("wl_shm: {e}"))?;
        // Optional: without it there's just no paste.
        let data_devices = DataDeviceManagerState::bind(&globals, &qh).ok();
        let surface = compositor.create_surface(&qh);
        let layer = layer_shell.create_layer_surface(&qh, surface, Layer::Overlay, Some("secret-broker"), None);
        // No anchor: compositors center the surface.
        layer.set_keyboard_interactivity(KeyboardInteractivity::Exclusive);
        layer.set_exclusive_zone(-1);
        layer.set_size(W, 300);
        layer.commit();
        let pool = SlotPool::new((W * 300 * 4) as usize, &shm).map_err(|e| format!("shm pool: {e}"))?;
        let app = App {
            registry_state: RegistryState::new(&globals),
            seat_state: SeatState::new(&globals, &qh),
            output_state: OutputState::new(&globals, &qh),
            shm,
            pool,
            layer,
            keyboard: None,
            ctrl: false,
            shift: false,
            data_devices,
            data_device: None,
            paste: None,
            reveal: false,
            configured: false,
            scale: 1,
            width: W,
            height: 300,
            input: new_input(),
            events: VecDeque::new(),
            dirty: true,
            view: View::default(),
            theme,
            fonts,
        };
        let mut ui = Ui {
            _conn: conn,
            queue,
            app,
        };
        // Get the first configure.
        let start = Instant::now();
        while !ui.app.configured {
            if start.elapsed() > Duration::from_secs(5) {
                return Err("compositor did not configure the dialog".into());
            }
            ui.queue
                .blocking_dispatch(&mut ui.app)
                .map_err(|e| format!("wayland: {e}"))?;
        }
        Ok(ui)
    }

    pub fn set_view(&mut self, v: View) {
        self.app.view = v;
        self.app.dirty = true;
    }

    pub fn view_mut(&mut self) -> &mut View {
        self.app.dirty = true;
        &mut self.app.view
    }

    /// Wait for the next event (keyboard, `extra` fd readable, or a 1s tick).
    pub fn wait(&mut self, extra: Option<RawFd>) -> Result<UiEvent, String> {
        loop {
            if self.app.dirty && self.app.configured {
                self.app.draw(&self.queue.handle());
            }
            if let Some(ev) = self.app.events.pop_front() {
                return Ok(ev);
            }
            self.queue.flush().map_err(|e| format!("wayland: {e}"))?;
            let Some(guard) = self.queue.prepare_read() else {
                self.queue
                    .dispatch_pending(&mut self.app)
                    .map_err(|e| format!("wayland: {e}"))?;
                continue;
            };
            let wl_fd = guard.connection_fd().as_raw_fd();
            let mut fds = vec![libc::pollfd {
                fd: wl_fd,
                events: libc::POLLIN,
                revents: 0,
            }];
            let paste_fd = self.app.paste.as_ref().map(|p| p.pipe.as_raw_fd());
            for fd in [extra, paste_fd].into_iter().flatten() {
                fds.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            let timeout = if paste_fd.is_some() { 100 } else { 1000 };
            // SAFETY: fds is a valid array of pollfd for the duration of the call.
            let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
            let ready = |fd: Option<RawFd>| fd.is_some_and(|fd| fds.iter().any(|p| p.fd == fd && p.revents != 0));
            let wl_ready = fds.first().is_some_and(|p| p.revents != 0);
            let extra_ready = ready(extra);
            let paste_ready = ready(paste_fd);
            if wl_ready {
                match guard.read() {
                    Ok(_) => {}
                    Err(smithay_client_toolkit::reexports::client::backend::WaylandError::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(format!("wayland: {e}")),
                }
            } else {
                drop(guard);
            }
            self.queue
                .dispatch_pending(&mut self.app)
                .map_err(|e| format!("wayland: {e}"))?;
            if paste_fd.is_some() {
                self.app.poll_paste(paste_ready);
                if self.app.paste.is_some() && n == 0 {
                    continue; // short paste timeout, not a 1s tick
                }
            }
            if let Some(ev) = self.app.events.pop_front() {
                return Ok(ev);
            }
            if extra_ready {
                return Ok(UiEvent::Readable);
            }
            if n == 0 {
                if self.app.view.deadline.is_some() {
                    self.app.dirty = true;
                }
                return Ok(UiEvent::Tick);
            }
        }
    }

    /// Render the current view into an RGBA buffer without a compositor
    /// (tests, `--render-png`).
    pub fn render_offscreen(theme: Theme, fonts: Fonts, view: View, field: Field<'_>, scale: i32) -> (u32, u32, Vec<u8>) {
        let mut app_like = Offscreen {
            theme,
            fonts,
            view,
        };
        let h = layout_height(&mut app_like.fonts, &app_like.view);
        let (w, h) = (W * scale as u32, h * scale as u32);
        let mut data = vec![0u8; (w * h * 4) as usize];
        {
            let mut c = Canvas {
                w: w as i32,
                h: h as i32,
                data: &mut data,
            };
            paint(&mut c, &mut app_like.fonts, &app_like.theme, &app_like.view, field, scale as f32);
        }
        (w, h, data)
    }
}

struct Offscreen {
    theme: Theme,
    fonts: Fonts,
    view: View,
}

const PAD: f32 = 26.0;
const TITLE_PX: f32 = 21.0;
const BODY_PX: f32 = 14.5;
const SMALL_PX: f32 = 12.5;
const ROW_H: f32 = 22.0;
const DETAIL_PX: f32 = 12.5;
const DETAIL_H: f32 = 18.0;
const DETAIL_VISIBLE: usize = 16;
const DETAIL_LABEL_W: f32 = 104.0;
const FIELD_KEYS_H: f32 = 20.0;

fn tone(t: &Theme, tone: Tone) -> Rgb {
    match tone {
        Tone::Normal => t.foreground,
        Tone::Muted => t.muted,
        Tone::Accent => t.accent,
        Tone::Warn => t.yellow,
        Tone::Error => t.red,
    }
}

fn body_lines(fonts: &mut Fonts, v: &View) -> Vec<String> {
    if v.body.is_empty() {
        return Vec::new();
    }
    fonts.wrap(false, &v.body, BODY_PX, W as f32 - 2.0 * PAD, 8)
}

/// Wrapped detail lines (label only on the first line of each value).
fn detail_lines(fonts: &mut Fonts, v: &View) -> Vec<(String, String, Tone)> {
    let width = W as f32 - 2.0 * PAD - 24.0 - DETAIL_LABEL_W;
    let mut out = Vec::new();
    for (label, value, tone) in &v.details {
        if label.is_empty() && value.is_empty() {
            out.push((String::new(), String::new(), Tone::Muted));
            continue;
        }
        for (i, line) in fonts.wrap_hard(false, value, DETAIL_PX, width).into_iter().enumerate() {
            out.push((if i == 0 { label.clone() } else { String::new() }, line, *tone));
        }
    }
    out
}

fn details_height(fonts: &mut Fonts, v: &View) -> f32 {
    if !v.show_details || v.details.is_empty() {
        return 0.0;
    }
    let n = detail_lines(fonts, v).len().min(DETAIL_VISIBLE);
    14.0 + n as f32 * DETAIL_H + 12.0 + DETAIL_H
}

/// Logical height for a view.
fn layout_height(fonts: &mut Fonts, v: &View) -> u32 {
    let mut h = PAD + TITLE_PX + 14.0;
    h += v.rows.len() as f32 * ROW_H;
    h += details_height(fonts, v);
    let body = body_lines(fonts, v).len();
    if body > 0 {
        h += body as f32 * ROW_H + 6.0;
    }
    if !v.phrase.is_empty() {
        h += 40.0;
    }
    if v.field.is_some() {
        h += 12.0 + 44.0 + FIELD_KEYS_H;
    }
    h += v.hints.len() as f32 * ROW_H;
    h += 10.0 + ROW_H; // message line (reserved, so the card doesn't jump)
    h += 14.0 + SMALL_PX + PAD;
    h.ceil() as u32
}

fn fmt_remaining(d: Option<Instant>) -> String {
    let Some(d) = d else { return String::new() };
    let s = d.saturating_duration_since(Instant::now()).as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

fn paint(c: &mut Canvas<'_>, fonts: &mut Fonts, t: &Theme, v: &View, field: Field<'_>, s: f32) {
    c.clear();
    let (w, h) = (c.w as f32, c.h as f32);
    // border + card
    c.round_rect(0.0, 0.0, w, h, 14.0 * s, t.accent);
    c.round_rect(2.0 * s, 2.0 * s, w - 4.0 * s, h - 4.0 * s, 12.0 * s, t.background);
    let inner = (W as f32 - 2.0 * PAD) * s;
    let x = PAD * s;
    let mut y = PAD * s + fonts.ascent(TITLE_PX * s);
    // lock glyph + title
    let title = fonts.ellipsize(true, &v.title, TITLE_PX * s, inner - 60.0 * s);
    c.text(fonts, true, x, y, TITLE_PX * s, &title, t.accent);
    let rem = fmt_remaining(v.deadline);
    if !rem.is_empty() {
        let rw = fonts.width(false, &rem, SMALL_PX * s);
        c.text(fonts, false, x + inner - rw, y, SMALL_PX * s, &rem, t.muted);
    }
    y += 14.0 * s;
    let label_w = 132.0 * s;
    for (label, value, tn) in &v.rows {
        y += ROW_H * s;
        c.text(fonts, false, x, y, BODY_PX * s, label, t.muted);
        let val = fonts.ellipsize(false, value, BODY_PX * s, inner - label_w);
        c.text(fonts, false, x + label_w, y, BODY_PX * s, &val, tone(t, *tn));
    }
    if v.show_details && !v.details.is_empty() {
        let lines = detail_lines(fonts, v);
        let n = lines.len();
        let shown = n.min(DETAIL_VISIBLE);
        let first = v.scroll.min(n.saturating_sub(shown));
        let top = y + 10.0 * s;
        let ph = (shown as f32 * DETAIL_H + 12.0) * s;
        c.round_rect(x, top, inner, ph, 8.0 * s, t.surface);
        let mut ly = top + 4.0 * s;
        for (label, value, tn) in lines.iter().skip(first).take(shown) {
            ly += DETAIL_H * s;
            let lx = x + 12.0 * s;
            if !label.is_empty() {
                let l = fonts.ellipsize(false, label, DETAIL_PX * s, (DETAIL_LABEL_W - 6.0) * s);
                c.text(fonts, false, lx, ly, DETAIL_PX * s, &l, t.muted);
            }
            let val = fonts.ellipsize(false, value, DETAIL_PX * s, inner - (24.0 + DETAIL_LABEL_W) * s);
            c.text(fonts, false, lx + DETAIL_LABEL_W * s, ly, DETAIL_PX * s, &val, tone(t, *tn));
        }
        let ind = if n > shown {
            format!("lines {}–{} of {n}   ↑ ↓ PgUp PgDn scroll", first + 1, first + shown)
        } else {
            format!("{n} lines")
        };
        let iy = top + ph + (DETAIL_H - 2.0) * s;
        c.text(fonts, false, x + 4.0 * s, iy, SMALL_PX * s, &ind, t.muted);
        y = top + ph + DETAIL_H * s;
    }
    let body = body_lines(fonts, v);
    if !body.is_empty() {
        y += 6.0 * s;
        for line in &body {
            y += ROW_H * s;
            // wrap() measured at 1x; ellipsize again at this scale
            let l = fonts.ellipsize(false, line, BODY_PX * s, inner);
            c.text(fonts, false, x, y, BODY_PX * s, &l, t.foreground);
        }
    }
    if !v.phrase.is_empty() {
        let top = y + 10.0 * s;
        c.round_rect(x, top, inner, 30.0 * s, 8.0 * s, t.selection);
        let by = top + 20.0 * s;
        let lw = c.text(fonts, false, x + 12.0 * s, by, SMALL_PX * s, "your phrase  ", t.muted);
        let ph = fonts.ellipsize(true, &v.phrase, BODY_PX * s, inner - lw - 24.0 * s);
        c.text(fonts, true, x + 12.0 * s + lw, by, BODY_PX * s, &ph, t.foreground);
        y = top + 30.0 * s;
    }
    if let Some(label) = &v.field {
        let top = y + 12.0 * s;
        let edge = if v.busy {
            t.muted
        } else if field.plain.is_some() {
            t.yellow // shown in clear: make it obvious
        } else {
            t.accent
        };
        c.round_rect(x, top, inner, 44.0 * s, 9.0 * s, edge);
        c.round_rect(x + 1.5 * s, top + 1.5 * s, inner - 3.0 * s, 41.0 * s, 8.0 * s, t.surface);
        let by = top + 28.0 * s;
        let lw = c.text(fonts, false, x + 14.0 * s, by, BODY_PX * s, label, t.muted);
        let mut dx = x + 14.0 * s + lw + 10.0 * s;
        let room = x + inner - 18.0 * s - dx;
        if let Some(plain) = field.plain {
            // Show the end of the text if it doesn't fit (that's where the
            // cursor is).
            let px = BODY_PX * s;
            let mut start = 0;
            while fonts.width_uncached(plain.get(start..).unwrap_or(""), px) > room {
                match plain.get(start..).and_then(|r| r.chars().next()) {
                    Some(ch) => start += ch.len_utf8(),
                    None => break,
                }
            }
            let shown = plain.get(start..).unwrap_or("");
            dx += c.secret_text(fonts, dx, by, px, shown, t.foreground) + 2.0 * s;
        } else {
            let n = field.len.min((room / (15.0 * s)).max(0.0) as usize);
            for _ in 0..n {
                c.round_rect(dx, by - 9.0 * s, 9.0 * s, 9.0 * s, 4.5 * s, t.foreground);
                dx += 15.0 * s;
            }
        }
        if !v.busy {
            c.round_rect(dx, by - 15.0 * s, 2.0 * s, 19.0 * s, 1.0 * s, t.accent);
        }
        y = top + 44.0 * s;
        let keys = format!(
            "Ctrl+V paste    Ctrl+H {}    Ctrl+U clear    Ctrl+W delete word",
            if field.plain.is_some() { "hide" } else { "show" }
        );
        let kl = fonts.ellipsize(false, &keys, SMALL_PX * s, inner);
        c.text(fonts, false, x + 4.0 * s, y + (FIELD_KEYS_H - 3.0) * s, SMALL_PX * s, &kl, t.muted);
        y += FIELD_KEYS_H * s;
    }
    for hint in &v.hints {
        y += ROW_H * s;
        let hl = fonts.ellipsize(false, hint, BODY_PX * s, inner - 22.0 * s);
        c.round_rect(x + 2.0 * s, y - 9.0 * s, 8.0 * s, 8.0 * s, 4.0 * s, t.yellow);
        c.text(fonts, false, x + 20.0 * s, y, BODY_PX * s, &hl, t.foreground);
    }
    y += (10.0 + ROW_H) * s;
    if let Some((m, tn)) = &v.message {
        let ml = fonts.ellipsize(false, m, BODY_PX * s, inner);
        c.text(fonts, false, x, y, BODY_PX * s, &ml, tone(t, *tn));
    }
    let fy = h - PAD * s + 4.0 * s;
    let foot = fonts.ellipsize(false, &v.footer, SMALL_PX * s, inner);
    c.text(fonts, false, x, fy, SMALL_PX * s, &foot, t.muted);
}

impl App {
    fn draw(&mut self, _qh: &QueueHandle<Self>) {
        self.dirty = false;
        let want_h = layout_height(&mut self.fonts, &self.view);
        if want_h != self.height {
            self.height = want_h;
            self.layer.set_size(W, want_h);
            self.layer.commit();
            // wait for the configure with the new size
            return;
        }
        let s = self.scale.max(1);
        let (pw, ph) = (self.width as i32 * s, self.height as i32 * s);
        let stride = pw * 4;
        let Ok((buffer, data)) = self.pool.create_buffer(pw, ph, stride, wl_shm::Format::Argb8888) else {
            return;
        };
        {
            let mut c = Canvas { w: pw, h: ph, data };
            let field = Field {
                len: self.input.chars().count(),
                plain: self.reveal.then_some(self.input.as_str()),
            };
            paint(&mut c, &mut self.fonts, &self.theme, &self.view, field, s as f32);
        }
        let surf = self.layer.wl_surface();
        surf.set_buffer_scale(s);
        surf.damage_buffer(0, 0, pw, ph);
        if buffer.attach_to(surf).is_ok() {
            self.layer.commit();
        }
    }

    fn scroll_by(&mut self, delta: isize) {
        let n = detail_lines(&mut self.fonts, &self.view).len();
        let max = n.saturating_sub(DETAIL_VISIBLE);
        let cur = self.view.scroll.min(max);
        self.view.scroll = if delta < 0 {
            cur.saturating_sub(delta.unsigned_abs())
        } else {
            cur.saturating_add(delta.unsigned_abs()).min(max)
        };
        self.dirty = true;
    }

    /// Ctrl+V: ask the clipboard owner for text; `Ui::wait` reads the pipe.
    fn start_paste(&mut self) {
        if self.view.field.is_none() || self.view.busy || self.paste.is_some() {
            return;
        }
        let offer = self.data_device.as_ref().and_then(|d| d.data().selection_offer());
        let Some(offer) = offer else {
            self.note("clipboard is empty", Tone::Warn);
            return;
        };
        let Some(mime) = offer.with_mime_types(pick_mime) else {
            self.note("clipboard has no text", Tone::Warn);
            return;
        };
        let pipe = match offer.receive(mime.to_string()) {
            Ok(p) => p,
            Err(e) => {
                self.note(&format!("paste failed: {e}"), Tone::Error);
                return;
            }
        };
        let fd = pipe.as_raw_fd();
        // SAFETY: fcntl on a pipe fd we own; failure only means blocking reads,
        // and we only read after poll says readable.
        unsafe {
            let fl = libc::fcntl(fd, libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        self.paste = Some(Paste {
            pipe,
            buf: Zeroizing::new(Vec::with_capacity(MAX_PASTE + 1024)),
            started: Instant::now(),
        });
    }

    /// Read what's there; finish on EOF, too much data, or timeout.
    fn poll_paste(&mut self, readable: bool) {
        use std::io::Read;
        let Some(p) = self.paste.as_mut() else { return };
        let mut done = false;
        let mut err = None;
        if readable {
            let mut chunk = Zeroizing::new([0u8; 1024]);
            loop {
                match p.pipe.read(&mut chunk[..]) {
                    Ok(0) => {
                        done = true;
                        break;
                    }
                    Ok(n) => {
                        if p.buf.len() + n > MAX_PASTE {
                            err = Some("clipboard text is too long (over 4 KiB)");
                            break;
                        }
                        p.buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        err = Some("couldn't read the clipboard");
                        break;
                    }
                }
            }
        }
        if err.is_none() && !done && p.started.elapsed() > PASTE_TIMEOUT {
            err = Some("the clipboard owner didn't answer");
        }
        if err.is_none() && !done {
            return;
        }
        let Some(p) = self.paste.take() else { return };
        if let Some(e) = err {
            self.note(e, Tone::Error);
            return;
        }
        let text = match clean_paste(&p.buf) {
            Ok(t) => t,
            Err(e) => {
                self.note(e, Tone::Warn);
                return;
            }
        };
        let n = text.chars().count();
        if self.input.chars().count() + n > MAX_INPUT {
            self.note(&format!("too long to paste (max {MAX_INPUT} characters)"), Tone::Error);
            return;
        }
        self.input.push_str(text);
        self.note(&format!("pasted {n} characters"), Tone::Muted);
    }

    fn note(&mut self, m: &str, tone: Tone) {
        self.view.message = Some((m.to_string(), tone));
        self.dirty = true;
    }

    fn key(&mut self, ev: KeyEvent) {
        let details = !self.view.details.is_empty();
        match ev.keysym {
            Keysym::Escape => self.events.push_back(UiEvent::Cancel),
            Keysym::Tab | Keysym::ISO_Left_Tab if details => {
                self.view.show_details = !self.view.show_details;
                self.dirty = true;
            }
            Keysym::Up if self.view.show_details => self.scroll_by(-1),
            Keysym::Down if self.view.show_details => self.scroll_by(1),
            Keysym::Page_Up if self.view.show_details => self.scroll_by(-(DETAIL_VISIBLE as isize - 2)),
            Keysym::Page_Down if self.view.show_details => self.scroll_by(DETAIL_VISIBLE as isize - 2),
            Keysym::Home if self.view.show_details => self.scroll_by(-100_000),
            Keysym::End if self.view.show_details => self.scroll_by(100_000),
            Keysym::Return | Keysym::KP_Enter => {
                if self.view.busy {
                    return;
                }
                if self.view.field.is_some() {
                    if self.input.is_empty() {
                        return;
                    }
                    let pin = std::mem::replace(&mut self.input, new_input());
                    self.paste = None;
                    self.events.push_back(UiEvent::Submit(pin));
                } else {
                    self.events.push_back(UiEvent::Submit(Zeroizing::new(String::new())));
                }
                self.dirty = true;
            }
            Keysym::BackSpace => {
                if self.ctrl {
                    delete_word(&mut self.input);
                } else {
                    self.input.pop();
                }
                self.dirty = true;
            }
            Keysym::Insert if self.shift && !self.ctrl => self.start_paste(),
            _ => {
                if self.view.field.is_none() || self.view.busy {
                    return;
                }
                if self.ctrl {
                    match ev.keysym {
                        Keysym::u | Keysym::U => zeroize::Zeroize::zeroize(&mut *self.input),
                        Keysym::w | Keysym::W => delete_word(&mut self.input),
                        Keysym::h | Keysym::H => self.reveal = !self.reveal,
                        Keysym::v | Keysym::V => self.start_paste(),
                        _ => return,
                    }
                    self.dirty = true;
                    return;
                }
                if let Some(t) = ev.utf8.as_deref() {
                    for ch in t.chars().filter(|c| !c.is_control()) {
                        if self.input.chars().count() < MAX_INPUT {
                            self.input.push(ch);
                        }
                    }
                    self.dirty = true;
                }
            }
        }
    }
}

impl CompositorHandler for App {
    fn scale_factor_changed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, f: i32) {
        if f != self.scale {
            self.scale = f.clamp(1, 4);
            self.dirty = true;
        }
    }
    fn transform_changed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: wl_output::Transform) {}
    fn frame(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: u32) {}
    fn surface_enter(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: &wl_output::WlOutput) {}
    fn surface_leave(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_surface::WlSurface, _: &wl_output::WlOutput) {}
}

impl OutputHandler for App {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }
    fn new_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn update_output(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
    fn output_destroyed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_output::WlOutput) {}
}

impl LayerShellHandler for App {
    fn closed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &LayerSurface) {
        self.events.push_back(UiEvent::Closed);
    }
    fn configure(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &LayerSurface, cfg: LayerSurfaceConfigure, _: u32) {
        if cfg.new_size.0 > 0 {
            self.width = cfg.new_size.0;
        }
        if cfg.new_size.1 > 0 {
            self.height = cfg.new_size.1;
        }
        self.configured = true;
        self.dirty = true;
    }
}

impl SeatHandler for App {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }
    fn new_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
    fn new_capability(&mut self, _: &Connection, qh: &QueueHandle<Self>, seat: wl_seat::WlSeat, cap: Capability) {
        if cap == Capability::Keyboard && self.keyboard.is_none() {
            self.keyboard = self.seat_state.get_keyboard(qh, &seat, None).ok();
        }
        if cap == Capability::Keyboard && self.data_device.is_none() {
            self.data_device = self.data_devices.as_ref().map(|m| m.get_data_device(qh, &seat));
        }
    }
    fn remove_capability(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat, cap: Capability) {
        if cap == Capability::Keyboard {
            if let Some(k) = self.keyboard.take() {
                k.release();
            }
        }
    }
    fn remove_seat(&mut self, _: &Connection, _: &QueueHandle<Self>, _: wl_seat::WlSeat) {}
}

impl KeyboardHandler for App {
    fn enter(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: &wl_surface::WlSurface, _: u32, _: &[u32], _: &[Keysym]) {}
    fn leave(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: &wl_surface::WlSurface, _: u32) {}
    fn press_key(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: u32, ev: KeyEvent) {
        self.key(ev);
    }
    fn repeat_key(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: u32, ev: KeyEvent) {
        if matches!(ev.keysym, Keysym::BackSpace | Keysym::Up | Keysym::Down | Keysym::Page_Up | Keysym::Page_Down) {
            self.key(ev);
        }
    }
    fn release_key(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: u32, _: KeyEvent) {}
    fn update_modifiers(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &wl_keyboard::WlKeyboard, _: u32, m: Modifiers, _: RawModifiers, _: u32) {
        self.ctrl = m.ctrl;
        self.shift = m.shift;
    }
}

// Only the clipboard selection is used; drag and drop is ignored.
impl DataDeviceHandler for App {
    fn enter(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice, _: f64, _: f64, _: &wl_surface::WlSurface) {}
    fn leave(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice) {}
    fn motion(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice, _: f64, _: f64) {}
    fn selection(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice) {}
    fn drop_performed(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &WlDataDevice) {}
}

impl DataOfferHandler for App {
    fn source_actions(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &mut DragOffer, _: DndAction) {}
    fn selected_action(&mut self, _: &Connection, _: &QueueHandle<Self>, _: &mut DragOffer, _: DndAction) {}
}

impl ShmHandler for App {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl ProvidesRegistryState for App {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }
    registry_handlers![OutputState, SeatState];
}

delegate_registry!(App);
smithay_client_toolkit::delegate_dispatch2!(App);

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn paste_cleaning() {
        assert_eq!(clean_paste(b"hunter2\n"), Ok("hunter2"));
        assert_eq!(clean_paste(b"hunter2\r\n"), Ok("hunter2"));
        assert_eq!(clean_paste("pässwörd ✓".as_bytes()), Ok("pässwörd ✓"));
        assert_eq!(clean_paste(b"a b"), Ok("a b"));
        assert!(clean_paste(b"").is_err());
        assert!(clean_paste(b"\n").is_err());
        assert!(clean_paste(b"two\nlines").is_err());
        assert!(clean_paste(b"tab\there").is_err());
        assert!(clean_paste(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn mime_choice() {
        let m = |v: &[&str]| pick_mime(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(m(&["text/plain", "text/plain;charset=utf-8"]), Some("text/plain;charset=utf-8"));
        assert_eq!(m(&["TEXT", "text/plain"]), Some("text/plain"));
        assert_eq!(m(&["UTF8_STRING"]), Some("UTF8_STRING"));
        assert_eq!(m(&["image/png"]), None);
    }

    #[test]
    fn word_delete() {
        let mut s = String::from("correct horse  ");
        delete_word(&mut s);
        assert_eq!(s, "correct ");
        delete_word(&mut s);
        assert_eq!(s, "");
        delete_word(&mut s);
        assert_eq!(s, "");
    }
}
