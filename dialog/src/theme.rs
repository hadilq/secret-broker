//! Colors from the current Omarchy theme (colors.toml), with the jade
//! defaults when no theme file is found. Only `key = "#rrggbb"` lines are
//! read; anything else is ignored.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

#[derive(Debug, Clone)]
pub struct Theme {
    pub background: Rgb,
    pub surface: Rgb,
    pub foreground: Rgb,
    pub muted: Rgb,
    pub accent: Rgb,
    pub selection: Rgb,
    pub red: Rgb,
    pub yellow: Rgb,
    pub green: Rgb,
}

impl Default for Theme {
    fn default() -> Self {
        Theme {
            background: Rgb(0x14, 0x26, 0x20),
            surface: Rgb(0x20, 0x3b, 0x31),
            foreground: Rgb(0xdf, 0xed, 0xe5),
            muted: Rgb(0x91, 0xad, 0x9f),
            accent: Rgb(0x8b, 0xcb, 0xb1),
            selection: Rgb(0x2b, 0x51, 0x47),
            red: Rgb(0xd8, 0x8d, 0x91),
            yellow: Rgb(0xc5, 0xcc, 0x91),
            green: Rgb(0x8b, 0xcb, 0xb1),
        }
    }
}

pub fn parse_hex(s: &str) -> Option<Rgb> {
    let h = s.trim().trim_matches('"').trim_matches('\'').strip_prefix('#')?;
    if h.len() != 6 || !h.is_ascii() {
        return None;
    }
    let byte = |i: usize| h.get(i..i.checked_add(2)?).and_then(|b| u8::from_str_radix(b, 16).ok());
    Some(Rgb(byte(0)?, byte(2)?, byte(4)?))
}

/// Parse colors.toml text over the defaults.
pub fn parse(text: &str) -> Theme {
    let mut t = Theme::default();
    let mut get = std::collections::HashMap::new();
    for line in text.lines() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if let Some(c) = parse_hex(v) {
            get.insert(k.trim().to_string(), c);
        }
    }
    let pick = |names: &[&str], d: Rgb| names.iter().find_map(|n| get.get(*n).copied()).unwrap_or(d);
    t.background = pick(&["background"], t.background);
    t.surface = pick(&["lighter_background", "color0", "selection_background"], t.surface);
    t.foreground = pick(&["foreground", "bright_foreground"], t.foreground);
    t.muted = pick(&["dark_foreground", "muted", "color8"], t.muted);
    t.accent = pick(&["accent", "color4", "cursor"], t.accent);
    t.selection = pick(&["selection", "selection_background"], t.selection);
    t.red = pick(&["red", "color1"], t.red);
    t.yellow = pick(&["yellow", "color3"], t.yellow);
    t.green = pick(&["green", "color2"], t.green);
    t
}

pub fn candidates(explicit: Option<&Path>) -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(p) = explicit {
        v.push(p.to_path_buf());
    }
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let state = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".local/state")));
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.as_ref().map(|h| h.join(".config")));
    if let Some(s) = state {
        v.push(s.join("omarchy/current/theme/colors.toml"));
    }
    if let Some(c) = config {
        v.push(c.join("omarchy/current/theme/colors.toml"));
    }
    v
}

/// Load the theme now (themes can change between dialogs).
pub fn load(explicit: Option<&Path>) -> Theme {
    for p in candidates(explicit) {
        if let Ok(text) = std::fs::read_to_string(&p) {
            return parse(&text);
        }
    }
    Theme::default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_omarchy_colors() {
        let t = parse("accent = \"#112233\"\nbackground = \"#000000\"\nnope = 3\nred=\"#ff0000\"\n");
        assert_eq!(t.accent, Rgb(0x11, 0x22, 0x33));
        assert_eq!(t.background, Rgb(0, 0, 0));
        assert_eq!(t.red, Rgb(0xff, 0, 0));
        assert_eq!(t.foreground, Theme::default().foreground);
        assert!(parse_hex("#12345").is_none() && parse_hex("#zzzzzz").is_none());
    }
}
