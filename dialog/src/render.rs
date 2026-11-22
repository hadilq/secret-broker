//! Tiny software renderer: anti-aliased rounded rectangles and text into a
//! premultiplied ARGB8888 (wl_shm) buffer. Integer math here is on pixel
//! coordinates bounded by the buffer size; floats do the blending.
#![allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]

use crate::theme::Rgb;
use fontdue::{Font, FontSettings, Metrics};
use std::collections::HashMap;

pub struct Fonts {
    pub regular: Font,
    pub bold: Font,
    cache: HashMap<(bool, char, u32), (Metrics, Vec<u8>)>,
}

impl Fonts {
    pub fn load(regular: &[u8], bold: Option<&[u8]>) -> Result<Self, String> {
        let r = Font::from_bytes(regular, FontSettings::default()).map_err(|e| e.to_string())?;
        let b = match bold {
            Some(b) => Font::from_bytes(b, FontSettings::default()).map_err(|e| e.to_string())?,
            None => Font::from_bytes(regular, FontSettings::default()).map_err(|e| e.to_string())?,
        };
        Ok(Fonts {
            regular: r,
            bold: b,
            cache: HashMap::new(),
        })
    }

    fn glyph(&mut self, bold: bool, c: char, px: f32) -> &(Metrics, Vec<u8>) {
        let key = (bold, c, px.to_bits());
        let font = if bold { &self.bold } else { &self.regular };
        self.cache
            .entry(key)
            .or_insert_with(|| font.rasterize(c, px))
    }

    /// Advance width without touching the glyph cache, for revealed secret
    /// text (so the cache doesn't keep which characters a password uses).
    pub fn width_uncached(&self, text: &str, px: f32) -> f32 {
        text.chars().map(|c| self.regular.metrics(c, px).advance_width).sum()
    }

    pub fn width(&mut self, bold: bool, text: &str, px: f32) -> f32 {
        text.chars().map(|c| self.glyph(bold, c, px).0.advance_width).sum()
    }

    pub fn ascent(&self, px: f32) -> f32 {
        self.regular
            .horizontal_line_metrics(px)
            .map(|m| m.ascent)
            .unwrap_or(px * 0.8)
    }

    /// Cut `text` to fit `max` pixels, adding an ellipsis.
    pub fn ellipsize(&mut self, bold: bool, text: &str, px: f32, max: f32) -> String {
        if self.width(bold, text, px) <= max {
            return text.to_string();
        }
        let ell = self.width(bold, "…", px);
        let mut out = String::new();
        let mut w = 0.0;
        for c in text.chars() {
            let cw = self.glyph(bold, c, px).0.advance_width;
            if w + cw + ell > max {
                break;
            }
            w += cw;
            out.push(c);
        }
        out.push('…');
        out
    }

    /// Word wrap without a line limit; words wider than `max` (paths, store
    /// hashes) are broken between characters.
    pub fn wrap_hard(&mut self, bold: bool, text: &str, px: f32, max: f32) -> Vec<String> {
        let mut lines = Vec::new();
        for para in text.split('\n') {
            let mut cur = String::new();
            for word in para.split(' ') {
                let cand = if cur.is_empty() {
                    word.to_string()
                } else {
                    format!("{cur} {word}")
                };
                if self.width(bold, &cand, px) <= max {
                    cur = cand;
                    continue;
                }
                if !cur.is_empty() {
                    lines.push(std::mem::take(&mut cur));
                }
                for ch in word.chars() {
                    cur.push(ch);
                    if self.width(bold, &cur, px) > max && cur.chars().count() > 1 {
                        cur.pop();
                        lines.push(std::mem::take(&mut cur));
                        cur.push(ch);
                    }
                }
            }
            lines.push(cur);
        }
        lines
    }

    /// Greedy word wrap into at most `max_lines` lines.
    pub fn wrap(&mut self, bold: bool, text: &str, px: f32, max: f32, max_lines: usize) -> Vec<String> {
        let mut lines: Vec<String> = Vec::new();
        for para in text.split('\n') {
            let mut cur = String::new();
            for word in para.split(' ') {
                let cand = if cur.is_empty() {
                    word.to_string()
                } else {
                    format!("{cur} {word}")
                };
                if self.width(bold, &cand, px) <= max || cur.is_empty() {
                    cur = cand;
                } else {
                    lines.push(std::mem::take(&mut cur));
                    cur = word.to_string();
                }
            }
            lines.push(cur);
        }
        if lines.len() > max_lines {
            lines.truncate(max_lines);
            if let Some(last) = lines.last_mut() {
                let l = format!("{last} …");
                *last = self.ellipsize(bold, &l, px, max);
            }
        }
        lines
            .into_iter()
            .map(|l| self.ellipsize(bold, &l, px, max))
            .collect()
    }
}

pub struct Canvas<'a> {
    pub w: i32,
    pub h: i32,
    pub data: &'a mut [u8],
}

impl Canvas<'_> {
    pub fn clear(&mut self) {
        self.data.fill(0);
    }

    /// Blend `c` at coverage `a` (0..1) over pixel (x, y).
    fn blend(&mut self, x: i32, y: i32, c: Rgb, a: f32) {
        if x < 0 || y < 0 || x >= self.w || y >= self.h || a <= 0.0 {
            return;
        }
        let i = ((y * self.w + x) * 4) as usize;
        let Some(px) = self.data.get_mut(i..i + 4) else {
            return;
        };
        let a = a.min(1.0);
        let inv = 1.0 - a;
        // premultiplied: dst = src*a + dst*(1-a); bytes are B, G, R, A
        let mix = |s: u8, d: u8| (f32::from(s) * a + f32::from(d) * inv).round().clamp(0.0, 255.0) as u8;
        if let [b, g, r, al] = px {
            *b = mix(c.2, *b);
            *g = mix(c.1, *g);
            *r = mix(c.0, *r);
            *al = (255.0 * a + f32::from(*al) * inv).round().clamp(0.0, 255.0) as u8;
        }
    }

    /// Anti-aliased filled rounded rectangle.
    pub fn round_rect(&mut self, x: f32, y: f32, w: f32, h: f32, r: f32, c: Rgb) {
        let (x0, y0) = (x.floor() as i32, y.floor() as i32);
        let (x1, y1) = ((x + w).ceil() as i32, (y + h).ceil() as i32);
        let r = r.min(w / 2.0).min(h / 2.0).max(0.0);
        for py in y0.max(0)..y1.min(self.h) {
            for px in x0.max(0)..x1.min(self.w) {
                let (cx, cy) = (px as f32 + 0.5, py as f32 + 0.5);
                // signed distance to the rounded rect
                let qx = (cx - (x + w / 2.0)).abs() - (w / 2.0 - r);
                let qy = (cy - (y + h / 2.0)).abs() - (h / 2.0 - r);
                let outside = (qx.max(0.0).powi(2) + qy.max(0.0).powi(2)).sqrt();
                let inside = qx.max(qy).min(0.0);
                let d = outside + inside - r;
                let cov = (0.5 - d).clamp(0.0, 1.0);
                self.blend(px, py, c, cov);
            }
        }
    }

    /// Draw text with its baseline at `y`; returns the advance.
    #[allow(clippy::too_many_arguments)]
    pub fn text(&mut self, fonts: &mut Fonts, bold: bool, x: f32, y: f32, px: f32, s: &str, c: Rgb) -> f32 {
        let mut pen = x;
        for ch in s.chars() {
            let (m, bitmap) = {
                let g = fonts.glyph(bold, ch, px);
                (g.0, g.1.clone())
            };
            self.glyph_at(pen, y, m, &bitmap, c);
            pen += m.advance_width;
        }
        pen - x
    }

    /// Like `text` (regular face), but rasterizes each glyph on the spot and
    /// drops it: used for a revealed passphrase, which must not end up in the
    /// glyph cache.
    pub fn secret_text(&mut self, fonts: &Fonts, x: f32, y: f32, px: f32, s: &str, c: Rgb) -> f32 {
        let mut pen = x;
        for ch in s.chars() {
            let (m, mut bitmap) = fonts.regular.rasterize(ch, px);
            self.glyph_at(pen, y, m, &bitmap, c);
            zeroize::Zeroize::zeroize(&mut bitmap);
            pen += m.advance_width;
        }
        pen - x
    }

    fn glyph_at(&mut self, pen: f32, y: f32, m: Metrics, bitmap: &[u8], c: Rgb) {
        let gx = (pen + m.xmin as f32).round() as i32;
        let gy = (y - m.ymin as f32 - m.height as f32).round() as i32;
        for row in 0..m.height {
            for col in 0..m.width {
                let cov = bitmap.get(row * m.width + col).copied().unwrap_or(0);
                if cov > 0 {
                    self.blend(gx + col as i32, gy + row as i32, c, f32::from(cov) / 255.0);
                }
            }
        }
    }
}
