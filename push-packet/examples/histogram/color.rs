use std::{
    hash::{DefaultHasher, Hash, Hasher},
    time::Instant,
};

use ratatui::style::Color;

pub fn ip_color<T: Hash>(value: &T) -> Color {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    let output = hasher.finish();

    let bytes = output.to_le_bytes();
    let r = bytes[0];
    let g = bytes[1];
    let b = bytes[3];
    let pick = bytes[3] % 3;
    if pick == 0 {
        Color::Rgb(255, g, b)
    } else if pick == 1 {
        Color::Rgb(r, 255, b)
    } else {
        Color::Rgb(r, g, 255)
    }
}

pub fn fade(base_color: Color, last: Instant, window: usize) -> Color {
    let Color::Rgb(r, g, b) = base_color else {
        return base_color;
    };
    let t = (last.elapsed().as_secs_f32() / window as f32).clamp(0.0, 1.0);
    const BG: (f32, f32, f32) = (8.0, 8.0, 8.0);
    let alpha = 0.9 - 0.7 * t;
    let blend = |fg: u8, bg: f32| (alpha * fg as f32 + (1.0 - alpha) * bg) as u8;
    Color::Rgb(blend(r, BG.0), blend(g, BG.1), blend(b, BG.2))
}

pub fn text_color(bg: Color) -> Color {
    let Color::Rgb(r, g, b) = bg else {
        return bg;
    };
    let bg_lum = 0.299 * r as f32 + 0.587 * g as f32 + 0.114 * b as f32;
    const MIN_DISTANCE: f32 = 85.0;
    let mut target_lum = 255.0 - bg_lum;
    if (target_lum - bg_lum).abs() < MIN_DISTANCE {
        target_lum = if bg_lum < 128.0 {
            bg_lum + MIN_DISTANCE
        } else {
            bg_lum - MIN_DISTANCE
        };
    }
    target_lum = target_lum.clamp(0.0, 255.0);
    let (ir, ig, ib) = (255 - r, 255 - b, 255 - g);
    let inv_lum = 0.299 * ir as f32 + 0.587 * ig as f32 + 0.114 * ib as f32;
    if inv_lum < 1.0 {
        let v = target_lum as u8;
        return Color::Rgb(v, v, v);
    }
    let scale = target_lum / inv_lum;
    let s = |c: u8| (c as f32 * scale).clamp(0.0, 255.0) as u8;
    Color::Rgb(s(ir), s(ig), s(ib))
}
