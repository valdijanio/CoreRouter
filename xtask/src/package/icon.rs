//! The application icon (G0.28), drawn by code: a rounded blue square with a
//! ring and four arrows pointing out (the usual router symbol). One geometry,
//! two outputs: an SVG for `hicolor/scalable` and PNGs rasterized here with
//! 4×4 supersampling for the fixed sizes. No third-party artwork.

/// Sizes of the `hicolor/<n>x<n>/apps` PNGs.
pub const SIZES: &[u32] = &[16, 24, 32, 48, 64, 128, 256, 512];

/// The drawing is laid out on a 256-unit square.
const UNITS: f32 = 256.0;
const TOP: [f32; 3] = [0x1e as f32, 0x88 as f32, 0xe5 as f32];
const BOTTOM: [f32; 3] = [0x0d as f32, 0x47 as f32, 0xa1 as f32];
const ARROW_ANGLES: [f32; 4] = [45.0, 135.0, 225.0, 315.0];

pub fn svg() -> String {
    let arrows: String = ARROW_ANGLES
        .iter()
        .map(|a| {
            format!(
                "  <path d=\"M54 -8H88V-22L114 0L88 22V8H54Z\" \
                 transform=\"translate(128 128) rotate({a})\"/>\n"
            )
        })
        .collect();
    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 256 256\">\n\
         <defs><linearGradient id=\"g\" x1=\"0\" y1=\"0\" x2=\"0\" y2=\"1\">\
         <stop offset=\"0\" stop-color=\"#1e88e5\"/><stop offset=\"1\" stop-color=\"#0d47a1\"/>\
         </linearGradient></defs>\n\
         <rect x=\"8\" y=\"8\" width=\"240\" height=\"240\" rx=\"48\" fill=\"url(#g)\"/>\n\
         <circle cx=\"128\" cy=\"128\" r=\"38\" fill=\"none\" stroke=\"#fff\" stroke-width=\"16\"/>\n\
         <g fill=\"#fff\">\n{arrows}</g>\n</svg>\n"
    )
}

/// Inside the rounded square (8..248, corner radius 48)?
fn in_square(x: f32, y: f32) -> bool {
    let (lo, hi, r) = (8.0, 248.0, 48.0);
    if !(lo..=hi).contains(&x) || !(lo..=hi).contains(&y) {
        return false;
    }
    let cx = x.clamp(lo + r, hi - r);
    let cy = y.clamp(lo + r, hi - r);
    (x - cx).powi(2) + (y - cy).powi(2) <= r * r
}

/// Inside the white ring or one of the arrows?
fn in_mark(x: f32, y: f32) -> bool {
    let (dx, dy) = (x - 128.0, y - 128.0);
    let r = (dx * dx + dy * dy).sqrt();
    if (30.0..=46.0).contains(&r) {
        return true;
    }
    ARROW_ANGLES.iter().any(|a| {
        let (s, c) = a.to_radians().sin_cos();
        // Into the arrow's own frame (the inverse of SVG's rotate).
        let lx = dx * c + dy * s;
        let ly = -dx * s + dy * c;
        let shaft = (54.0..=88.0).contains(&lx) && ly.abs() <= 8.0;
        let head = (88.0..=114.0).contains(&lx) && ly.abs() <= 22.0 * (114.0 - lx) / 26.0;
        shaft || head
    })
}

/// The icon as straight-alpha RGBA, `size`×`size`.
pub fn rgba(size: u32) -> Vec<u8> {
    const SS: u32 = 4;
    let scale = UNITS / size as f32;
    let mut out = Vec::with_capacity((size * size * 4) as usize);
    for py in 0..size {
        for px in 0..size {
            // Premultiplied sums over the subsamples.
            let mut acc = [0.0f32; 4];
            for sy in 0..SS {
                for sx in 0..SS {
                    let x = (px as f32 + (sx as f32 + 0.5) / SS as f32) * scale;
                    let y = (py as f32 + (sy as f32 + 0.5) / SS as f32) * scale;
                    if !in_square(x, y) {
                        continue;
                    }
                    let rgb = if in_mark(x, y) {
                        [255.0; 3]
                    } else {
                        let t = ((y - 8.0) / 240.0).clamp(0.0, 1.0);
                        [0, 1, 2].map(|i| {
                            TOP.get(i).copied().unwrap_or(0.0) * (1.0 - t)
                                + BOTTOM.get(i).copied().unwrap_or(0.0) * t
                        })
                    };
                    for (a, v) in acc.iter_mut().zip(rgb.iter().chain([255.0].iter())) {
                        *a += v;
                    }
                }
            }
            let n = (SS * SS) as f32;
            let [r, g, b, a] = acc;
            let alpha = a / n;
            for v in [r, g, b] {
                // Back to straight alpha.
                let c = if alpha > 0.0 {
                    v / n * 255.0 / alpha
                } else {
                    0.0
                };
                out.push(c.round().clamp(0.0, 255.0) as u8);
            }
            out.push(alpha.round().clamp(0.0, 255.0) as u8);
        }
    }
    out
}

pub fn png(size: u32) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, size, size);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut w = enc.write_header().map_err(|e| format!("png: {e}"))?;
        w.write_image_data(&rgba(size))
            .map_err(|e| format!("png: {e}"))?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icon_has_a_transparent_corner_a_blue_body_and_a_white_mark() {
        let size = 64;
        let px = |x: u32, y: u32| {
            let i = ((y * size + x) * 4) as usize;
            rgba(size)[i..i + 4].to_vec()
        };
        assert_eq!(px(0, 0)[3], 0, "corner outside the rounded square");
        let body = px(32, 6);
        assert!(body[3] == 255 && body[2] > body[0], "blue body: {body:?}");
        // On the ring (radius 38 of 256 → ~9.5 px from the centre).
        let ring = px(32 + 9, 32);
        assert!(ring.iter().all(|&c| c > 230), "white ring: {ring:?}");
        let decoded = png::Decoder::new(std::io::Cursor::new(png(16).unwrap()))
            .read_info()
            .unwrap();
        assert_eq!(decoded.info().width, 16);
        assert!(svg().starts_with("<svg") && svg().contains("rotate(315)"));
    }
}
