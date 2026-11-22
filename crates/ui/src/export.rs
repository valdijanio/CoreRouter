//! Saving what a window exports (G4.5: a graph's CSV and PNG). The UI does
//! no I/O (it runs in the browser too): the app installs a [`SaveFile`] in
//! the egui context ([`install`]); without one (wasm, tests) the text goes
//! to the clipboard and the image too.

use std::sync::Arc;

use egui::{ColorImage, Context, Id};

/// What is exported.
pub enum Export {
    Text(String),
    Image(ColorImage),
}

/// Save `export` under a file name like `graph-ether1-day.csv`; returns
/// where it went (shown to the operator) or why it could not.
pub type SaveFile = Arc<dyn Fn(&str, Export) -> Result<String, String> + Send + Sync>;

fn key() -> Id {
    Id::unique("corerouter-export-save-file")
}

/// The app's way of saving files (native: the Downloads folder).
pub fn install(ctx: &Context, save: SaveFile) {
    ctx.data_mut(|d| d.insert_temp(key(), save));
}

/// Save, or copy when the app has no saver. Returns what to tell the
/// operator.
pub(crate) fn save(ctx: &Context, name: &str, export: Export) -> Result<String, String> {
    match ctx.data(|d| d.get_temp::<SaveFile>(key())) {
        Some(f) => f(name, export),
        None => {
            match export {
                Export::Text(t) => ctx.copy_text(t),
                Export::Image(i) => ctx.copy_image(i),
            }
            Ok("copied to the clipboard".into())
        }
    }
}

/// Read a file the operator names (G4.3n: PPP › Secrets › Import from
/// MikroTik); the app's way, as [`SaveFile`] for saving.
pub type OpenFile = Arc<dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync>;

fn open_key() -> Id {
    Id::unique("corerouter-export-open-file")
}

/// The app's way of reading files (native: the local disk).
pub fn install_open(ctx: &Context, open: OpenFile) {
    ctx.data_mut(|d| d.insert_temp(open_key(), open));
}

/// The bytes of `path`, or why not (no reader here: the browser, tests).
pub(crate) fn open(ctx: &Context, path: &str) -> Result<Vec<u8>, String> {
    if path.trim().is_empty() {
        return Err("type the file's path, drop the file on the window or paste it".into());
    }
    match ctx.data(|d| d.get_temp::<OpenFile>(open_key())) {
        Some(f) => f(path),
        None => Err("files cannot be read here: drop the file on the window or paste it".into()),
    }
}

/// Bytes per upload chunk until the router says otherwise.
pub(crate) const UPLOAD_CHUNK: usize = 1 << 20;

/// A piece of a file the operator names (G1.6e: System › Packages sends a
/// package of tens of MiB in chunks, never whole in memory): up to `len`
/// bytes at `offset`, and the file's size.
pub type ReadAt = Arc<dyn Fn(&str, u64, usize) -> Result<(Vec<u8>, u64), String> + Send + Sync>;

fn read_at_key() -> Id {
    Id::unique("corerouter-export-read-at")
}

/// The app's way of reading pieces of files (native: the local disk).
pub fn install_read_at(ctx: &Context, read: ReadAt) {
    ctx.data_mut(|d| d.insert_temp(read_at_key(), read));
}

/// Up to `len` bytes of `path` at `offset`, and its size; or why not (the
/// browser has no reader).
pub(crate) fn read_at(
    ctx: &Context,
    path: &str,
    offset: u64,
    len: usize,
) -> Result<(Vec<u8>, u64), String> {
    if path.trim().is_empty() {
        return Err("type the file's path or drop the file on the window".into());
    }
    match ctx.data(|d| d.get_temp::<ReadAt>(read_at_key())) {
        Some(f) => f(path, offset, len),
        None => Err("files of this computer cannot be read here (browser): copy the package to the router, or use corerouter-cli upload".into()),
    }
}

/// The saver of `ctx`, to call from a screenshot callback (another thread).
pub(crate) fn saver(ctx: &Context) -> Option<SaveFile> {
    ctx.data(|d| d.get_temp::<SaveFile>(key()))
}

/// The part of `img` under `rect` (points), clamped to the image.
pub(crate) fn crop(img: &ColorImage, rect: egui::Rect, pixels_per_point: f32) -> ColorImage {
    let [w, h] = img.size;
    let px = |v: f32, max: usize| ((v * pixels_per_point).max(0.0) as usize).min(max);
    let (x0, x1) = (px(rect.min.x, w), px(rect.max.x, w));
    let (y0, y1) = (px(rect.min.y, h), px(rect.max.y, h));
    let (cw, ch) = (x1.saturating_sub(x0), y1.saturating_sub(y0));
    let mut pixels = Vec::with_capacity(cw * ch);
    for y in y0..y1 {
        if let Some(row) = img.pixels.get(y * w + x0..y * w + x0 + cw) {
            pixels.extend_from_slice(row);
        }
    }
    if pixels.len() != cw * ch {
        return ColorImage::new([0, 0], Vec::new());
    }
    ColorImage::new([cw, ch], pixels)
}
