//! Files the UI hands over (Tools › Ping → Export CSV): written to disk by
//! the native app, offered as a browser download by the web one.

use corerouter_ui::{CoreRouterUi, Export};

/// Save every pending export and say where in the UI log.
pub fn save_all(ui: &mut CoreRouterUi) {
    for file in ui.take_exports() {
        match save(&file) {
            Ok(place) => ui.note(true, "export", format!("saved {place}")),
            Err(e) => ui.note(false, "export", format!("{}: {e}", file.file_name)),
        }
    }
}

/// Where native exports go: `$COREROUTER_EXPORT_DIR`, else `~/Downloads`
/// when it exists, else the current directory.
#[cfg(not(target_arch = "wasm32"))]
fn dir() -> std::path::PathBuf {
    use std::path::PathBuf;
    if let Some(d) = std::env::var_os("COREROUTER_EXPORT_DIR") {
        return PathBuf::from(d);
    }
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    if let Some(downloads) = home.map(|h| PathBuf::from(h).join("Downloads"))
        && downloads.is_dir()
    {
        return downloads;
    }
    PathBuf::from(".")
}

#[cfg(not(target_arch = "wasm32"))]
fn save(file: &Export) -> Result<String, String> {
    // The name comes from the UI ("ping-3.csv"); keep only its last part.
    let name = std::path::Path::new(&file.file_name)
        .file_name()
        .ok_or("no file name")?;
    save_in(&dir(), std::path::Path::new(name), &file.bytes)
}

/// Write `bytes` to a new file in `dir`: `name`, or `name-2`, `name-3`…
/// when it is taken. Never replaces a file (the counter in "ping-1.csv"
/// starts again with every run of the GUI).
#[cfg(not(target_arch = "wasm32"))]
fn save_in(dir: &std::path::Path, name: &std::path::Path, bytes: &[u8]) -> Result<String, String> {
    use std::io::Write as _;
    let stem = name
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("export");
    let ext = name.extension().and_then(|s| s.to_str());
    for n in 1..=1000u32 {
        let file = match (n, ext) {
            (1, _) => name.to_path_buf(),
            (_, Some(e)) => format!("{stem}-{n}.{e}").into(),
            (_, None) => format!("{stem}-{n}").into(),
        };
        let path = dir.join(file);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                f.write_all(bytes).map_err(|e| e.to_string())?;
                return Ok(path.display().to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Err(format!(
        "{}: 1000 files of that name already",
        name.display()
    ))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn a_second_export_never_replaces_the_first() {
        let dir = std::env::temp_dir().join(format!("cr-export-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let name = std::path::Path::new("ping-1.csv");
        let a = save_in(&dir, name, b"first").unwrap();
        let b = save_in(&dir, name, b"second").unwrap();
        assert_ne!(a, b);
        assert_eq!(std::fs::read(&a).unwrap(), b"first");
        assert_eq!(std::fs::read(&b).unwrap(), b"second");
        assert!(b.ends_with("ping-1-2.csv"), "{b}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

#[cfg(target_arch = "wasm32")]
fn save(file: &Export) -> Result<String, String> {
    use eframe::wasm_bindgen::JsCast as _;
    let err = |e: eframe::wasm_bindgen::JsValue| format!("{e:?}");
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(file.bytes.as_slice()));
    let opts = web_sys::BlobPropertyBag::new();
    opts.set_type(file.mime);
    let blob = web_sys::Blob::new_with_u8_array_sequence_and_options(&parts, &opts).map_err(err)?;
    let url = web_sys::Url::create_object_url_with_blob(&blob).map_err(err)?;
    let document = web_sys::window()
        .and_then(|w| w.document())
        .ok_or("no document")?;
    let a: web_sys::HtmlAnchorElement = document
        .create_element("a")
        .map_err(err)?
        .dyn_into()
        .map_err(|_| "not an anchor".to_owned())?;
    a.set_href(&url);
    a.set_download(&file.file_name);
    a.click();
    web_sys::Url::revoke_object_url(&url).map_err(err)?;
    Ok(format!("{} (download)", file.file_name))
}
