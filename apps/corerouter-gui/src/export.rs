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
    let path = dir().join(name);
    std::fs::write(&path, &file.bytes).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
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
