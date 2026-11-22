//! The router's CRDP node id: 128 random bits generated on first boot and
//! kept next to the config (`<config-dir>/node-id`, 32 hex digits), so
//! neighbors and saved connections recognise the router across restarts,
//! address changes and identity changes. Without a config dir it lives only
//! as long as the process.

use std::collections::hash_map::RandomState;
use std::fs;
use std::hash::{BuildHasher, Hasher};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use corerouter_discovery::NodeId;

pub const FILE: &str = "node-id";

/// 128 bits from the OS: every `RandomState` is seeded from the system's
/// random source, so no extra dependency is needed.
pub fn random() -> NodeId {
    let mut out = [0u8; 16];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = RandomState::new().build_hasher();
        h.write_usize(i);
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
        );
        h.write_u32(std::process::id());
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    if out == [0; 16] {
        out[15] = 1;
    }
    NodeId(out)
}

/// The id stored in `dir`, or a new one saved there. A missing or damaged
/// file gets a new id (logged); a file that cannot be written leaves the id
/// valid for this run only.
pub fn load_or_create(dir: Option<&Path>) -> NodeId {
    let Some(dir) = dir else {
        return random();
    };
    let path = dir.join(FILE);
    match fs::read_to_string(&path) {
        Ok(text) if text.len() <= 64 => match text.parse::<NodeId>() {
            Ok(id) => return id,
            Err(e) => log::warn!("{}: {e}; generating a new node id", path.display()),
        },
        Ok(_) => log::warn!("{} is too long; generating a new node id", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log::warn!(
            "cannot read {}: {e}; generating a new node id",
            path.display()
        ),
    }
    let id = random();
    let tmp = dir.join(format!("{FILE}.tmp"));
    let saved = fs::File::create(&tmp)
        .and_then(|mut f| {
            writeln!(f, "{id}")?;
            f.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, &path));
    match saved {
        Ok(()) => log::info!("new node id {id} saved to {}", path.display()),
        Err(e) => log::error!(
            "cannot save the node id to {}: {e}; it changes on restart",
            path.display()
        ),
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_random_and_survive_a_restart() {
        assert_ne!(random(), random());
        let dir = std::env::temp_dir().join(format!("crdp-node-id-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let a = load_or_create(Some(&dir));
        assert_eq!(load_or_create(Some(&dir)), a);
        fs::write(dir.join(FILE), "garbage").unwrap();
        let b = load_or_create(Some(&dir));
        assert_ne!(b, a);
        assert_eq!(load_or_create(Some(&dir)), b);
        fs::remove_dir_all(&dir).unwrap();
    }
}
