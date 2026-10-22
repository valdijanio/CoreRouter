//! `/ip dns adlist` (G4.1d): downloads the block lists and hands their
//! names to the LAN forwarder (`proto-dns`, stage `adlist`).
//!
//! One thread follows the running config. A list is loaded when it is
//! added or changed, every [`REFRESH`] after that (RouterOS checks every 4
//! hours), and on `ip.dns.adlist.reload`. Downloading, parsing and sorting
//! a list of hundreds of thousands of names happens here, never under the
//! session lock; the forwarder sees the new names in one swap. A failed
//! download keeps the names it had and is tried again after [`RETRY`].
//!
//! Hostile input: the body is capped at [`MAX_BYTES`], all lists together
//! at [`MAX_NAMES`] names (about 30 bytes each in memory), and the text is
//! parsed line by line with every name checked (`proto-dns`, `adlist.rs`).
//! A `file` list is read from `--adlist-dir` only (a file name, never a
//! path: the config checks it).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::dns_adlist::{AdlistBackend, AdlistStatus};
use corerouter_engine::{Shared, lock};
use corerouter_model::ItemId;
use corerouter_model::dns_adlist::AdlistEntry;
use corerouter_proto_dns::adlist::{Adlists, Loaded, parse};

/// How often a loaded list is fetched again.
pub(crate) const REFRESH: Duration = Duration::from_secs(4 * 3600);
/// How soon a failed list is tried again.
pub(crate) const RETRY: Duration = Duration::from_secs(600);
/// Largest list downloaded or read (the biggest public lists are ~30 MB).
pub(crate) const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Names of all lists together (~60 MB of memory).
pub(crate) const MAX_NAMES: usize = 2_000_000;
/// One download, redirects included.
const TIMEOUT: Duration = Duration::from_secs(120);
const TICK: Duration = Duration::from_secs(1);

/// What the loader knows of one list.
struct List {
    entry: AdlistEntry,
    state: &'static str,
    loaded: Option<Arc<Loaded>>,
    skipped: u64,
    loaded_at: Option<Instant>,
    error: Option<String>,
    due: Instant,
}

#[derive(Default)]
struct State {
    lists: BTreeMap<ItemId, List>,
    /// `ip.dns.adlist.reload`: these now (`None`: every list).
    reload: BTreeSet<Option<ItemId>>,
}

/// Host names to addresses.
type Resolve = dyn Fn(&str) -> Result<Vec<std::net::IpAddr>, String> + Send + Sync;

/// Where lists come from, and where their names go.
pub(crate) struct Loader {
    state: Mutex<State>,
    wake: Condvar,
    dir: Option<PathBuf>,
    /// Host names of `url` lists (the router's resolver in the daemon).
    resolve: Box<Resolve>,
    /// The forwarder's lists (absent until the forwarder started).
    target: Box<dyn Fn() -> Option<Arc<Adlists>> + Send + Sync>,
}

impl Loader {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The running config's lists: new and changed ones are due now, gone
    /// ones are dropped.
    fn follow(&self, entries: &[AdlistEntry], now: Instant) -> bool {
        let mut st = self.state();
        let before = st.lists.len();
        st.lists.retain(|id, _| entries.iter().any(|e| e.id == *id));
        let mut changed = st.lists.len() != before;
        for e in entries {
            match st.lists.get_mut(&e.id) {
                Some(l) if l.entry == *e => {}
                Some(l) => {
                    let same_source = l.entry.source() == e.source() && l.entry.ssl_verify == e.ssl_verify;
                    l.entry = e.clone();
                    if !same_source {
                        l.loaded = None;
                        l.loaded_at = None;
                        l.due = now;
                    }
                    if e.disabled {
                        l.state = "off";
                    } else if l.loaded.is_none() {
                        l.state = "waiting";
                        l.due = now;
                    }
                    changed = true;
                }
                None => {
                    st.lists.insert(
                        e.id,
                        List {
                            entry: e.clone(),
                            state: if e.disabled { "off" } else { "waiting" },
                            loaded: None,
                            skipped: 0,
                            loaded_at: None,
                            error: None,
                            due: now,
                        },
                    );
                    changed = true;
                }
            }
        }
        changed
    }

    /// The next list to load now, marked `loading`.
    fn next_due(&self, now: Instant) -> Option<(AdlistEntry, usize)> {
        let mut st = self.state();
        let all = st.reload.remove(&None);
        let asked: Vec<ItemId> = std::mem::take(&mut st.reload).into_iter().flatten().collect();
        for (id, l) in st.lists.iter_mut() {
            if all || asked.contains(id) {
                l.due = now;
            }
        }
        let id = st
            .lists
            .iter()
            .filter(|(_, l)| !l.entry.disabled && l.due <= now)
            .min_by_key(|(_, l)| l.due)
            .map(|(id, _)| *id)?;
        // The names the others hold count against the ceiling.
        let others: usize = st
            .lists
            .iter()
            .filter(|(i, l)| **i != id && !l.entry.disabled)
            .filter_map(|(_, l)| l.loaded.as_ref().map(|x| x.len()))
            .sum();
        let l = st.lists.get_mut(&id)?;
        l.state = "loading";
        // Not picked again while it loads.
        l.due = now + REFRESH;
        Some((l.entry.clone(), MAX_NAMES.saturating_sub(others)))
    }

    fn fetch(&self, e: &AdlistEntry) -> Result<String, String> {
        let bytes = if e.url.is_empty() {
            let dir = self
                .dir
                .as_ref()
                .ok_or("file lists need the daemon's --adlist-dir")?;
            let path = dir.join(&e.file);
            let meta = std::fs::metadata(&path).map_err(|err| format!("{}: {err}", e.file))?;
            if meta.len() > MAX_BYTES as u64 {
                return Err(format!("{}: larger than {MAX_BYTES} bytes", e.file));
            }
            std::fs::read(&path).map_err(|err| format!("{}: {err}", e.file))?
        } else {
            super::https::get(&e.url, e.ssl_verify, MAX_BYTES, TIMEOUT, &*self.resolve)?
        };
        // Lists are ASCII; a stray byte must not cost the whole list.
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Loads one list and publishes the result.
    fn load(&self, e: &AdlistEntry, budget: usize) {
        let result = self.fetch(e).map(|text| parse(&text, budget));
        let now = Instant::now();
        {
            let mut st = self.state();
            let Some(l) = st.lists.get_mut(&e.id) else {
                return;
            };
            if l.entry.source() != e.source() {
                // Changed while it loaded: the new source is due already.
                return;
            }
            match result {
                Ok(parsed) => {
                    let truncated = parsed.truncated;
                    l.skipped = parsed.skipped as u64;
                    let loaded = Loaded::new(e.id.0, parsed);
                    // The counter goes on across refreshes of the same list.
                    if let Some(old) = &l.loaded {
                        loaded
                            .hits
                            .store(old.hits.load(Ordering::Relaxed), Ordering::Relaxed);
                    }
                    log::info!("DNS adlist {}: {} names from {}", e.id, loaded.len(), e.source());
                    l.loaded = Some(Arc::new(loaded));
                    l.loaded_at = Some(now);
                    l.state = "loaded";
                    l.error = truncated.then(|| {
                        format!("only the first names kept: all lists together hold at most {MAX_NAMES}")
                    });
                    l.due = now + REFRESH;
                }
                Err(why) => {
                    let why: String = why.chars().take(300).collect();
                    log::warn!("DNS adlist {}: {} not loaded: {why}", e.id, e.source());
                    l.state = "failed";
                    l.error = Some(why);
                    l.due = now + RETRY;
                }
            }
        }
        self.publish();
    }

    /// Hands the enabled, loaded lists to the forwarder.
    fn publish(&self) {
        let Some(target) = (self.target)() else {
            return;
        };
        let lists: Vec<Arc<Loaded>> = self
            .state()
            .lists
            .values()
            .filter(|l| !l.entry.disabled)
            .filter_map(|l| l.loaded.clone())
            .collect();
        target.set(lists);
    }

    /// One pass: follow the config, load what is due.
    fn step(&self, entries: &[AdlistEntry]) {
        if self.follow(entries, Instant::now()) {
            self.publish();
        }
        while let Some((e, budget)) = self.next_due(Instant::now()) {
            self.load(&e, budget);
        }
    }
}

impl AdlistBackend for Loader {
    fn status(&self) -> Vec<AdlistStatus> {
        self.state()
            .lists
            .iter()
            .map(|(id, l)| AdlistStatus {
                id: Some(*id),
                state: l.state,
                name_count: l.loaded.as_ref().map_or(0, |x| x.len() as u64),
                match_count: l.loaded.as_ref().map_or(0, |x| x.hits.load(Ordering::Relaxed)),
                skipped: l.skipped,
                loaded_secs_ago: l.loaded_at.map(|t| t.elapsed().as_secs()),
                error: l.error.clone(),
            })
            .collect()
    }

    fn reload(&self, id: Option<ItemId>) {
        self.state().reload.insert(id);
        self.wake.notify_all();
    }
}

/// Starts the loader: registered in the session, following its config.
pub(crate) fn spawn(session: Shared, loader: Arc<Loader>) -> std::io::Result<()> {
    lock(&session).set_adlist_backend(loader.clone());
    thread::Builder::new().name("dns-adlist".into()).spawn(move || {
        loop {
            let entries = lock(&session).store().running().ip.dns_adlist.entries.clone();
            loader.step(&entries);
            let st = loader.state();
            if st.reload.is_empty() {
                let _ = loader.wake.wait_timeout(st, TICK);
            }
        }
    })?;
    Ok(())
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns adlist",
    flags: &[super::Flag {
        name: "--adlist-dir",
        value: Some("<dir>"),
        help: "where /ip dns adlist file=… lists are read from",
    }],
    start,
};

fn start(ctx: &super::Ctx) -> Result<(), String> {
    let session = ctx.session.clone();
    let loader = Arc::new(Loader {
        state: Mutex::default(),
        wake: Condvar::new(),
        dir: ctx.flag("--adlist-dir").map(PathBuf::from),
        resolve: Box::new(move |host| super::dns::resolve(&session, host)),
        target: Box::new(super::dns_server::adlists),
    });
    if let Err(e) = spawn(ctx.session.clone(), loader) {
        log::error!("DNS adlist is off: cannot start its thread: {e}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use serde_json::json;

    fn loader(dir: Option<PathBuf>, target: Arc<Adlists>) -> Arc<Loader> {
        Arc::new(Loader {
            state: Mutex::default(),
            wake: Condvar::new(),
            dir,
            resolve: Box::new(|_| Ok(vec!["127.0.0.1".parse().unwrap()])),
            target: Box::new(move || Some(target.clone())),
        })
    }

    #[test]
    fn loads_url_and_file_lists_and_follows_the_config() {
        let dir = std::env::temp_dir().join(format!("cr-adlist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("local.txt"), "0.0.0.0 file.example\nbroken line here\n").unwrap();
        let body = "# list\n0.0.0.0 ads.example\n||track.example^\n";
        let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        let port = super::super::https::tests::serve(vec![reply.into_bytes(); 2]);
        let target = Arc::new(Adlists::default());
        let l = loader(Some(dir.clone()), target.clone());
        let session = shared(Session::virtual_lab());
        lock(&session).set_adlist_backend(l.clone());
        let run = |p: serde_json::Value| lock(&session).execute("ip.dns.adlist.add", &p).unwrap();
        run(json!({"url": format!("http://lists.test:{port}/hosts")}));
        run(json!({"file": "local.txt"}));
        run(json!({"file": "missing.txt"}));
        let entries = || lock(&session).store().running().ip.dns_adlist.entries.clone();
        l.step(&entries());
        assert!(target.find("ads.example").is_some());
        assert!(target.find("x.track.example").is_some());
        assert!(target.find("file.example").is_some());
        let rows = lock(&session).execute("ip.dns.adlist.print", &json!({})).unwrap();
        assert_eq!((rows[0]["state"].as_str(), rows[0]["name_count"].as_u64()), (Some("loaded"), Some(2)));
        assert_eq!((rows[1]["name_count"].as_u64(), rows[1]["skipped"].as_u64()), (Some(1), Some(1)));
        assert_eq!(rows[2]["state"], "failed");
        assert!(rows[2]["error"].as_str().unwrap().contains("missing.txt"));
        // Disabling takes the names out at once; reload fetches again.
        lock(&session)
            .execute("ip.dns.adlist.set", &json!({"id": "*2", "disabled": true}))
            .unwrap();
        l.step(&entries());
        assert!(target.find("file.example").is_none());
        target.find("ads.example").unwrap().hits.fetch_add(3, Ordering::Relaxed);
        lock(&session).execute("ip.dns.adlist.reload", &json!({"id": "*1"})).unwrap();
        l.step(&entries());
        let rows = lock(&session).execute("ip.dns.adlist.print", &json!({})).unwrap();
        assert_eq!(rows[0]["match_count"], 3, "kept across a reload");
        assert_eq!(rows[1]["state"], "off");
        lock(&session).execute("ip.dns.adlist.remove", &json!({"id": "*1"})).unwrap();
        l.step(&entries());
        assert!(target.find("ads.example").is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn the_name_ceiling_spans_every_list() {
        let dir = std::env::temp_dir().join(format!("cr-adlist-max-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), "a.example\nb.example\n").unwrap();
        let target = Arc::new(Adlists::default());
        let l = loader(Some(dir.clone()), target.clone());
        let mut e = AdlistEntry::new(ItemId(1));
        e.file = "a.txt".into();
        l.follow(std::slice::from_ref(&e), Instant::now());
        let (entry, budget) = l.next_due(Instant::now()).unwrap();
        assert_eq!(budget, MAX_NAMES);
        l.load(&entry, 1);
        let st = l.status();
        assert_eq!(st[0].name_count, 1);
        assert!(st[0].error.as_deref().unwrap().contains("at most"));
        assert!(l.next_due(Instant::now()).is_none(), "next refresh in 4 h");
        let _ = std::fs::remove_dir_all(dir);
    }
}
