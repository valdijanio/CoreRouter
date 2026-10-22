//! The GUI in a browser: which router to manage (from the page URL) and the
//! WebSocket backend that talks to it.
//!
//! - `?connect=ws://127.0.0.1:7980` — that daemon (`corerouter-daemon --ws`);
//! - `?lab` — the virtual lab, inside the page (nothing persists);
//! - neither — the connect screen, with "Connect to" set to the daemon that
//!   served the page (`ws(s)://<host>/ws`, the WebFig model with
//!   `corerouter-daemon --ws <port> --web-root <dist>`) and the Neighbors tab
//!   filled from that daemon's `ip.neighbor.list` (a browser cannot listen
//!   for CRDP itself). The Saved tab lives in `localStorage`.
//!
//! Browser events (open, message, close) only fill a queue; `poll` hands it
//! to the UI on its next frame.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::{Rc, Weak};

use corerouter_engine::{Session, shared};
use corerouter_ui::{
    Backend, ConnectScreen, CoreRouterUi, Link, NeighborRow, Reply, RequestId, SavedRouter,
};
use eframe::wasm_bindgen::JsCast as _;
use eframe::wasm_bindgen::closure::Closure;
use serde_json::{Value, json};
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

/// Milliseconds between reconnection attempts.
const RETRY_MS: f64 = 2000.0;

pub enum Choice {
    Lab,
    Connect(String),
    /// The connect screen; the WebSocket URL of the daemon that served the page.
    Screen(String),
}

/// `localStorage` key of the Saved tab.
const SAVED_KEY: &str = "corerouter.saved-routers";
/// Milliseconds between two `ip.neighbor.list` on the connect screen.
const NEIGHBORS_MS: f64 = 2000.0;

/// Read the page URL.
pub fn choice() -> Choice {
    let Some(location) = web_sys::window().map(|w| w.location()) else {
        return Choice::Lab;
    };
    let query = location
        .search()
        .ok()
        .and_then(|s| web_sys::UrlSearchParams::new_with_str(&s).ok());
    if let Some(q) = &query {
        if q.has("lab") {
            return Choice::Lab;
        }
        if let Some(url) = q.get("connect").filter(|u| !u.is_empty()) {
            return Choice::Connect(if url.contains("://") {
                url
            } else {
                format!("ws://{url}")
            });
        }
    }
    let secure = location.protocol().is_ok_and(|p| p == "https:");
    let host = location.host().unwrap_or_default();
    Choice::Screen(format!("{}://{host}/ws", if secure { "wss" } else { "ws" }))
}

/// `ws://…` for what the operator typed: a URL as is, `host:port` gets the
/// scheme and the `/ws` path of `corerouter-daemon --ws`.
fn ws_url(addr: &str) -> String {
    if addr.contains("://") {
        addr.to_owned()
    } else {
        format!("ws://{addr}/ws")
    }
}

/// The connect screen in the browser.
pub struct WebPlatform {
    /// Connection to the daemon that served the page, for its neighbor list.
    home: WsBackend,
    asked: Option<RequestId>,
    asked_at: f64,
    rows: Vec<NeighborRow>,
}

pub fn connect_screen(home: String) -> (ConnectScreen, WebPlatform) {
    let mut screen = ConnectScreen::new(load_saved());
    screen.connect_to = home.clone();
    screen.set_source(format!(
        "Neighbors of the router at {home} (ip.neighbor.list; a browser cannot listen \
         for announcements itself)"
    ));
    let platform = WebPlatform {
        home: WsBackend::new(home),
        asked: None,
        asked_at: f64::NEG_INFINITY,
        rows: Vec::new(),
    };
    (screen, platform)
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

fn load_saved() -> Vec<SavedRouter> {
    storage()
        .and_then(|s| s.get_item(SAVED_KEY).ok().flatten())
        .filter(|text| text.len() <= 1 << 20)
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .map(|v| SavedRouter::list_from_json(&v))
        .unwrap_or_default()
}

/// One `ip.neighbor.list` row of the home daemon as a Neighbors row; it is
/// reachable from the browser through its WebSocket port, if it has one.
fn neighbor_row(r: &Value) -> NeighborRow {
    let get = |k: &str| r.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let address = get("address");
    let ws = r
        .get("mgmt")
        .and_then(|m| m.get("ws"))
        .and_then(Value::as_u64);
    let host = if address.contains(':') {
        format!("[{address}]")
    } else {
        address.clone()
    };
    NeighborRow {
        key: format!(
            "{}/{}/{}",
            get("interface"),
            get("protocol"),
            r.get("node_id").and_then(Value::as_str).unwrap_or(&address)
        ),
        interface: get("interface"),
        protocol: get("protocol").to_uppercase(),
        address: address.clone(),
        mac: get("mac"),
        identity: get("identity"),
        version: get("version"),
        board: get("board"),
        uptime_secs: r.get("uptime_secs").and_then(Value::as_u64),
        connect_to: ws
            .filter(|_| !address.is_empty())
            .map(|p| format!("ws://{host}:{p}/ws")),
        // The WebSocket listens on loopback only until G0.3.
        remote: !address
            .parse::<std::net::IpAddr>()
            .is_ok_and(|a| a.is_loopback()),
    }
}

impl crate::Platform for WebPlatform {
    fn neighbors(&mut self) -> Vec<NeighborRow> {
        for (id, result) in self.home.poll() {
            if Some(id) != self.asked {
                continue;
            }
            self.asked = None;
            if let Ok(Value::Array(rows)) = result {
                self.rows = rows.iter().map(neighbor_row).collect();
            }
        }
        let now = js_sys::Date::now();
        if self.asked.is_none() && now - self.asked_at >= NEIGHBORS_MS {
            self.asked_at = now;
            self.asked = Some(
                self.home
                    .submit("engine.execute", json!({"command": "ip.neighbor.list"})),
            );
        }
        self.rows.clone()
    }

    fn store_saved(&mut self, saved: &[SavedRouter]) {
        let text = SavedRouter::list_to_json(saved).to_string();
        if let Some(s) = storage()
            && s.set_item(SAVED_KEY, &text).is_err()
        {
            log::error!("cannot keep the router list in localStorage");
        }
    }

    fn connect(&mut self, addr: &str) -> Result<CoreRouterUi, String> {
        let url = ws_url(addr);
        if !(url.starts_with("ws://") || url.starts_with("wss://")) {
            return Err(format!(
                "Connect to needs ws://HOST:PORT/ws or HOST:PORT, got '{addr}'"
            ));
        }
        // Auth/TLS are G0.3: the daemon only listens on loopback.
        log::info!("managing the router at {url}");
        Ok(CoreRouterUi::with_backend(Box::new(WsBackend::new(url))))
    }

    fn lab(&mut self) -> CoreRouterUi {
        CoreRouterUi::new(shared(Session::virtual_lab()))
    }
}

/// The socket and the callbacks it holds (dropped together).
struct Conn {
    ws: WebSocket,
    _on_open: Closure<dyn FnMut(Event)>,
    _on_message: Closure<dyn FnMut(MessageEvent)>,
    _on_close: Closure<dyn FnMut(CloseEvent)>,
}

struct State {
    url: String,
    link: Link,
    conn: Option<Conn>,
    /// A closed socket whose callbacks may still be running: dropped on the
    /// next `poll`, never from inside its own callback.
    dead: Option<Conn>,
    /// Sent on the socket, not answered yet.
    in_flight: BTreeSet<RequestId>,
    /// Submitted while the socket was still opening.
    outbox: Vec<(RequestId, String)>,
    replies: Vec<Reply>,
    retry_at: f64,
}

impl State {
    fn send(&mut self, id: RequestId, text: &str) {
        let sent = self.conn.as_ref().map(|c| c.ws.send_with_str(text));
        match sent {
            Some(Ok(())) => {
                self.in_flight.insert(id);
            }
            _ => self
                .replies
                .push((id, Err(format!("cannot send to {}", self.url)))),
        }
    }

    /// The socket is gone: everything waiting on it fails, retry later.
    fn lost(&mut self, reason: String) {
        if let Some(c) = self.conn.take() {
            self.dead = Some(c);
        }
        let msg = format!("connection to {} lost: {reason}", self.url);
        let waiting: Vec<RequestId> = std::mem::take(&mut self.in_flight)
            .into_iter()
            .chain(
                std::mem::take(&mut self.outbox)
                    .into_iter()
                    .map(|(id, _)| id),
            )
            .collect();
        for id in waiting {
            self.replies.push((id, Err(msg.clone())));
        }
        self.link = Link::Disconnected {
            target: self.url.clone(),
            reason,
        };
        self.retry_at = js_sys::Date::now() + RETRY_MS;
    }

    fn opened(&mut self) {
        self.link = Link::Connected {
            target: self.url.clone(),
        };
        for (id, text) in std::mem::take(&mut self.outbox) {
            self.send(id, &text);
        }
    }

    fn message(&mut self, text: &str) {
        let Ok(reply) = serde_json::from_str::<Value>(text) else {
            return;
        };
        let Some(id) = reply.get("id").and_then(Value::as_u64) else {
            return;
        };
        if !self.in_flight.remove(&id) {
            return;
        }
        let result = if reply.get("ok").and_then(Value::as_bool) == Some(true) {
            Ok(reply.get("result").cloned().unwrap_or(Value::Null))
        } else {
            Err(reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("unknown error")
                .to_owned())
        };
        self.replies.push((id, result));
    }
}

pub struct WsBackend {
    state: Rc<RefCell<State>>,
    next: RequestId,
}

impl WsBackend {
    pub fn new(url: String) -> Self {
        let me = Self {
            state: Rc::new(RefCell::new(State {
                link: Link::Connecting {
                    target: url.clone(),
                },
                url,
                conn: None,
                dead: None,
                in_flight: BTreeSet::new(),
                outbox: Vec::new(),
                replies: Vec::new(),
                retry_at: 0.0,
            })),
            next: 0,
        };
        me.connect();
        me
    }

    fn connect(&self) {
        let url = self.state.borrow().url.clone();
        let ws = match WebSocket::new(&url) {
            Ok(ws) => ws,
            Err(e) => {
                let why = e.as_string().unwrap_or_else(|| "invalid address".into());
                self.state.borrow_mut().lost(why);
                return;
            }
        };
        // Callbacks hold a weak handle: no cycle through the socket.
        let weak: Weak<RefCell<State>> = Rc::downgrade(&self.state);
        let w = weak.clone();
        let on_open = Closure::<dyn FnMut(Event)>::new(move |_| {
            if let Some(s) = w.upgrade() {
                s.borrow_mut().opened();
            }
        });
        let w = weak.clone();
        let on_message = Closure::<dyn FnMut(MessageEvent)>::new(move |e: MessageEvent| {
            if let (Some(s), Some(text)) = (w.upgrade(), e.data().as_string()) {
                s.borrow_mut().message(&text);
            }
        });
        let w = weak;
        let on_close = Closure::<dyn FnMut(CloseEvent)>::new(move |e: CloseEvent| {
            if let Some(s) = w.upgrade() {
                let why = match (e.code(), e.reason()) {
                    (_, r) if !r.is_empty() => r,
                    // 1006: refused, or the handshake failed (e.g. Origin not allowed).
                    (1006, _) => "no answer (is `corerouter-daemon --ws` running, \
                                  and is this page's origin allowed?)"
                        .into(),
                    (code, _) => format!("closed ({code})"),
                };
                s.borrow_mut().lost(why);
            }
        });
        ws.set_onopen(Some(on_open.as_ref().unchecked_ref()));
        ws.set_onmessage(Some(on_message.as_ref().unchecked_ref()));
        ws.set_onclose(Some(on_close.as_ref().unchecked_ref()));
        let mut s = self.state.borrow_mut();
        s.link = Link::Connecting {
            target: s.url.clone(),
        };
        s.conn = Some(Conn {
            ws,
            _on_open: on_open,
            _on_message: on_message,
            _on_close: on_close,
        });
    }
}

impl Backend for WsBackend {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        self.next = self.next.wrapping_add(1);
        let id = self.next;
        let text = json!({"id": id, "method": method, "params": params}).to_string();
        let mut s = self.state.borrow_mut();
        let ready = s.conn.as_ref().map(|c| c.ws.ready_state());
        match ready {
            Some(WebSocket::OPEN) => s.send(id, &text),
            Some(WebSocket::CONNECTING) => s.outbox.push((id, text)),
            _ => {
                let why = match &s.link {
                    Link::Disconnected { reason, .. } => reason.clone(),
                    _ => "not connected".into(),
                };
                let msg = format!("not connected to {}: {why}", s.url);
                s.replies.push((id, Err(msg)));
            }
        }
        id
    }

    fn poll(&mut self) -> Vec<Reply> {
        let retry = {
            let mut s = self.state.borrow_mut();
            s.dead = None;
            s.conn.is_none() && js_sys::Date::now() >= s.retry_at
        };
        if retry {
            self.connect();
        }
        std::mem::take(&mut self.state.borrow_mut().replies)
    }

    fn link(&self) -> Link {
        self.state.borrow().link.clone()
    }
}

impl Drop for WsBackend {
    fn drop(&mut self) {
        if let Some(c) = self.state.borrow_mut().conn.take() {
            let _ = c.ws.close();
        }
    }
}
