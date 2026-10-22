//! The GUI in a browser: which router to manage (from the page URL) and the
//! WebSocket backend that talks to it.
//!
//! - `?connect=ws://127.0.0.1:7980` — that daemon (`corerouter-daemon --ws`);
//! - `?lab` — the virtual lab, inside the page (nothing persists);
//! - neither — the daemon that served the page (`ws(s)://<host>/ws`, the
//!   WebFig model with `corerouter-daemon --ws <port> --web-root <dist>`).
//!
//! Browser events (open, message, close) only fill a queue; `poll` hands it
//! to the UI on its next frame.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::{Rc, Weak};

use corerouter_ui::{Backend, Link, Reply, RequestId};
use eframe::wasm_bindgen::JsCast as _;
use eframe::wasm_bindgen::closure::Closure;
use serde_json::{Value, json};
use web_sys::{CloseEvent, Event, MessageEvent, WebSocket};

/// Milliseconds between reconnection attempts.
const RETRY_MS: f64 = 2000.0;

pub enum Choice {
    Lab,
    Connect(String),
}

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
    Choice::Connect(format!("{}://{host}/ws", if secure { "wss" } else { "ws" }))
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
