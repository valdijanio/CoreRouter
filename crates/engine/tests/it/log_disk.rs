//! G4.6g: the log files come back at boot and are hostile input.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_engine::log_disk::{MAX_LINE, decode, decode_all, encode, file_name, file_number};
use corerouter_engine::{Session, logging::LogBook};
use corerouter_model::logging::{LogEvent, TOPICS};
use proptest::prelude::*;
use serde_json::{Value, json};

fn event(message: &str) -> LogEvent {
    LogEvent {
        seq: 9,
        time: 1_700_000_000,
        topics: vec!["system".into(), "warning".into()],
        origin: "admin · GUI".into(),
        message: message.into(),
        detail: json!({"command": "x", "params": {"a": 1}}),
    }
}

#[test]
fn a_line_comes_back_as_it_went_without_its_number() {
    let line = encode(&event("Falhou: «ação»")).unwrap();
    assert!(line.ends_with('\n'));
    assert_eq!(line.matches('\n').count(), 1, "one line");
    let mut back = decode(line.trim_end().as_bytes()).unwrap();
    assert_eq!(back.seq, 0);
    back.seq = 9;
    assert_eq!(back, event("Falhou: «ação»"));
}

#[test]
fn an_oversized_event_is_not_written() {
    assert!(encode(&event(&"x".repeat(MAX_LINE))).is_none());
}

/// What a crash and a bad flash leave: the good lines are kept.
#[test]
fn torn_and_damaged_lines_cost_only_themselves() {
    let good = encode(&event("boa")).unwrap();
    let mut text = Vec::new();
    text.extend_from_slice(good.as_bytes());
    text.extend_from_slice(b"\xff\xfe not json\n");
    text.extend_from_slice(b"\n");
    text.extend_from_slice(b"{\"time\":1,\"topics\":[\"nope\"],\"message\":\"x\"}\n");
    text.extend_from_slice(b"{\"time\":1,\"topics\":[],\"message\":\"x\"}\n");
    text.extend_from_slice(good.as_bytes());
    text.extend_from_slice(&good.as_bytes()[..good.len() / 2]);
    let (events, bad) = decode_all(&text);
    assert_eq!(events.len(), 2);
    assert_eq!(bad, 3, "the torn last line is a crash, not damage");
}

/// A hand-edited file cannot put escapes on the operator's terminal.
#[test]
fn what_comes_back_is_clean_and_bounded() {
    let line = json!({"time": 1, "topics": ["info"], "origin": "a\u{1b}[31m\nb",
        "message": format!("m\u{1b}]0;x\u{7}\r\n{}", "y".repeat(10_000))})
    .to_string();
    let e = decode(line.as_bytes()).unwrap();
    assert!(!e.origin.chars().any(char::is_control), "{:?}", e.origin);
    assert!(!e.message.chars().any(char::is_control));
    assert!(e.message.len() < 2100, "{}", e.message.len());
}

#[test]
fn file_names_are_strict() {
    assert_eq!(file_name("log", 3), "log.3.txt");
    assert_eq!(file_number("log", "log.0.txt"), Some(0));
    assert_eq!(file_number("log", "log.12.txt"), Some(12));
    for other in [
        "log.txt",
        "log.03.txt",
        "log..txt",
        "log.x.txt",
        "log.1.txt.bak",
        "log2.1.txt",
        "log.-1.txt",
        "log.99999999999.txt",
    ] {
        assert_eq!(file_number("log", other), None, "{other}");
    }
}

proptest! {
    /// Any bytes: no panic, whatever comes back is printable, and a boot
    /// that restores it answers `log.print`.
    #[test]
    fn any_bytes_are_safe(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let (events, _) = decode_all(&bytes);
        for e in &events {
            prop_assert!(!e.message.chars().any(char::is_control));
        }
        let mut s = Session::virtual_lab();
        s.log_disk_attach(events, 0);
        s.execute("log.print", &json!({})).unwrap();
    }

    /// Lines that look like ours, damaged here and there: same.
    #[test]
    fn mutated_lines_are_safe(
        time in any::<u64>(),
        message in ".{0,200}",
        origin in ".{0,40}",
        topic in 0..TOPICS.len(),
        depth in 0usize..200,
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 0..8),
        cut_at in any::<prop::sample::Index>(),
    ) {
        let mut detail = String::from("0");
        for _ in 0..depth {
            detail = format!("[{detail}]");
        }
        let mut line = format!(
            "{{\"time\":{time},\"topics\":[{}],\"origin\":{},\"message\":{},\"detail\":{detail}}}\n",
            Value::from(TOPICS[topic]),
            Value::from(origin.as_str()),
            Value::from(message.as_str()),
        )
        .into_bytes();
        for (at, b) in &flips {
            let i = at.index(line.len());
            line[i] = *b;
        }
        line.truncate(cut_at.index(line.len() + 1));
        let (events, _) = decode_all(&line);
        let mut s = Session::virtual_lab();
        s.log_disk_attach(events, 0);
        s.execute("log.print", &json!({})).unwrap();
        prop_assert!(s.ext::<LogBook>().is_some());
    }

    /// Whatever an event holds, what is written comes back the same.
    #[test]
    fn any_event_round_trips(message in "[^\\p{Cc}]{0,300}", origin in "[^\\p{Cc}]{0,50}", time in any::<u64>()) {
        let e = LogEvent { seq: 0, time, topics: vec!["info".into()], origin, message, detail: Value::Null };
        let line = encode(&e).unwrap();
        prop_assert_eq!(decode(line.trim_end().as_bytes()).unwrap(), e);
    }
}
