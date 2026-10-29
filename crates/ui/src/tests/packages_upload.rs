//! System › Packages › From this computer (G1.6e): the window reads the
//! local file a chunk at a time and sends it in order; the engine queues
//! it for the package service.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use super::*;
use crate::packages::{PackagesPanel, WIN};

const SIZE: usize = (2 << 20) + 12_345;

fn open() -> Harness {
    let mut s = Session::virtual_lab();
    corerouter_engine::package::feed_status(
        &mut s,
        json!({"supported": true, "running": "a", "primary": "a", "trial": null, "slots": [
            {"slot": "a", "state": "running", "running": true},
            {"slot": "b", "state": "empty", "running": false}]}),
    );
    let mut h = Harness::with_session(s);
    let file: Vec<u8> = (0..SIZE).map(|i| (i % 253) as u8).collect();
    crate::export::install_read_at(
        &h.ctx,
        Arc::new(move |path: &str, off: u64, len: usize| {
            if path != "/home/op/b.crpkg" {
                return Err(format!("{path}: not found"));
            }
            let at = (off as usize).min(file.len());
            let end = (at + len).min(file.len());
            Ok((file[at..end].to_vec(), file.len() as u64))
        }),
    );
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    until(&mut h, "the status", |h| h.has_text("From this computer"));
    h
}

fn until(h: &mut Harness, what: &str, done: impl Fn(&mut Harness) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(h) {
        assert!(Instant::now() < deadline, "{what}: {:?}", h.app.log());
        h.time += 0.05;
        h.idle();
    }
}

#[test]
fn sends_a_local_package_in_chunks() {
    let mut h = open();
    assert!(h.has_text("From this computer"));
    h.app.panel_mut::<PackagesPanel>().unwrap().local = "/home/op/b.crpkg".into();
    h.idle();
    h.click(h.text("Upload and check"));
    until(&mut h, "every chunk sent", |h| {
        let p = h.app.panel_mut::<PackagesPanel>().unwrap();
        p.sending.is_none()
    });
    let mut s = h.session.lock().unwrap();
    let pk = s.ext::<corerouter_engine::package::Packages>().unwrap();
    let up = pk.upload.as_ref().expect("the upload is the engine's");
    assert_eq!((up.size, up.received), (SIZE as u64, SIZE as u64));
    assert!(up.tx.is_none(), "end of stream");
    let job = corerouter_engine::package::take_job(&mut s).unwrap();
    assert_eq!(
        job.kind,
        corerouter_engine::package::JobKind::Upload { size: SIZE as u64, downgrade: false, check: true }
    );
    let rx = corerouter_engine::package::take_upload(&mut s, job.id).unwrap();
    let got: Vec<u8> = rx.try_iter().flatten().collect();
    assert_eq!(got.len(), SIZE);
    assert_eq!(got[SIZE - 1], ((SIZE - 1) % 253) as u8);
}

#[test]
fn a_missing_file_says_why_and_sends_nothing() {
    let mut h = open();
    h.app.panel_mut::<PackagesPanel>().unwrap().local = "/nope.crpkg".into();
    h.idle();
    h.click(h.text("Upload and check"));
    h.idle();
    assert!(h.has_text_containing("not found"));
    let s = h.session.lock().unwrap();
    assert!(s.ext::<corerouter_engine::package::Packages>().unwrap().upload.is_none());
}

#[test]
fn an_address_in_package_file_is_downloaded_by_the_router() {
    let mut h = open();
    h.app.panel_mut::<PackagesPanel>().unwrap().path = "https://up.example/b.crpkg".into();
    h.idle();
    h.click(h.text("Check"));
    until(&mut h, "the job", |h| {
        let s = h.session.lock().unwrap();
        s.ext::<corerouter_engine::package::Packages>().unwrap().queued.is_some()
    });
    let mut s = h.session.lock().unwrap();
    let job = corerouter_engine::package::take_job(&mut s).unwrap();
    assert_eq!(
        job.kind,
        corerouter_engine::package::JobKind::Download {
            url: "https://up.example/b.crpkg".into(),
            verify: true,
            downgrade: false,
            check: true
        }
    );
}
