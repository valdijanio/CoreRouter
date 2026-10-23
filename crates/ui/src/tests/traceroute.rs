//! MTR window, G6.4c: the Traceroute mode runs one pass with N probes per
//! hop (the Probes column), UDP/TCP probes and Paris; without Paris a hop
//! behind the simulated ECMP pair shows its two routers with a chip.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, Job, Runner};
use serde_json::json;

use super::*;
use crate::mtr::{MtrForm, mtr_params};

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

fn open() -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Mtr);
    for _ in 0..6 {
        h.idle();
    }
    h
}

fn run_until_done(h: &mut Harness) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !h.app.mtr.task.as_ref().is_some_and(|t| t.done) {
        assert!(Instant::now() < deadline, "{:?}", h.app.log());
        thread::sleep(Duration::from_millis(30));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    h.idle();
}

#[test]
fn the_form_picks_the_command() {
    let f = MtrForm {
        traceroute: true,
        address: " 8.8.8.8 ".into(),
        protocol: "tcp".into(),
        port: "443".into(),
        ..MtrForm::default()
    };
    let (cmd, p) = mtr_params(&f);
    assert_eq!(cmd, "tool.traceroute.start");
    assert_eq!(
        p,
        json!({"address": "8.8.8.8", "max_hops": 30, "use_dns": true, "as_lookup": false,
            "protocol": "tcp", "paris": true, "port": 443, "probes": 3})
    );
    let (cmd, p) = mtr_params(&MtrForm { address: "1.1.1.1".into(), ..MtrForm::default() });
    assert_eq!(cmd, "tool.mtr.start");
    assert_eq!(p["protocol"], "icmp");
    assert!(p.get("port").is_none() && p.get("probes").is_none());
}

#[test]
fn a_traceroute_pass_with_probes_and_ecmp() {
    let mut h = open();
    {
        let f = &mut h.app.mtr.form;
        f.traceroute = true;
        f.address = "8.8.8.8".into();
        f.protocol = "udp".into();
        f.paris = false;
        f.probes = "6".into();
        f.use_dns = false;
    }
    h.idle();
    assert!(h.has_text("Probes") && h.has_text("Paris") && h.has_text("Port"));
    h.click(h.text("Start"));
    run_until_done(&mut h);
    let s = h.app.mtr.task.as_ref().unwrap().summary.clone();
    assert_eq!(s["mode"], "traceroute", "{s}");
    assert_eq!(s["reached"], true);
    assert!(h.has_text_containing("ECMP 2"), "the zig-zag at hop 3");
    assert!(h.has_text_containing("port unreachable"));
    // Paris on: one router at hop 3 (UDP Paris goes one probe at a time,
    // and silent hops cost a timeout each: fewer probes keep it short).
    h.app.mtr.form.paris = true;
    h.app.mtr.form.probes = "2".into();
    h.idle();
    h.click(h.text("Start"));
    run_until_done(&mut h);
    assert!(!h.has_text_containing("ECMP 2"));
}

#[test]
fn every_explanation_exists() {
    for key in ["mtr.mode", "mtr.probes", "mtr.protocol", "mtr.port", "mtr.paris"] {
        for l in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: l, help: l };
            assert_eq!(crate::i18n::explain(langs, key).map(|(x, _)| x), Some(l), "{key} in {l:?}");
        }
    }
}
