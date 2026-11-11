//! G0.24b: no window grows by itself. A list that draws something under a
//! table filling the window (an "empty" hint, a footer taller than the
//! table's `reserve`) overflows it by that height every frame; egui grows a
//! window to fit its content when the mouse lets go of a resize, so the
//! window crept down to the bottom of the screen (DNS Adlist, 2026-11-10).

use super::*;

/// How far `win` grew in 15 frames after its data settled (px).
fn growth(win: Win) -> Option<String> {
    let mut h = Harness::new();
    h.screen = egui::vec2(1600.0, 1400.0);
    h.app.open.clear();
    h.app.open.insert(win);
    let height = |h: &mut Harness| {
        h.idle();
        h.ctx.memory(|m| m.area_rect(win_id(win))).map_or(0.0, |r| r.height())
    };
    // Settle: the data arrives (refreshed a few times: some lists draw
    // more once it comes), a sizing pass. Then watch, without refresh:
    // growing once is fine, growing on is the bug.
    for f in 0..30 {
        if f % 10 == 0 {
            h.app.cache.refreshed_at = None;
        }
        height(&mut h);
    }
    let start = height(&mut h);
    let mut end = start;
    for _ in 0..15 {
        end = height(&mut h);
    }
    (end - start > 1.0).then(|| format!("{} ({start:.0} → {end:.0} px in 15 frames)", win.title()))
}

#[test]
fn no_window_grows_by_itself() {
    // Each window on its own harness: split over the cores (G0.30).
    let all = Win::all();
    let per = all.len().div_ceil(4).max(1);
    let grew: Vec<String> = std::thread::scope(|sc| {
        let jobs: Vec<_> = all
            .chunks(per)
            .map(|wins| sc.spawn(move || wins.iter().filter_map(|w| growth(*w)).collect::<Vec<_>>()))
            .collect();
        jobs.into_iter().flat_map(|j| j.join().unwrap()).collect()
    });
    assert!(grew.is_empty(), "windows that grow by themselves: {grew:#?}");
}

#[test]
fn the_empty_hint_is_inside_the_table_and_goes_with_the_first_item() {
    let hint = "No forwarders. A group of servers (plain, DoH or DoT) that a static FWD \
                entry sends its names to: /ip dns static add name=corp.example type=FWD \
                forward-to=<group>.";
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open.insert(Win::Panel(crate::dns_forwarders::WIN));
    for _ in 0..4 {
        h.idle();
    }
    let at = h.find_text(hint).expect("the hint is painted");
    let items = h.find_text("0 items").expect("the table's status line");
    assert!(at.y < items.y, "the hint is in the table, above its status line");

    lock(&h.session)
        .execute("ip.dns.forwarders.add", &json!({"name": "CORP", "dns_servers": ["192.0.2.1"]}))
        .unwrap();
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    assert!(h.has_text("1 items"), "the forwarder arrived");
    assert!(!h.has_text(hint), "no hint with an item");
}
