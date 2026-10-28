//! Positions for the topology drawing (the Topology tab): a
//! force-directed layout (Fruchterman & Reingold, 1991) — every pair of
//! nodes pushes apart, every link pulls its ends together, and the step
//! shrinks each round ("cooling") until the drawing settles.
//!
//! Deterministic: the start positions come from the node ids (a hash on a
//! circle), so the same LSDB draws the same picture every time and a
//! router keeps its place between refreshes. The repulsion is O(n²) per
//! round; the rounds split the nodes in chunks on threads (each thread
//! reads every position of the round before and writes only its own
//! chunk; threads started once, a barrier between rounds; the same answer
//! on 1 or N threads). Numbers in
//! `docs/ospf.md` (G3.4b, **medido**).

/// One node's position, in a unit square scaled by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Pos {
    pub x: f32,
    pub y: f32,
}

/// Rounds run (the step cools to ~0 by the last).
pub const ROUNDS: usize = 300;
/// Above this many nodes the rounds go on threads.
const PARALLEL_FROM: usize = 64;

fn hash(id: u64) -> u64 {
    // SplitMix64: a stable spread of the ids.
    let mut z = id.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The start: each node on a circle at the angle its id hashes to, a
/// little inside or outside it.
pub fn start(ids: &[u64]) -> Vec<Pos> {
    ids.iter()
        .map(|id| {
            let h = hash(*id);
            let a = (h & 0xFFFF) as f32 / 65_536.0 * std::f32::consts::TAU;
            let r = 0.35 + ((h >> 16) & 0xFF) as f32 / 255.0 * 0.1;
            Pos {
                x: 0.5 + r * a.cos(),
                y: 0.5 + r * a.sin(),
            }
        })
        .collect()
}

/// Lay out `n` nodes (ids for the start) joined by `edges` (index pairs;
/// out of range ones are ignored). `threads`: 0 picks by size.
pub fn layout(ids: &[u64], edges: &[(usize, usize)], threads: usize) -> Vec<Pos> {
    let n = ids.len();
    let mut pos = start(ids);
    if n < 2 {
        return pos.into_iter().map(|_| Pos { x: 0.5, y: 0.5 }).collect();
    }
    let k = (1.0 / n as f32).sqrt(); // ideal edge length in the unit square
    let threads = if threads == 0 {
        threads_for(n)
    } else {
        threads
    };
    // Adjacency as index lists, built once.
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n];
    for &(a, b) in edges {
        if a < n && b < n && a != b {
            if let Some(v) = adj.get_mut(a) {
                v.push(b);
            }
            if let Some(v) = adj.get_mut(b) {
                v.push(a);
            }
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    if threads > 1 && n >= PARALLEL_FROM && rounds_on_threads(&mut pos, &adj, k, threads) {
        normalize(&mut pos);
        return pos;
    }
    let _ = threads;
    let mut next = pos.clone();
    for round in 0..ROUNDS {
        let t = temp(round);
        for (i, slot) in next.iter_mut().enumerate() {
            *slot = move_one(&pos, &adj, k, t, i);
        }
        std::mem::swap(&mut pos, &mut next);
    }
    normalize(&mut pos);
    pos
}

/// The step allowed in round `round` (cooling linearly to 0).
fn temp(round: usize) -> f32 {
    0.1 * (1.0 - round as f32 / ROUNDS as f32)
}

/// Node `i`'s new position from the old ones.
fn move_one(pos: &[Pos], adj: &[Vec<usize>], k: f32, temp: f32, i: usize) -> Pos {
    let Some(p) = pos.get(i).copied() else {
        return Pos::default();
    };
    let (mut dx, mut dy) = (0.0f32, 0.0f32);
    for (j, q) in pos.iter().enumerate() {
        if i == j {
            continue;
        }
        let (ex, ey) = (p.x - q.x, p.y - q.y);
        let d2 = (ex * ex + ey * ey).max(1e-6);
        // Repulsion k² / d, along the unit vector: k² · e / d².
        let f = k * k / d2;
        dx += ex * f;
        dy += ey * f;
    }
    for &j in adj.get(i).map_or(&[][..], Vec::as_slice) {
        let Some(q) = pos.get(j) else { continue };
        let (ex, ey) = (p.x - q.x, p.y - q.y);
        let d = (ex * ex + ey * ey).sqrt().max(1e-3);
        // Attraction d² / k, along the unit vector: d · e / k.
        let f = d / k;
        dx -= ex * f;
        dy -= ey * f;
    }
    let len = (dx * dx + dy * dy).sqrt().max(1e-9);
    let s = len.min(temp) / len;
    Pos {
        x: p.x + dx * s,
        y: p.y + dy * s,
    }
}

/// Every round on `threads` threads started once: each computes its chunk
/// from the shared positions (read lock), waits for the others, writes its
/// chunk back (write lock, a copy), waits again. Starting threads every
/// round cost more than it saved (16 threads: 69 ms against 72 ms on one,
/// **medido**). `false`: a thread could not start (the caller runs alone).
#[cfg(not(target_arch = "wasm32"))]
fn rounds_on_threads(pos: &mut Vec<Pos>, adj: &[Vec<usize>], k: f32, threads: usize) -> bool {
    use std::sync::{Barrier, PoisonError, RwLock};
    let n = pos.len();
    let size = n.div_ceil(threads);
    let chunks = n.div_ceil(size);
    let start = pos.clone();
    let shared = RwLock::new(std::mem::take(pos));
    let barrier = Barrier::new(chunks);
    let ok = std::thread::scope(|scope| {
        // Each thread first waits for a go: if one cannot start, the others
        // are told to stop instead of waiting at the barrier for it.
        let mut handles = Vec::new();
        let mut gos = Vec::new();
        for c in 0..chunks {
            let (shared, barrier) = (&shared, &barrier);
            let (go, ready) = std::sync::mpsc::channel::<bool>();
            let h = std::thread::Builder::new()
                .name("ospf-layout".into())
                .spawn_scoped(scope, move || {
                    if ready.recv() != Ok(true) {
                        return;
                    }
                    let lo = c * size;
                    let hi = (lo + size).min(n);
                    let mut mine = vec![Pos::default(); hi - lo];
                    for round in 0..ROUNDS {
                        {
                            let p = shared.read().unwrap_or_else(PoisonError::into_inner);
                            for (o, i) in mine.iter_mut().zip(lo..hi) {
                                *o = move_one(&p, adj, k, temp(round), i);
                            }
                        }
                        barrier.wait();
                        {
                            let mut p = shared.write().unwrap_or_else(PoisonError::into_inner);
                            if let Some(dst) = p.get_mut(lo..hi) {
                                dst.copy_from_slice(&mine);
                            }
                        }
                        barrier.wait();
                    }
                });
            match h {
                Ok(h) => {
                    handles.push(h);
                    gos.push(go);
                }
                Err(_) => break,
            }
        }
        let all = handles.len() == chunks;
        for g in gos {
            let _ = g.send(all);
        }
        let joined = handles.into_iter().all(|h| h.join().is_ok());
        all && joined
    });
    let done = shared.into_inner().unwrap_or_else(PoisonError::into_inner);
    *pos = if ok { done } else { start };
    ok
}

/// Into the unit square with a margin, keeping the aspect.
fn normalize(pos: &mut [Pos]) {
    let (mut x0, mut y0, mut x1, mut y1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
    for p in pos.iter() {
        x0 = x0.min(p.x);
        y0 = y0.min(p.y);
        x1 = x1.max(p.x);
        y1 = y1.max(p.y);
    }
    let span = (x1 - x0).max(y1 - y0).max(1e-6);
    for p in pos.iter_mut() {
        p.x = 0.05 + 0.9 * (p.x - x0) / span;
        p.y = 0.05 + 0.9 * (p.y - y0) / span;
    }
}

/// Threads worth using for `n` nodes (1 on wasm).
pub fn threads_for(n: usize) -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = n;
        1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        if n < PARALLEL_FROM {
            return 1;
        }
        let cpus = std::thread::available_parallelism().map_or(1, usize::from);
        // Past ~8 the barrier between rounds costs what the split saves
        // (500 nodes: 66.8 ms on 1, 27.1 ms on 4, 29.1 ms on 16, **medido**).
        cpus.min(n / 64).clamp(1, 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(n: usize) -> (Vec<u64>, Vec<(usize, usize)>) {
        (
            (0..n as u64).collect(),
            (0..n).map(|i| (i, (i + 1) % n)).collect(),
        )
    }

    #[test]
    fn deterministic_and_the_same_on_threads() {
        let (ids, edges) = ring(200);
        let one = layout(&ids, &edges, 1);
        let many = layout(&ids, &edges, 8);
        assert_eq!(one, many);
        assert_eq!(one, layout(&ids, &edges, 1));
        assert!(
            one.iter()
                .all(|p| (0.0..=1.0).contains(&p.x) && (0.0..=1.0).contains(&p.y))
        );
    }

    #[test]
    fn linked_nodes_end_closer_than_unlinked() {
        let (ids, edges) = ring(30);
        let p = layout(&ids, &edges, 1);
        let d = |a: usize, b: usize| ((p[a].x - p[b].x).powi(2) + (p[a].y - p[b].y).powi(2)).sqrt();
        assert!(d(0, 1) < d(0, 15), "{} {}", d(0, 1), d(0, 15));
    }

    #[test]
    fn degenerate_inputs() {
        assert!(layout(&[], &[], 0).is_empty());
        assert_eq!(layout(&[7], &[(0, 5)], 0), vec![Pos { x: 0.5, y: 0.5 }]);
        let p = layout(&[1, 2], &[(0, 9), (1, 1)], 4);
        assert_eq!(p.len(), 2);
    }
}
