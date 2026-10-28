//! A router's event queue: earliest first, ties in insertion order (the
//! sequence number), so the run never depends on the heap's internals.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use crate::Time;

struct Entry<E> {
    at: Time,
    seq: u64,
    ev: E,
}

impl<E> PartialEq for Entry<E> {
    fn eq(&self, o: &Self) -> bool {
        self.at == o.at && self.seq == o.seq
    }
}
impl<E> Eq for Entry<E> {}
impl<E> PartialOrd for Entry<E> {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl<E> Ord for Entry<E> {
    // Reversed: `BinaryHeap` is a max-heap.
    fn cmp(&self, o: &Self) -> Ordering {
        o.at.cmp(&self.at).then_with(|| o.seq.cmp(&self.seq))
    }
}

pub(crate) struct Queue<E> {
    heap: BinaryHeap<Entry<E>>,
    seq: u64,
}

impl<E> Default for Queue<E> {
    fn default() -> Self {
        Queue {
            heap: BinaryHeap::new(),
            seq: 0,
        }
    }
}

impl<E> Queue<E> {
    pub(crate) fn push(&mut self, at: Time, ev: E) {
        self.seq += 1;
        self.heap.push(Entry {
            at,
            seq: self.seq,
            ev,
        });
    }

    pub(crate) fn next_at(&self) -> Option<Time> {
        self.heap.peek().map(|e| e.at)
    }

    /// The earliest event if it is before `end`.
    pub(crate) fn pop_before(&mut self, end: Time) -> Option<(Time, E)> {
        if self.heap.peek()?.at >= end {
            return None;
        }
        self.heap.pop().map(|e| (e.at, e.ev))
    }

    pub(crate) fn len(&self) -> usize {
        self.heap.len()
    }

    pub(crate) fn clear(&mut self) {
        self.heap.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn earliest_first_ties_in_order() {
        let mut q = Queue::default();
        q.push(5, 'a');
        q.push(3, 'b');
        q.push(5, 'c');
        q.push(3, 'd');
        assert_eq!(q.next_at(), Some(3));
        let mut out = Vec::new();
        while let Some((_, e)) = q.pop_before(10) {
            out.push(e);
        }
        assert_eq!(out, vec!['b', 'd', 'a', 'c']);
    }

    #[test]
    fn stops_at_the_window_end() {
        let mut q = Queue::default();
        q.push(9, 1);
        q.push(10, 2);
        assert_eq!(q.pop_before(10), Some((9, 1)));
        assert_eq!(q.pop_before(10), None);
        assert_eq!(q.len(), 1);
    }
}
