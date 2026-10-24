//! What a machine hands back to its caller after each entry point: frames
//! to transmit (packed in one reusable buffer) and events. The caller drains
//! it and calls [`Output::clear`]; capacity is kept, so the steady state
//! allocates nothing.

use std::ops::Range;

/// One frame to send: `ifindex` and its bytes in [`Output::buf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutFrame {
    pub ifindex: u32,
    pub range: Range<usize>,
}

#[derive(Debug)]
pub struct Output<E> {
    pub buf: Vec<u8>,
    pub frames: Vec<OutFrame>,
    pub events: Vec<E>,
}

impl<E> Default for Output<E> {
    fn default() -> Self {
        Output {
            buf: Vec::with_capacity(4096),
            frames: Vec::with_capacity(16),
            events: Vec::new(),
        }
    }
}

impl<E> Output<E> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.frames.clear();
        self.events.clear();
    }

    /// Records the bytes appended to `buf` since `start` as one frame.
    pub(crate) fn push_frame(&mut self, ifindex: u32, start: usize) {
        if self.buf.len() > start {
            self.frames.push(OutFrame {
                ifindex,
                range: start..self.buf.len(),
            });
        }
    }

    /// Frames as `(ifindex, bytes)`.
    pub fn frames(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.frames
            .iter()
            .filter_map(|f| Some((f.ifindex, self.buf.get(f.range.clone())?)))
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty() && self.events.is_empty()
    }
}
