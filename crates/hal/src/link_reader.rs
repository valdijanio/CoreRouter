//! Reading the links with the session unlocked (G1.3f). The poll reads
//! every link of the platform once a second; on a Linux BNG that is a
//! kernel dump with a link per subscriber, hundreds of milliseconds with
//! ten thousand. Done under the session lock, every command, the GUI and
//! MCP waited that long. So the read is split: a [`LinkReader`], taken from
//! the [`Hal`](crate::Hal) under the lock (cheap), reads with the lock
//! released, and [`Hal::poll_sample`](crate::Hal::poll_sample) takes the
//! lock again only to fold the result in.
//!
//! A read is stamped with the hal's epoch when its reader was made; an
//! `apply` in between moves the epoch, and the sample is refused (it may
//! show a port the apply had already seen replaced). The caller then polls
//! the old way.

use std::any::Any;

/// Reads the platform's links with no access to the hal; [`Send`], so a
/// thread of the app runs it.
pub trait LinkReader: Send {
    fn read(&mut self) -> LinkSample;
}

/// What a [`LinkReader`] read, for the hal that made it.
pub struct LinkSample {
    epoch: u64,
    data: Box<dyn Any + Send>,
}

impl LinkSample {
    pub fn new<T: Any + Send>(epoch: u64, data: T) -> Self {
        Self {
            epoch,
            data: Box::new(data),
        }
    }

    /// The hal's epoch when the reader was made.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The data, if it is a `T`.
    pub fn take<T: Any>(self) -> Option<T> {
        self.data.downcast::<T>().ok().map(|b| *b)
    }
}

impl std::fmt::Debug for LinkSample {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkSample")
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sample_gives_back_its_own_type_only() {
        let s = LinkSample::new(7, vec![1u32, 2]);
        assert_eq!(s.epoch(), 7);
        assert_eq!(s.take::<Vec<u32>>(), Some(vec![1, 2]));
        assert_eq!(LinkSample::new(1, 3u8).take::<u16>(), None);
    }
}
