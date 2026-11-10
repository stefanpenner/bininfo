/*
---
why: This file records one open and lets the caller stop it.
uses: bininfo
how: The terminal starts one watch when enter opens a file.
The disk reader adds bytes and checks the stop flag.
A stopped read returns no page.
---
*/

//! One open. The caller can stop it between reads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Bytes read so far, and a flag the reader checks between blocks.
pub struct Watch {
    stop: AtomicBool,
    done: AtomicU64,
    limit: AtomicU64,
}

impl Watch {
    /// A watch that runs until the caller stops it.
    pub fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            done: AtomicU64::new(0),
            limit: AtomicU64::new(0),
        }
    }

    /// Ask the reader to stop before the next block.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// True after `stop` or after the byte cap.
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Acquire)
    }

    /// Bytes copied or inflated for this open.
    pub fn done(&self) -> u64 {
        self.done.load(Ordering::Relaxed)
    }

    pub(crate) fn add(&self, n: u64) {
        let total = self.done.fetch_add(n, Ordering::Relaxed).saturating_add(n);
        let limit = self.limit.load(Ordering::Relaxed);
        if limit > 0 && total >= limit {
            self.stop.store(true, Ordering::Release);
        }
    }

    /// Stop after at least `n` bytes. `0` means no cap.
    #[cfg(test)]
    pub(crate) fn cap_at(&self, n: u64) {
        self.limit.store(n, Ordering::Relaxed);
    }
}
