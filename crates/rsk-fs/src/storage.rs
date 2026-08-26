// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The FID → bytes persistence backend. On device this is `sequential-storage`
//! over embassy-rp flash (implemented in `firmware`); tests use `RamStorage`.

use rsk_sdk::error::Result;

/// A persistent map from 16-bit file id to a byte value.
pub trait Storage {
    /// Largest value this backend can store for one FID. A log-structured backend
    /// serialises key+value through one scratch buffer, so the real ceiling is
    /// smaller than the buffer and was previously an unstated property of it —
    /// callers that picked their own cap could exceed it (audit run-32). Defaults
    /// to the device backend's, so a host test hits the same rejection.
    const MAX_VALUE: usize = crate::MAX_VALUE_BYTES;
    /// Copy the value for `fid` into `buf` (truncated to `buf.len()`), returning
    /// the value's full length, or `None` if `fid` is absent.
    fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize>;
    /// Store (or replace) the value for `fid`.
    fn write(&mut self, fid: u16, data: &[u8]) -> Result<()>;
    /// Remove `fid` if present.
    fn remove(&mut self, fid: u16) -> Result<()>;
    /// Length of the value for `fid`, or `None`.
    fn size(&mut self, fid: u16) -> Option<usize>;
    /// Whether `fid` has a stored value.
    fn exists(&mut self, fid: u16) -> bool {
        self.size(fid).is_some()
    }
    /// Whether the most recent [`read`](Self::read) / [`size`](Self::size) FAILED,
    /// rather than finding the key absent.
    ///
    /// Both return `None` for either outcome, and [`Fs`](crate::Fs) memoises the
    /// answer as a *decided* fact — so without this a transient backend fault
    /// becomes a permanent "file absent" for the rest of the boot, and every gate
    /// that reads `has_data` opens: `clientpin::set_pin` is guarded by
    /// `if has_data(EF_PIN)` alone, so a poisoned absence lets an unauthenticated
    /// host install its own PIN over the owner's (audit run-36).
    ///
    /// Defaults to `false` — a backend that cannot fail (the test RAM map) never
    /// needs to say so, and an implementor that forgets is no worse than before.
    fn last_error(&self) -> bool {
        false
    }
    /// Invoke `f` once per stored key (used to rebuild the dynamic-file set and to
    /// probe credential slots without a per-slot `read` of every absent FID).
    /// Returns `true` iff the enumeration ran to completion — every live key was
    /// yielded. A `false` return means the walk was truncated (a flash read fault),
    /// so the caller MUST NOT treat an un-yielded FID as absent (see
    /// [`crate::Fs::scan`]).
    fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool;
    /// Physically reclaim superseded records so that *overwritten* and *deleted*
    /// payloads are erased from the medium, not merely unlinked.
    ///
    /// A log-structured backend ([`crate::Storage`] over `sequential-storage`)
    /// only appends: an overwrite leaves the prior value in the log and a delete
    /// flips a header flag, so the old bytes survive a raw flash dump until the
    /// page is naturally reclaimed. That is fine for the device-root seal in the
    /// steady state, but it means a record re-sealed under a *stronger* root (the
    /// pre-OTP → OTP seed migration) leaves a copy sealed under the *weaker*
    /// chip-serial-only root readable until compaction. This drives that
    /// compaction on demand. Default: no-op (backends, like the test RAM map,
    /// that overwrite in place and keep no remnants).
    fn compact(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod ram {
    use super::*;
    use std::collections::HashMap;

    /// In-memory `Storage` for host tests. `Clone` lets fuzz targets snapshot
    /// an initialized image instead of re-deriving it per exec.
    #[derive(Default, Clone)]
    pub struct RamStorage {
        map: HashMap<u16, Vec<u8>>,
    }

    impl RamStorage {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Storage for RamStorage {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            let v = self.map.get(&fid)?;
            let n = v.len().min(buf.len());
            buf[..n].copy_from_slice(&v[..n]);
            Some(v.len())
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.map.insert(fid, data.to_vec());
            Ok(())
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.map.remove(&fid);
            Ok(())
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.map.get(&fid).map(|v| v.len())
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            for &k in self.map.keys() {
                f(k);
            }
            true // the RAM map iterates in memory; it cannot fault mid-walk
        }
    }
}

/// Backends that fail on purpose, shared by the applet crates' tests. One flash
/// fault shape per type, narrow enough that the setup and the observation cannot
/// be what fails.
#[cfg(any(test, feature = "test-util"))]
pub mod faults {
    use super::ram::RamStorage;
    use super::*;
    use crate::EF_META;
    use rsk_sdk::error::Error;
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    /// A RAM medium whose EF_META reads fail on demand while every other value
    /// still reads. Deleting anything then leaves "a record may stand over what I
    /// erased" undecidable — and EF_META is ONE blob shared by every applet, so
    /// that answer arrives at fids which carry no record of their own. It is the
    /// fault all four applet reset sweeps must carry to the end of their range
    /// instead of stopping on it.
    pub struct MetaStuck {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<bool>>,
        err: bool,
    }

    /// The other end of a [`MetaStuck`]: arms the fault, and reads the medium
    /// past `Fs`'s present cache — which a delete marks absent whether or not the
    /// backend `remove` ran, so a cache-level check would pass over a wipe that
    /// never happened.
    pub struct Medium {
        inner: Rc<RefCell<RamStorage>>,
        stuck: Rc<Cell<bool>>,
    }

    impl MetaStuck {
        pub fn new() -> (Self, Medium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let stuck = Rc::new(Cell::new(false));
            (
                Self {
                    inner: inner.clone(),
                    stuck: stuck.clone(),
                    err: false,
                },
                Medium { inner, stuck },
            )
        }
    }

    impl Medium {
        /// Start (`true`) or stop refusing EF_META.
        pub fn stick(&self, on: bool) {
            self.stuck.set(on);
        }
        /// Whether `fid` still has a value ON THE MEDIUM.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
    }

    impl Storage for MetaStuck {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            if fid == EF_META && self.stuck.get() {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            if fid == EF_META && self.stuck.get() {
                self.err = true;
                return None;
            }
            self.err = false;
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
        /// The whole point: a FAILED read must not be memoised as absence.
        fn last_error(&self) -> bool {
            self.err
        }
    }

    /// A RAM medium whose `remove` refuses one chosen fid while every other value
    /// still deletes — the other half of a [`MetaStuck`], and the one a sweep must
    /// stop on. [`crate::Fs::force_delete_halves`] removes UNCONDITIONALLY, so the
    /// refusal reaches a delete loop even at a fid that was never live.
    pub struct RemoveStuck {
        inner: Rc<RefCell<RamStorage>>,
        refused: Rc<Cell<Option<u16>>>,
    }

    /// The other end of a [`RemoveStuck`]: arms the fault, and reads the medium
    /// past `Fs`'s present cache, which a delete marks absent whether or not the
    /// backend `remove` ran.
    pub struct RemoveMedium {
        inner: Rc<RefCell<RamStorage>>,
        refused: Rc<Cell<Option<u16>>>,
    }

    impl RemoveStuck {
        pub fn new() -> (Self, RemoveMedium) {
            let inner = Rc::new(RefCell::new(RamStorage::new()));
            let refused = Rc::new(Cell::new(None));
            (
                Self {
                    inner: inner.clone(),
                    refused: refused.clone(),
                },
                RemoveMedium { inner, refused },
            )
        }
    }

    impl RemoveMedium {
        /// Refuse `remove` for `fid` (`None` clears the fault).
        pub fn refuse(&self, fid: Option<u16>) {
            self.refused.set(fid);
        }
        /// Whether `fid` still has a value ON THE MEDIUM.
        pub fn live(&self, fid: u16) -> bool {
            self.inner.borrow_mut().exists(fid)
        }
    }

    impl Storage for RemoveStuck {
        fn read(&mut self, fid: u16, buf: &mut [u8]) -> Option<usize> {
            self.inner.borrow_mut().read(fid, buf)
        }
        fn write(&mut self, fid: u16, data: &[u8]) -> Result<()> {
            self.inner.borrow_mut().write(fid, data)
        }
        fn remove(&mut self, fid: u16) -> Result<()> {
            if self.refused.get() == Some(fid) {
                return Err(Error::MemoryFatal);
            }
            self.inner.borrow_mut().remove(fid)
        }
        fn size(&mut self, fid: u16) -> Option<usize> {
            self.inner.borrow_mut().size(fid)
        }
        fn for_each_key(&mut self, f: &mut dyn FnMut(u16)) -> bool {
            self.inner.borrow_mut().for_each_key(f)
        }
    }
}
