//! Secret bytes kept outside the allocator: anonymous mmap'd pages that are
//! mlock'ed (best effort), excluded from core dumps (MADV_DONTDUMP), and
//! zeroed + unmapped on drop.

use crate::error::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroize;

static MLOCK_FAILED: AtomicBool = AtomicBool::new(false);

/// True if any mlock failed (secrets may be swappable; raise LimitMEMLOCK).
pub fn mlock_failed() -> bool {
    MLOCK_FAILED.load(Ordering::Relaxed)
}

pub struct SecretBuf {
    ptr: *mut u8,
    cap: usize,
    len: usize,
}

// SAFETY: SecretBuf exclusively owns its mapping; it is only read through
// &self and mutated in Drop, so moving or sharing it between threads is safe.
unsafe impl Send for SecretBuf {}
// SAFETY: see above; there is no interior mutability.
unsafe impl Sync for SecretBuf {}

impl SecretBuf {
    /// Copy `src` into locked memory and zero `src`.
    pub fn new(src: &mut [u8]) -> Result<Self> {
        let page = crate::sys::page_size();
        let pages = src.len().div_ceil(page).max(1);
        let cap = pages
            .checked_mul(page)
            .ok_or_else(|| Error::msg("secret too large"))?;
        // SAFETY: anonymous private mapping, no fd, kernel picks the address.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cap,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            src.zeroize();
            return Err(Error::msg(format!(
                "mmap: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: ptr/cap describe the mapping we just created.
        unsafe {
            if libc::mlock(ptr, cap) != 0 {
                MLOCK_FAILED.store(true, Ordering::Relaxed);
            }
            libc::madvise(ptr, cap, libc::MADV_DONTDUMP);
            std::ptr::copy_nonoverlapping(src.as_ptr(), ptr.cast::<u8>(), src.len());
        }
        let len = src.len();
        src.zeroize();
        Ok(SecretBuf {
            ptr: ptr.cast(),
            cap,
            len,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: ptr is valid for `cap >= len` bytes until Drop.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        // SAFETY: we own the mapping; after this it is never touched again.
        unsafe {
            std::slice::from_raw_parts_mut(self.ptr, self.cap).zeroize();
            libc::munlock(self.ptr.cast(), self.cap);
            libc::munmap(self.ptr.cast(), self.cap);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_zero_source() {
        let mut v = b"hello-secret".to_vec();
        let b = SecretBuf::new(&mut v).unwrap();
        assert_eq!(b.as_bytes(), b"hello-secret");
        assert!(v.iter().all(|x| *x == 0));
        let mut e: Vec<u8> = vec![];
        assert!(SecretBuf::new(&mut e).unwrap().is_empty());
    }
}
