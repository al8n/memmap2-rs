use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{io, ptr};

const MAP_ZERO: rustix::mm::MapFlags = unsafe { rustix::mm::MapFlags::from_bits_unchecked(0) };

#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "redox",
)))]
const MAP_STACK: rustix::mm::MapFlags = rustix::mm::MapFlags::STACK;

#[cfg(any(
    target_os = "dragonfly",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "redox",
))]
const MAP_STACK: rustix::mm::MapFlags = MAP_ZERO;

#[cfg(not(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
)))]
const MAP_POPULATE: rustix::mm::MapFlags = rustix::mm::MapFlags::POPULATE;

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "illumos",
    target_os = "ios",
    target_os = "macos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "redox",
))]
const MAP_POPULATE: rustix::mm::MapFlags = MAP_ZERO;

pub struct MmapInner {
    ptr: *mut core::ffi::c_void,
    len: usize,
}

impl MmapInner {
    /// Creates a new `MmapInner`.
    ///
    /// This is a thin wrapper around the `mmap` sytem call.
    fn new(
        len: usize,
        prot: rustix::mm::ProtFlags,
        flags: rustix::mm::MapFlags,
        file: RawFd,
        offset: u64,
    ) -> io::Result<Self> {
        let alignment = offset % page_size() as u64;
        let aligned_offset = offset - alignment;
        let aligned_len = len + alignment as usize;

        // `libc::mmap` does not support zero-size mappings. POSIX defines:
        //
        // https://pubs.opengroup.org/onlinepubs/9699919799/functions/mmap.html
        // > If `len` is zero, `mmap()` shall fail and no mapping shall be established.
        //
        // So if we would create such a mapping, crate a one-byte mapping instead:
        let aligned_len = aligned_len.max(1);

        // Note that in that case `MmapInner::len` is still set to zero,
        // and `Mmap` will still dereferences to an empty slice.
        //
        // If this mapping is backed by an empty file, we create a mapping larger than the file.
        // This is unusual but well-defined. On the same man page, POSIX further defines:
        //
        // > The `mmap()` function can be used to map a region of memory that is larger
        // > than the current size of the object.
        //
        // (The object here is the file.)
        //
        // > Memory access within the mapping but beyond the current end of the underlying
        // > objects may result in SIGBUS signals being sent to the process. The reason for this
        // > is that the size of the object can be manipulated by other processes and can change
        // > at any moment. The implementation should tell the application that a memory reference
        // > is outside the object where this can be detected; otherwise, written data may be lost
        // > and read data may not reflect actual data in the object.
        //
        // Because `MmapInner::len` is not incremented, this increment of `aligned_len`
        // will not allow accesses past the end of the file and will not cause SIGBUS.
        //
        // (SIGBUS is still possible by mapping a non-empty file and then truncating it
        // to a shorter size, but that is unrelated to this handling of empty files.)

        let ptr = unsafe {
            rustix::mm::mmap(
                ptr::null_mut(),
                aligned_len,
                prot,
                flags,
                rustix::fd::BorrowedFd::borrow_raw(file),
                aligned_offset,
            )
        };

        match ptr {
            Ok(ptr) => Ok(MmapInner {
                ptr: unsafe { ptr.offset(alignment as isize) },
                len,
            }),
            Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }

    fn new_anon(len: usize, stack: bool, populate: bool) -> io::Result<Self> {
        let stack = if stack { MAP_STACK } else { MAP_ZERO };
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                ptr::null_mut(),
                len.max(1),
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::PRIVATE | stack | populate,
            )
        };

        match ptr {
            Ok(ptr) => Ok(MmapInner { ptr, len }),
            Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
        }
    }

    #[inline]
    pub fn mlock(&self) -> io::Result<()> {
        unsafe {
            rustix::mm::mlock(self.ptr, self.len)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
    }

    #[inline]
    pub fn munlock(&self) -> io::Result<()> {
        unsafe {
            rustix::mm::munlock(self.ptr, self.len)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
    }

    #[inline]
    pub fn mlock_segment(&self, data_size: usize, offset: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = self.len.min(data_size) + alignment;

        unsafe { rustix::mm::mlock(self.ptr.offset(offset), len.min(data_size)) }
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    #[inline]
    pub fn munlock_segment(&self, data_size: usize, offset: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = self.len.min(data_size) + alignment;

        unsafe { rustix::mm::munlock(self.ptr.offset(offset), len) }
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    pub fn map(len: usize, file: RawFd, offset: u64, populate: bool) -> io::Result<MmapInner> {
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        MmapInner::new(
            len,
            rustix::mm::ProtFlags::READ,
            rustix::mm::MapFlags::SHARED | populate,
            file,
            offset,
        )
    }

    pub fn map_exec(len: usize, file: RawFd, offset: u64, populate: bool) -> io::Result<MmapInner> {
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        MmapInner::new(
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::EXEC,
            rustix::mm::MapFlags::SHARED | populate,
            file,
            offset,
        )
    }

    pub fn map_mut(len: usize, file: RawFd, offset: u64, populate: bool) -> io::Result<MmapInner> {
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        MmapInner::new(
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::SHARED | populate,
            file,
            offset,
        )
    }

    pub fn map_copy(len: usize, file: RawFd, offset: u64, populate: bool) -> io::Result<MmapInner> {
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        MmapInner::new(
            len,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE | populate,
            file,
            offset,
        )
    }

    pub fn map_copy_read_only(
        len: usize,
        file: RawFd,
        offset: u64,
        populate: bool,
    ) -> io::Result<MmapInner> {
        let populate = if populate { MAP_POPULATE } else { MAP_ZERO };
        MmapInner::new(
            len,
            rustix::mm::ProtFlags::READ,
            rustix::mm::MapFlags::PRIVATE | populate,
            file,
            offset,
        )
    }

    /// Open an anonymous memory map.
    #[inline]
    pub fn map_anon(len: usize, stack: bool, populate: bool) -> io::Result<MmapInner> {
        MmapInner::new_anon(len, stack, populate)
    }

    pub fn flush(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        unsafe { rustix::mm::msync(self.ptr.offset(offset), len, rustix::mm::MsyncFlags::SYNC) }
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    pub fn flush_async(&self, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        unsafe { rustix::mm::msync(self.ptr.offset(offset), len, rustix::mm::MsyncFlags::ASYNC) }
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    }

    fn mprotect(&mut self, prot: rustix::mm::MprotectFlags) -> io::Result<()> {
        unsafe {
            let alignment = self.ptr as usize % page_size();
            let ptr = self.ptr.offset(-(alignment as isize));
            let len = self.len + alignment;
            let len = len.max(1);
            rustix::mm::mprotect(ptr, len, prot)
                .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
        }
    }

    pub fn make_read_only(&mut self) -> io::Result<()> {
        self.mprotect(rustix::mm::MprotectFlags::READ)
    }

    pub fn make_exec(&mut self) -> io::Result<()> {
        self.mprotect(rustix::mm::MprotectFlags::READ | rustix::mm::MprotectFlags::EXEC)
    }

    pub fn make_mut(&mut self) -> io::Result<()> {
        self.mprotect(rustix::mm::MprotectFlags::READ | rustix::mm::MprotectFlags::WRITE)
    }

    #[inline]
    pub fn ptr(&self) -> *const u8 {
        self.ptr as *const u8
    }

    #[inline]
    pub fn mut_ptr(&mut self) -> *mut u8 {
        self.ptr as *mut u8
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn advise(&self, advice: rustix::mm::Advice, offset: usize, len: usize) -> io::Result<()> {
        let alignment = (self.ptr as usize + offset) % page_size();
        let offset = offset as isize - alignment as isize;
        let len = len + alignment;
        unsafe {
            match rustix::mm::madvise(self.ptr.offset(offset), len, advice) {
                Ok(_) => Ok(()),
                Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
            }
        }
    }
}

impl Drop for MmapInner {
    fn drop(&mut self) {
        let alignment = self.ptr as usize % page_size();
        let len = self.len + alignment;
        let len = len.max(1);
        // Any errors during unmapping/closing are ignored as the only way
        // to report them would be through panicking which is highly discouraged
        // in Drop impls, c.f. https://github.com/rust-lang/lang-team/issues/97
        unsafe {
            let ptr = self.ptr.offset(-(alignment as isize));
            let _ = rustix::mm::munmap(ptr, len);
        }
    }
}

unsafe impl Sync for MmapInner {}
unsafe impl Send for MmapInner {}

fn page_size() -> usize {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    match PAGE_SIZE.load(Ordering::Relaxed) {
        0 => {
            let page_size = rustix::param::page_size();

            PAGE_SIZE.store(page_size, Ordering::Relaxed);

            page_size
        }
        page_size => page_size,
    }
}

pub fn file_len(file: RawFd) -> io::Result<u64> {
    use rustix::fs::fstat;

    let borrowed_fd: rustix::fd::BorrowedFd<'_> =
        unsafe { rustix::fd::BorrowedFd::borrow_raw(file) };
    match fstat(borrowed_fd) {
        Ok(stat) => Ok(stat.st_size as u64),
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}
