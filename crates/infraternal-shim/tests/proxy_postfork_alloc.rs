//! Guard both owner-mismatch hooks against allocation after fork (#414).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use nix::libc;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs::File,
    os::unix::process::CommandExt,
    process::Command,
    sync::atomic::{AtomicBool, Ordering},
};
/// True only in the nested child, after fork and before exec.
static AFTER_FORK: AtomicBool = AtomicBool::new(false);
/// Report an allocation with async-signal-safe syscalls and terminate the probe child.
struct CheckedAllocator;
// SAFETY: allocations use System unchanged unless the nested child terminates;
// deallocation always returns the original pointer and layout to System.
unsafe impl GlobalAlloc for CheckedAllocator {
    /// Abort with a syscall-only marker if an owner-error hook allocates after fork.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if AFTER_FORK.load(Ordering::Relaxed) {
            let marker = b"J348_POSTFORK_ALLOCATION_IN_PROXY_OWNER_ERROR\n";
            unsafe {
                libc::write(2, marker.as_ptr().cast(), marker.len());
                libc::_exit(99);
            }
        }
        unsafe { System.alloc(layout) }
    }
    /// Release normal test allocations through their original allocator.
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { System.dealloc(p, layout) }
    }
}
/// Apply the guard to every allocation in this disposable integration-test process.
#[global_allocator]
static ALLOCATOR: CheckedAllocator = CheckedAllocator;
/// Force either owner mismatch while keeping the nested parent alive for its child.
fn assert_owner_error_does_not_allocate(proxy: bool) -> std::io::Result<()> {
    let cwd = File::open("/")?;
    let mut command = Command::new("/bin/true");
    // The nested fork makes getppid differ from the owner recorded by the hook.
    // Its parent stays alive until the probe child exits, preventing PDEATHSIG
    // from hiding the allocation. Only syscalls and lock-free atomics run here.
    unsafe {
        command.pre_exec(|| {
            let pid = libc::fork();
            if pid < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if pid > 0 {
                let mut status = 0;
                libc::waitpid(pid, &raw mut status, 0);
                libc::_exit(if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    98
                });
            }
            AFTER_FORK.store(true, Ordering::Relaxed);
            Ok(())
        });
    }
    if proxy {
        infraternal_shim::prepare_proxy_child(&mut command, &cwd, &[], None, None)?;
    } else {
        infraternal_shim::prepare_parent_bound_child(&mut command);
    }
    let result = command.status();
    assert!(
        result.is_err(),
        "proxy owner error allocated after fork: {result:?}"
    );
    Ok(())
}

/// A credential-drop hook must return its owner error without calling the allocator.
#[test]
fn proxy_owner_error_does_not_allocate_after_fork() -> std::io::Result<()> {
    assert_owner_error_does_not_allocate(true)
}

/// The earlier parent-binding hook has the same allocation-free error obligation.
#[test]
fn parent_bound_owner_error_does_not_allocate_after_fork() -> std::io::Result<()> {
    assert_owner_error_does_not_allocate(false)
}
