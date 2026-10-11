//! Isolated single-threaded descriptor and inherited-signal detachment probe [13][217], #154.
#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("missing result path")?;
    // Open before closing stdin so the result handle cannot alias a standard fd.
    let mut result = std::fs::File::create(path)?;
    let mask: u8 = std::env::args().nth(2).ok_or("missing fd mask")?.parse()?;
    let signals = std::env::args().nth(3).is_some_and(|arg| arg == "signals");
    if signals {
        let mut blocked = nix::sys::signal::SigSet::empty();
        blocked.add(nix::sys::signal::Signal::SIGHUP);
        blocked.thread_block()?;
    }
    let parent_mask = nix::sys::signal::SigSet::thread_get_mask()?;
    for fd in 0..3 {
        if mask & (1 << fd) != 0 {
            nix::unistd::close(fd)?;
        }
    }
    let detached = infraternal_shim::detach()?;
    if signals && !detached && nix::sys::signal::SigSet::thread_get_mask()? != parent_mask {
        return Err("detachment changed the caller's signal mask".into());
    }
    if detached {
        use std::io::Write as _;
        if signals {
            use std::os::unix::process::ExitStatusExt as _;
            // Deliberately bypass prepare_child: this exec observes the policy
            // established by detach itself, including inherited SIG_IGN.
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", "kill -HUP $$; exit 42"])
                .status()?;
            let empty =
                nix::sys::signal::SigSet::thread_get_mask()? == nix::sys::signal::SigSet::empty();
            writeln!(
                result,
                "signal_mask_empty={empty} child_sighup={:?}",
                status.signal()
            )?;
            return Ok(());
        }
        let descriptors = (0..3)
            .map(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")))
            .collect::<Result<Vec<_>, _>>();
        writeln!(result, "{descriptors:?}")?;
    }
    Ok(())
}
