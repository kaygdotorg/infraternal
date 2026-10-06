//! Isolated single-threaded closed-standard-descriptor regression probe for #16.
#![forbid(unsafe_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("missing result path")?;
    // Open before closing stdin so the result handle cannot alias a standard fd.
    let mut result = std::fs::File::create(path)?;
    let mask: u8 = std::env::args().nth(2).ok_or("missing fd mask")?.parse()?;
    for fd in 0..3 {
        if mask & (1 << fd) != 0 {
            nix::unistd::close(fd)?;
        }
    }
    if infraternal_shim::detach()? {
        use std::io::Write as _;
        let descriptors = (0..3)
            .map(|fd| std::fs::read_link(format!("/proc/self/fd/{fd}")))
            .collect::<Result<Vec<_>, _>>();
        writeln!(result, "{descriptors:?}")?;
    }
    Ok(())
}
