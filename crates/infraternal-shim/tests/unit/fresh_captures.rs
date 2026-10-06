//! Differential real-program captures sampled at bounded prefix intervals [13][40].
use super::*;

#[test]
#[ignore = "manual fresh capture oracle; set VT_CAPTURE_DIR after real program capture"]
fn fidelity_fresh_real_program_captures() {
    let root = std::path::PathBuf::from(std::env::var("VT_CAPTURE_DIR").unwrap());
    for name in ["vim", "htop", "less"] {
        let prefix = std::fs::read(root.join(format!("{name}.vt"))).unwrap();
        let continuation = std::fs::read(root.join(format!("{name}.continue.vt"))).unwrap();
        let mut accepted = 0;
        let mut rejected = 0;
        for end in (64..prefix.len())
            .step_by(64)
            .chain(std::iter::once(prefix.len()))
        {
            match check_replay(name, &prefix[..end], Some(&continuation), 200, 60) {
                Ok(()) => accepted += 1,
                Err(error) => {
                    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
                    rejected += 1;
                }
            }
        }
        println!(
            "fresh capture {name}: bytes={} accepted={accepted} rejected={rejected} divergent=0 stride=64 dimensions=200x60",
            prefix.len()
        );
    }
}
