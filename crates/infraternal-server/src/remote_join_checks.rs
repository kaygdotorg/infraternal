//! Fuzz entry point for what a joining machine and its approval send the server (#78, #263).
//!
//! [`verify_remote_join_sample`] picks one of three parsers by its first
//! input byte and feeds it the rest:
//!
//! - the `POST /remote/join` body and its canonical CSR spelling;
//! - the machine facts an owner approves in the browser (`JoinMachineRequest`
//!   validation, its key fingerprint and the derived receipt token);
//! - the one canonical spelling of an invitation secret that `redeem` hashes.
//!
//! Only built for tests and the `parser-checks` feature (the fuzz harness).

/// Fuzz the join and approval parsers with one input; panics when one of
/// their invariants breaks, as libFuzzer expects.
#[doc(hidden)]
pub fn verify_remote_join_sample(data: &[u8]) {
    let [selector, rest @ ..] = data else {
        return;
    };
    match selector % 3 {
        0 => crate::remote_http::check_join_request_sample(rest),
        1 => crate::auth::check_join_machine_sample(rest),
        _ => crate::enrollment::check_secret_sample(rest),
    }
}

/// Replays the committed seed corpus through the fuzz entry point, so the
/// ordinary test run exercises it on the stable toolchain (ENGINEERING P5).
#[cfg(test)]
mod seed_corpus {
    /// Every committed seed runs through the entry point without a panic.
    #[test]
    fn every_seed_replays_without_breaking_an_invariant() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/corpus/remote_join_approval"
        );
        let mut seeds = 0;
        for entry in std::fs::read_dir(dir).unwrap() {
            super::verify_remote_join_sample(&std::fs::read(entry.unwrap().path()).unwrap());
            seeds += 1;
        }
        assert!(seeds > 0, "no seeds in {dir}");
    }
}
