//! Owns long-lived PTY sessions across browser drops and agent upgrades [13].
//!
//! PTY syscalls will need audited unsafe blocks. Unsafe code remains denied here
//! until those syscalls exist, and each future block must document its safety
//! invariant and receive focused review.
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
