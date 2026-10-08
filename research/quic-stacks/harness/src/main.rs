//! Role: Entry point for the isolated QUIC stack benchmark and smoke checks.
//! SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "baseline")]
mod baseline;

#[cfg(feature = "openssl-native")]
mod openssl_native;

#[cfg(feature = "quinn-stack")]
mod quinn_stack;

#[cfg(feature = "common")]
mod test_identity;

#[cfg(feature = "measure")]
mod measure;

#[cfg(feature = "measure")]
mod memory;

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let action = match std::env::args().nth(1) {
        Some(action) => action,
        None => "baseline".to_owned(),
    };

    match action.as_str() {
        "baseline" => baseline_action(),
        "openssl-version" => baseline::print_version(),
        #[cfg(feature = "openssl-native")]
        "openssl-smoke" => openssl_native::smoke(),
        #[cfg(feature = "quinn-stack")]
        "quinn-smoke" => quinn_stack::smoke(),
        #[cfg(feature = "measure")]
        "bench-handshake" => measure::handshake_action(),
        #[cfg(feature = "measure")]
        "bench-throughput" => measure::throughput_action(),
        #[cfg(feature = "measure")]
        "bench-0rtt" => measure::zero_rtt_action(),
        #[cfg(feature = "measure")]
        "bench-memory" => memory::action(),
        #[cfg(feature = "measure")]
        "memory-server" => memory::server_action(),
        _ => Err(format!("unknown action: {action}").into()),
    }
}

fn baseline_action() -> Result<(), Box<dyn Error>> {
    #[cfg(feature = "baseline")]
    {
        baseline::smoke()
    }
    #[cfg(not(feature = "baseline"))]
    {
        Err("build with --features baseline for the OpenSSL baseline".into())
    }
}
