//! Prints the exact `inet infraternal_host` table the product renders for a policy (#483, D386).
//!
//! Kernel proofs such as `tests/review_j555_ipv6_netns.sh` load this output
//! instead of a hand-written copy, so they cannot drift from
//! `host_firewall::render`. Usage: `render_host_table '<policy JSON>'`.
//! The JSON is the role policy shape saved by `server init`.
use infraternal_plugin_mesh::host_firewall::{Policy, render};

/// Parse the policy from the first argument and print its rendered default-drop table.
fn main() -> Result<(), String> {
    let json = std::env::args()
        .nth(1)
        .ok_or("usage: render_host_table '<policy JSON>'")?;
    let policy: Policy = serde_json::from_str(&json).map_err(|error| error.to_string())?;
    print!("{}", render(&policy).map_err(|error| error.to_string())?);
    Ok(())
}
