//! Binary-size probe (#260, J1204): the same small program (a `HashMap<IpAddr, usize>` that is
//! filled from argv and queried) built once per hasher, so the size difference between the
//! builds is what the hasher's code adds to a static binary. Build with
//! `--features fold|ahash-probe|fx` (none = std SipHash-1-3) under the product's release
//! settings (`opt-level = 3`, fat LTO, `codegen-units = 1`, `strip`, `panic = unwind`).

use std::collections::HashMap;
use std::net::IpAddr;

#[cfg(feature = "fold")]
type State = foldhash::fast::RandomState;
#[cfg(feature = "ahash-probe")]
type State = ahash::RandomState;
#[cfg(feature = "fx")]
type State = rustc_hash::FxBuildHasher;
#[cfg(not(any(feature = "fold", feature = "ahash-probe", feature = "fx")))]
type State = std::hash::RandomState;

fn main() {
    let mut map: HashMap<IpAddr, usize, State> = HashMap::default();
    for (i, arg) in std::env::args().skip(1).enumerate() {
        if let Ok(ip) = arg.parse::<IpAddr>() {
            map.insert(ip, i);
        }
    }
    let probe: IpAddr = std::env::var("PROBE").ok().and_then(|v| v.parse().ok()).unwrap_or(IpAddr::from([10, 254, 0, 1]));
    println!("{:?}", map.get(&probe));
}
