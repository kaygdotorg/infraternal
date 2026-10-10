//! Research-only authenticated SSH measurements; stdin supplies a synthetic fixture key, never a server credential.
#![forbid(unsafe_code)]

use russh::{
    client,
    keys::{
        PrivateKeyWithHashAlg, PublicKeyOrCertificate, check_known_hosts_path, decode_secret_key,
    },
};
use std::{path::PathBuf, sync::Arc, time::Instant};
use tokio::io::AsyncReadExt;

struct Strict {
    known_hosts: PathBuf,
    port: u16,
}
impl client::Handler for Strict {
    type Error = russh::Error;
    fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        std::future::ready(match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                Ok(
                    check_known_hosts_path("127.0.0.1", self.port, key, &self.known_hosts)
                        .unwrap_or(false),
                )
            }
            PublicKeyOrCertificate::Certificate(_) => Ok(false),
        })
    }
}

fn rss() -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|s| s.starts_with("VmRSS:"))
                .and_then(|s| s.split_whitespace().nth(1))
                .and_then(|s| s.parse().ok())
        })
        .unwrap_or(0)
}

fn private_memory() -> u64 {
    std::fs::read_to_string("/proc/self/smaps_rollup")
        .unwrap_or_default()
        .lines()
        .filter(|line| line.starts_with("Private_Clean:") || line.starts_with("Private_Dirty:"))
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .sum()
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("SSH research probe failed (details withheld)");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err("expected port known_hosts user samples retained".into());
    }
    let port = args[1].parse::<u16>()?;
    let samples = args[4].parse::<usize>()?;
    let retained = args[5].parse::<usize>()?;
    let mut pem = String::new();
    tokio::io::stdin()
        .take(65537)
        .read_to_string(&mut pem)
        .await?;
    if pem.len() > 65536 {
        return Err("fixture input too large".into());
    }
    let key = Arc::new(decode_secret_key(&pem, None)?);
    // Only a synthetic fixture key enters this process. It is never serialized
    // or printed by the probe, including on an error.
    let baseline = rss();
    let baseline_private = private_memory();
    let mut timings = Vec::new();
    let mut sessions = Vec::new();
    for index in 0..samples.max(retained) {
        let started = Instant::now();
        let mut session = client::connect(
            Arc::new(client::Config::default()),
            ("127.0.0.1", port),
            Strict {
                known_hosts: args[2].clone().into(),
                port,
            },
        )
        .await?;
        if !session
            .authenticate_publickey(&args[3], PrivateKeyWithHashAlg::new(key.clone(), None))
            .await?
            .success()
        {
            return Err("fixture authentication failed".into());
        }
        if index < samples {
            timings.push(started.elapsed().as_micros());
        }
        if sessions.len() < retained {
            sessions.push(session);
        } else {
            session
                .disconnect(russh::Disconnect::ByApplication, "fixture complete", "")
                .await?;
        }
    }
    timings.sort_unstable();
    let resident = rss();
    let resident_private = private_memory();
    if samples > 0 {
        println!(
            "METRIC candidate=russh version=0.63.1 samples={samples} auth_p50_us={} auth_p99_us={}",
            timings[samples / 2],
            timings[(samples * 99 / 100).min(samples - 1)]
        );
    }
    println!(
        "METRIC candidate=russh baseline_rss_kib={baseline} retained_rss_kib={resident} connections={retained} client_delta_kib={} client_private_delta_kib={} scale_sessions=200",
        resident.saturating_sub(baseline),
        resident_private.saturating_sub(baseline_private)
    );
    for session in sessions {
        session
            .disconnect(russh::Disconnect::ByApplication, "fixture complete", "")
            .await?;
    }
    Ok(())
}
