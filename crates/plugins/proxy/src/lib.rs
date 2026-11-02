//! Owns downloaded proxy components, node-local configuration and process supervision [D316], #281.
//! Per-machine wildcard certificates are the default, and their private keys remain on that machine.
//! Flat exact-service certificate names are visible in public Certificate Transparency logs.
//! DNS provider custody is interim owner-only file storage behind `DnsTokenCustody` [#289].
//! Node-key sealing or `OpenBao` can replace the file implementation later without changing callers.
//! The CLI pairs `publish [port]` with `unpublish <port|name>`; the separate inverse is the
//! orchestrator's choice on #281, pending any owner rename. A missing unpublish target is an
//! idempotent D303 `missing` result (exit 4), including the shared `--json` envelope.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod agent;
pub mod cli;
pub mod config;
pub mod controller;
pub mod custody;
pub mod download;
pub mod installer;
pub mod manifest;
pub mod mesh_context;
pub mod names;
pub mod release_signature;
pub mod supervisor;

#[cfg(test)]
#[path = "custody_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "manifest_tests.rs"]
mod manifest_tests;

#[cfg(test)]
#[path = "installer_tests.rs"]
mod installer_tests;

#[cfg(test)]
#[path = "names_tests.rs"]
mod names_tests;

#[cfg(test)]
#[path = "cli_tests.rs"]
mod cli_tests;

#[cfg(test)]
#[path = "download_tests.rs"]
mod download_tests;

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;

#[cfg(test)]
#[path = "supervisor_tests.rs"]
mod supervisor_tests;

#[cfg(test)]
#[path = "agent_tests.rs"]
mod agent_tests;
