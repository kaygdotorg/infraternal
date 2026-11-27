//! Pure mesh coordination for D163–D167; transport and kernel wiring live outside this crate.
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod model;

pub mod address;

pub mod names;

pub mod rules;

/// Subnet routes: networks a node routes for the mesh once approved (D197 M3).
pub mod networks;

pub mod view;

pub mod coordinator;

pub mod backend;

pub mod proxy_ports;

/// Shares exact-address mesh SSH listener ports with the GotaTun packet filter.
pub mod mesh_ssh;

/// Observation bounds for relay discovery, and the address rules every candidate follows (#515).
pub mod discovery;

/// The measured path rule for a mesh pair: which relay, and direct or relayed (D313 Q5, #201).
pub mod path_choice;

pub mod cli;

/// Shared framing for offline Linux mesh status.
pub mod public_journal;
