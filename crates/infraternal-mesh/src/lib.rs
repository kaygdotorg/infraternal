//! Pure mesh coordination for D163–D167; transport and kernel wiring live outside this crate.
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

pub mod model;

pub mod address;

pub mod names;

pub mod rules;

pub mod view;

pub mod coordinator;

pub mod backend;

pub mod proxy_ports;

#[cfg(feature = "relay")]
pub mod discovery;

pub mod cli;
