//! Exercises discovery bounds, NAT evidence and rebinding without choosing a path [196,197].
#![allow(clippy::expect_used)]

use infraternal_mesh::{
    discovery::{
        Discovery, DiscoveryError, MAX_OBSERVATIONS, MappingEvidence, Observation, usable_address,
    },
    model::NodeId,
};
use std::{net::SocketAddr, time::Duration};

fn address(value: &str) -> SocketAddr {
    value.parse().expect("fixture address")
}
fn observation(destination: &str, reflexive: &str) -> Observation {
    Observation {
        observer: NodeId(1),
        destination: address(destination),
        reflexive: address(reflexive),
    }
}
fn record(book: &mut Discovery, value: Observation) {
    book.observe(1, value, Duration::ZERO, Duration::from_secs(30))
        .expect("authenticated observation");
}

#[test]
fn distinct_destinations_establish_mapping_evidence_but_not_filtering() {
    let mut book = Discovery::new(1);
    let a = observation("192.0.2.1:443", "198.51.100.1:40000");
    record(&mut book, a);
    record(
        &mut book,
        Observation {
            observer: NodeId(2),
            ..a
        },
    );
    assert_eq!(
        book.evidence(false, Duration::ZERO),
        Ok(MappingEvidence::Unknown)
    );
    record(
        &mut book,
        observation("192.0.2.2:443", "198.51.100.1:40000"),
    );
    assert_eq!(
        book.evidence(false, Duration::ZERO),
        Ok(MappingEvidence::Stable)
    );
    record(
        &mut book,
        observation("192.0.2.2:444", "198.51.100.1:40001"),
    );
    assert_eq!(
        book.evidence(false, Duration::ZERO),
        Ok(MappingEvidence::DestinationDependent)
    );
}

#[test]
fn address_families_are_independent_and_mapped_ipv4_is_canonical() {
    let mut book = Discovery::new(1);
    record(
        &mut book,
        observation("192.0.2.1:443", "198.51.100.1:40000"),
    );
    record(
        &mut book,
        observation("[2001:db8::1]:443", "[2001:db8::2]:40000"),
    );
    assert_eq!(
        book.evidence(false, Duration::ZERO),
        Ok(MappingEvidence::Unknown)
    );
    assert_eq!(
        book.evidence(true, Duration::ZERO),
        Ok(MappingEvidence::Unknown)
    );
    record(
        &mut book,
        observation("[::ffff:192.0.2.2]:443", "[::ffff:198.51.100.1]:40000"),
    );
    assert_eq!(
        book.evidence(false, Duration::ZERO),
        Ok(MappingEvidence::Stable)
    );
    record(
        &mut book,
        observation("[2001:db8::3]:443", "[2001:db8::2]:40001"),
    );
    assert_eq!(
        book.evidence(true, Duration::ZERO),
        Ok(MappingEvidence::DestinationDependent)
    );
}

#[test]
fn rebinding_retires_candidates_and_old_responses_cannot_repopulate_them() {
    let mut book = Discovery::new(1);
    let a = observation("192.0.2.1:443", "198.51.100.1:40000");
    record(&mut book, a);
    let now = Duration::from_secs(1);
    book.restart(2, now).expect("network changed");
    assert_eq!(book.observations(now).expect("new generation"), []);
    assert_eq!(
        book.observe(1, a, now, Duration::from_secs(30)),
        Err(DiscoveryError::StaleGeneration)
    );
    assert_eq!(book.restart(2, now), Err(DiscoveryError::StaleGeneration));
    book.observe(2, a, now, Duration::from_secs(30))
        .expect("new socket observation");
    assert_eq!(book.evidence(false, now), Ok(MappingEvidence::Unknown));
}

#[test]
fn expiration_is_exact_and_reversed_time_cannot_revive_candidates() {
    let mut book = Discovery::new(1);
    record(
        &mut book,
        observation("192.0.2.1:443", "198.51.100.1:40000"),
    );
    let expiry = Duration::from_secs(30);
    assert_eq!(
        book.observations(
            expiry
                .checked_sub(Duration::from_nanos(1))
                .expect("positive expiry")
        )
        .expect("before expiry")
        .len(),
        1
    );
    assert_eq!(book.observations(expiry).expect("expiry"), []);
    assert_eq!(
        book.observations(Duration::ZERO),
        Err(DiscoveryError::ClockReversed)
    );
    assert_eq!(book.observations(expiry).expect("still expired"), []);
}

#[test]
fn full_books_allow_refresh_and_reuse_expired_slots() {
    let mut book = Discovery::new(1);
    let a = observation("192.0.2.1:443", "198.51.100.1:40000");
    for observer in 0..MAX_OBSERVATIONS {
        record(
            &mut book,
            Observation {
                observer: NodeId(u64::try_from(observer).expect("bound")),
                ..a
            },
        );
    }
    let extra = Observation {
        observer: NodeId(999),
        ..a
    };
    assert_eq!(
        book.observe(1, extra, Duration::ZERO, Duration::from_secs(30)),
        Err(DiscoveryError::Full)
    );
    record(&mut book, a);
    assert_eq!(
        book.observations(Duration::ZERO).expect("bounded").len(),
        MAX_OBSERVATIONS
    );
    book.observe(1, extra, Duration::from_secs(30), Duration::from_secs(30))
        .expect("expired slots");
    assert_eq!(
        book.observations(Duration::from_secs(30))
            .expect("one live entry")
            .len(),
        1
    );
}

#[test]
fn unusable_addresses_and_invalid_lifetimes_leave_the_book_unchanged() {
    let mut book = Discovery::new(1);
    let a = observation("192.0.2.1:443", "198.51.100.1:40000");
    for invalid in [
        "0.0.0.0:1",
        "0.1.2.3:1",
        "127.1.2.3:1",
        "224.0.0.1:1",
        "255.255.255.255:1",
        "169.254.1.2:1",
        "192.0.2.1:0",
        "[::]:1",
        "[::1]:1",
        "[ff02::1]:1",
        "[fe80::1]:1",
        "[fe80::1%2]:1",
        "[2001:db8::1%2]:1",
        "[::ffff:127.0.0.1]:1",
    ] {
        assert_eq!(
            usable_address(address(invalid)),
            Err(DiscoveryError::InvalidAddress),
            "{invalid}"
        );
    }
    assert_eq!(
        book.observe(1, a, Duration::ZERO, Duration::ZERO),
        Err(DiscoveryError::InvalidAddress)
    );
    assert_eq!(
        book.observe(1, a, Duration::from_secs(1), Duration::MAX),
        Err(DiscoveryError::InvalidAddress)
    );
    assert_eq!(
        book.observe(
            1,
            Observation {
                reflexive: address("[2001:db8::1]:1"),
                ..a
            },
            Duration::ZERO,
            Duration::from_secs(1)
        ),
        Err(DiscoveryError::InvalidAddress)
    );
    assert_eq!(book.observations(Duration::ZERO).expect("unchanged"), []);
    assert!(usable_address(address("10.0.0.1:1")).is_ok());
    assert!(usable_address(address("[fd01::1]:1")).is_ok());
}
