//! Pins the owner-approved certificate and hostname shapes [#281].

use super::names::{
    CertificateName, NameShape, default_name_shape, exposure_names,
};

#[test]
fn per_machine_wildcard_is_the_default_and_covers_the_machine_service_name() {
    assert_eq!(default_name_shape(), NameShape::PerMachineWildcard);
    let names = exposure_names(
        NameShape::default(),
        "build01",
        "docs",
        "ssh.kayg.org",
    )
    .expect("valid per-machine wildcard names");

    assert_eq!(names.hostname, "docs.build01.ssh.kayg.org");
    assert_eq!(
        names.certificate,
        CertificateName::Wildcard("*.build01.ssh.kayg.org".to_owned())
    );
}

#[test]
fn flat_service_names_receive_an_exact_service_certificate() {
    let names = exposure_names(
        NameShape::FlatService,
        "build01",
        "docs",
        "ssh.kayg.org",
    )
    .expect("valid flat service names");

    assert_eq!(names.hostname, "docs.ssh.kayg.org");
    assert_eq!(
        names.certificate,
        CertificateName::Exact("docs.ssh.kayg.org".to_owned())
    );
}

#[test]
fn exposure_names_reject_invalid_labels_and_oversized_domains() {
    assert!(exposure_names(NameShape::FlatService, "bad machine", "docs", "ssh.kayg.org").is_err());
    assert!(exposure_names(
        NameShape::PerMachineWildcard,
        "build01",
        "docs",
        &format!("{}.example", "a".repeat(250)),
    )
    .is_err());
}
