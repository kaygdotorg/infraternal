//! Exercises the stable/edge grammar shared by build identity and signed release lookups [226].
use super::channel;
#[test]
fn accepts_only_worker_version_forms() {
    for version in ["0.1.0", "12.34.56", "edge-20261011T071500Z"] {
        assert_eq!(
            channel(version),
            Some(if version.starts_with("edge-") {
                "edge"
            } else {
                "stable"
            })
        );
    }
    for version in [
        "",
        "1.2",
        "1.2.3.4",
        "v1.2.3",
        "1.2.3-rc1",
        "edge-20261011T071500",
        "edge-20261011t071500Z",
        "edge-20261011T071500z",
        "edge-2026101aT071500Z",
        "edge-20261011T071500Z/../1.2.3",
        "1.2.3\n",
        "１.2.3",
    ] {
        assert_eq!(channel(version), None, "{version}");
    }
    assert_eq!(channel(&"1".repeat(128)), None);
}
