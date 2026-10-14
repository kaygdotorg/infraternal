//! Checks that the public helper contract enumerates every admitted control kind [D12,D203], #146.
#![forbid(unsafe_code)]
use infraternal_plugin_desktop::protocol::Kind;

#[test]
fn admitted_helper_control_kinds_have_contract_rows() {
    let contract = include_str!("../../../../contracts/desktop-helper.md");
    let declared: Vec<u8> = contract
        .lines()
        .filter_map(|line| {
            line.strip_prefix('|')?
                .split('|')
                .next()?
                .trim()
                .parse()
                .ok()
        })
        .collect();
    for kind in [
        Kind::List,
        Kind::Start,
        Kind::Resize,
        Kind::Input,
        Kind::Stop,
        Kind::Status,
        Kind::Keyframe,
        Kind::ReleaseInput,
        Kind::Congested,
        Kind::Control,
    ] {
        assert!(
            declared.contains(&(kind as u8)),
            "admitted helper control kind {} has no contract row",
            kind as u8
        );
    }
}
