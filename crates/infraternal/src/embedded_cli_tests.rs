//! Checks inherited-fd parser compatibility and dispatch boundaries without invoking untrusted descriptors, #78.

use super::*;

#[test]
fn inherited_flags_keep_public_parser_validation_and_values() {
    for flags in [
        vec!["--fd", "3"],
        vec!["--state", "/private/state", "--fd=3"],
        vec!["--fd=2147483647", "--state=/private/state"],
        vec!["--fd=-1"],
    ] {
        let public = super::super::Cli::try_parse_from(
            ["infraternal", "agent"]
                .into_iter()
                .chain(flags.iter().copied()),
        )
        .unwrap();
        let super::super::Command::Agent { boot, .. } = public.command else {
            panic!("expected infraternal agent command");
        };
        let inherited = Inherited::try_parse_from(
            std::iter::once("infraternal agent").chain(flags.iter().copied()),
        )
        .unwrap();
        assert_eq!(boot.fd, inherited.options.fd);
        assert_eq!(boot.state, inherited.options.state);
    }
    for invalid in [
        vec!["--fd=2147483648"],
        vec!["--fd=wrong"],
        vec!["--fd", "3", "unexpected"],
        vec!["--fd", "3", "--state"],
    ] {
        assert!(
            Inherited::try_parse_from(std::iter::once("infraternal agent").chain(invalid),)
                .is_err()
        );
    }
}

#[test]
fn dispatch_keeps_public_help_operator_modes_and_foreign_commands() {
    for args in [
        vec!["infraternal", "agent", "--fd", "3"],
        vec!["infraternal", "agent", "--fd=3", "--state=/private"],
    ] {
        assert!(requested(
            &args.into_iter().map(OsString::from).collect::<Vec<_>>()
        ));
    }
    for args in [
        vec![
            "infraternal",
            "agent",
            "join",
            "https://example.test/remote/join",
        ],
        vec!["infraternal", "agent", "--fd=3", "--help"],
        vec!["infraternal", "agent", "--fd=3", "--data=/private"],
        vec!["infraternal", "server", "--fd=3"],
        vec!["infraternal", "__shim", "--fd=3"],
    ] {
        assert!(!requested(
            &args.into_iter().map(OsString::from).collect::<Vec<_>>()
        ));
    }
    assert!(Inherited::try_parse_from(["infraternal agent", "--fd=3", "join"]).is_err());
}
