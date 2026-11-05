//! The fixed invocation must agree with the full CLI schema on every launcher shape.
use super::*;
use clap::Parser;
use std::ffi::OsString;

#[derive(Parser)]
struct Full {
    #[command(flatten)]
    options: Options,
}
fn arguments() -> Vec<OsString> {
    [
        "--session",
        "0123456789abcdef0123456789abcdef",
        "--uid",
        "1002",
        "--cols",
        "80",
        "--rows",
        "24",
        "--state",
        "/private/session-state",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}
/// Every launcher shape decodes to the same options as the full CLI schema, lifeline included.
#[test]
fn spawned_shapes_reuse_full_shim_options_and_defaults() {
    for flags in [
        &[][..],
        &["--readiness"],
        &["--detach"],
        &["--readiness", "--detach"],
        &["--retain-output", "--detach"],
        &["--retain-output", "--command-stdin", "--detach"],
        &["--detach", "--lifeline-fd", "9"],
        &["--retain-output", "--detach", "--lifeline-fd", "12"],
    ] {
        let mut args = arguments();
        args.extend(flags.iter().map(OsString::from));
        let spawned = Options::spawned(&args).unwrap();
        let full = Full::try_parse_from(std::iter::once(OsString::from("__shim")).chain(args))
            .unwrap()
            .options;
        assert_eq!(spawned.session, full.session);
        assert_eq!(
            (spawned.uid, spawned.cols, spawned.rows),
            (full.uid, full.cols, full.rows)
        );
        assert_eq!(spawned.state, full.state);
        assert_eq!(spawned.retain_output, full.retain_output);
        assert_eq!(spawned.lifeline_fd, full.lifeline_fd);
        assert_eq!(spawned.command_stdin, full.command_stdin);
        assert_eq!(
            (
                spawned.detach,
                spawned.readiness,
                spawned.ring_capacity,
                spawned.exit_retention_ms
            ),
            (
                full.detach,
                full.readiness,
                full.ring_capacity,
                full.exit_retention_ms
            )
        );
    }
}
#[test]
fn spawned_decode_refuses_changes_to_the_fixed_shape_before_startup() {
    let original = arguments();
    for length in 0..original.len() {
        assert!(Options::spawned(&original[..length]).is_none());
    }
    for (field, value) in [
        (0, "--other"),
        (1, "invalid"),
        (2, "--uid=1002"),
        (3, "-1"),
        (3, "01002"),
        (3, "4294967296"),
        (5, "65536"),
        (7, "+24"),
        (8, "--data"),
    ] {
        let mut args = original.clone();
        args[field] = value.into();
        assert!(Options::spawned(&args).is_none(), "{field}: {value}");
    }
    let mut args = original.clone();
    args.extend([OsString::from("--detach"), OsString::from("--readiness")]);
    assert!(Options::spawned(&args).is_none());
    let mut args = original;
    args.push(OsString::from("--detach"));
    args.push(OsString::from("--detach"));
    assert!(Options::spawned(&args).is_none());
}
