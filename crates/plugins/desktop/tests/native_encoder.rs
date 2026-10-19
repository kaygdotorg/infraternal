//! Checks native completion/encoding decisions and real hardware access units for the selected desktop component (#146).
#![cfg(all(target_os = "macos", feature = "desktop"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn run_swift_fixture(name: &str, sources: &[&str], optimized: bool) {
    use std::{path::PathBuf, process::Command};
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = PathBuf::from(
        std::env::var_os("CARGO_TARGET_DIR")
            .expect("set CARGO_TARGET_DIR to the job's scratch build directory"),
    );
    std::fs::create_dir_all(&target).unwrap();
    let binary = target.join(format!("desktop-{name}-test-{}", std::process::id()));
    let mut compiler = Command::new("swiftc");
    if optimized {
        compiler.arg("-O");
    }
    let build = compiler
        .args(sources.iter().map(|source| root.join(source)))
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        build.status.success(),
        "{}",
        String::from_utf8_lossy(&build.stderr)
    );
    let result = Command::new(&binary).output();
    std::fs::remove_file(binary).unwrap();
    let result = result.unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn managed_windows_never_retry_an_externally_undone_resize() {
    run_swift_fixture(
        "window-ownership",
        &[
            "native/CaptureState.swift",
            "tests/fixtures/window-ownership-test.swift",
        ],
        false,
    );
}

#[test]
#[ignore = "requires a fixture-owned GUI window and the shared Mac hardware lock"]
fn keyboard_inventory_selects_only_the_original_window_identity() {
    run_swift_fixture(
        "keyboard-target",
        &[
            "native/Inventory.swift",
            "tests/fixtures/keyboard-target-test.swift",
        ],
        false,
    );
}

#[test]
fn hardware_encoder_delivers_repeated_frames_after_reconfiguration() {
    run_swift_fixture(
        "encoder",
        &[
            "native/CaptureState.swift",
            "native/LowDelaySPS.swift",
            "native/Encoder.swift",
            "tests/fixtures/encoder-session-test.swift",
        ],
        true,
    );
}

#[test]
fn raw_encoder_drops_preserve_delta_references_and_refresh_quality() {
    // This fixture also contains assert-based geometry, local-priority and
    // bitrate checks. Keep assertions enabled rather than optimizing them away.
    run_swift_fixture(
        "state",
        &[
            "native/CaptureState.swift",
            "tests/fixtures/control-state-test.swift",
        ],
        false,
    );
}

#[test]
fn delivered_pixels_are_owned_and_raw_drops_never_confirm_new_content() {
    run_swift_fixture(
        "frame-pixels",
        &[
            "native/FramePixels.swift",
            "tests/fixtures/frame-pixels-test.swift",
        ],
        true,
    );
}

#[test]
fn identical_surface_callbacks_preserve_one_refresh_and_static_repair() {
    run_swift_fixture(
        "surface-delivery",
        &[
            "native/CaptureState.swift",
            "native/FrameDamage.swift",
            "native/FramePixels.swift",
            "native/LowDelaySPS.swift",
            "native/Encoder.swift",
            "native/SurfaceCapture.swift",
            "tests/fixtures/surface-delivery-test.swift",
        ],
        true,
    );
}

#[test]
fn empty_native_damage_rectangles_do_not_schedule_unchanged_pictures() {
    run_swift_fixture(
        "frame-damage",
        &[
            "native/FrameDamage.swift",
            "tests/fixtures/frame-damage-test.swift",
        ],
        false,
    );
}

#[test]
#[ignore = "requires the signed helper, a running managing process and the shared Mac hardware lock"]
fn managed_native_window_has_no_resize_requests_or_frame_size_flips() {
    let helper = std::env::var_os("INFRATERNAL_NATIVE_CONTROL_TEST_HELPER")
        .expect("set the authorized installed native helper path");
    let scratch =
        std::env::var_os("CARGO_TARGET_DIR").expect("set the job scratch target directory");
    let result = std::process::Command::new("python3")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/native-managed-window.py"),
        )
        .arg(helper)
        .arg(scratch)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
}

#[test]
#[ignore = "requires authorized signed helper, an owned GUI document and the shared Mac hardware lock"]
fn native_typing_stays_within_the_source_control_reply_budget() {
    let helper = std::env::var_os("INFRATERNAL_NATIVE_CONTROL_TEST_HELPER")
        .expect("set the authorized installed native helper path");
    let scratch =
        std::env::var_os("CARGO_TARGET_DIR").expect("set the job scratch target directory");
    let result = std::process::Command::new("python3")
        .arg(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/native-input-pipeline.py"),
        )
        .arg(helper)
        .arg(scratch)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    println!("{}", String::from_utf8_lossy(&result.stdout));
}
