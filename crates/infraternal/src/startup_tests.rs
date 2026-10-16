//! Checks first-entry dump protection and startup reactor ownership [217][243], #154, #189.

#[test]
fn process_dumpability_is_disabled_before_dispatch() {
    const NAME: &str = "startup_tests::process_dumpability_is_disabled_before_dispatch";
    if std::env::var_os("INFRATERNAL_DUMP_TEST").is_some() {
        super::harden_startup().unwrap();
        assert!(
            !nix::sys::prctl::get_dumpable().unwrap(),
            "entry must close post-exec dumpability"
        );
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", NAME, "--nocapture"])
        .env("INFRATERNAL_DUMP_TEST", "1")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Typed startup results and panic cleanup must survive reactor type erasure.
#[cfg(all(feature = "plugin-server", feature = "plugin-agent"))]
#[test]
fn shared_reactor_preserves_borrows_errors_and_panic_cleanup() {
    use std::{cell::Cell, panic::AssertUnwindSafe};

    struct OnDrop<'a>(&'a Cell<u32>);
    impl Drop for OnDrop<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let drops = Cell::new(0);
    let failed: Result<&str, &str> = super::block_on(&runtime, async {
        let _guard = OnDrop(&drops);
        Err("refused")
    });
    assert_eq!(failed, Err("refused"));
    assert_eq!(drops.get(), 1);
    let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
        super::block_on::<()>(&runtime, async {
            let _guard = OnDrop(&drops);
            panic!("fixture startup failure");
        });
    }));
    let original = caught.unwrap_err();
    assert_eq!(
        original.downcast_ref::<&str>(),
        Some(&"fixture startup failure")
    );
    assert_eq!(drops.get(), 2);
    let text = String::from("retained outcome");
    assert_eq!(super::block_on(&runtime, async { text.as_str() }), text);
}
