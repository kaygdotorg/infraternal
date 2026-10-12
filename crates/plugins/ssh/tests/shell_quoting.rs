//! Proves generated script argv preserves exact bytes through supported real login shells, including nested setup (#190).
#![allow(clippy::unwrap_used)]

use infraternal_plugin_ssh::transport::shell_quote;
use std::process::Command;

#[test]
#[ignore = "run on the owned disposable target with all supported login shells installed"]
fn nested_scripts_preserve_bytes_without_expanding_public_text() {
    let text =
        "literal 'quote' \\ \\\\ $HOME $(printf substituted) `printf substituted`\nsecond line";
    for shell in ["/bin/sh", "/bin/bash", "/bin/zsh", "/bin/fish"] {
        let mut program = format!("printf '%s' {}", shell_quote(text));
        for depth in 0..4 {
            let output = Command::new(shell).args(["-c", &program]).output().unwrap();
            assert!(output.status.success(), "shell={shell} depth={depth}");
            assert_eq!(
                output.stdout,
                text.as_bytes(),
                "shell={shell} depth={depth}"
            );
            assert!(output.stderr.is_empty(), "shell={shell} depth={depth}");
            program = format!("sh -c {}", shell_quote(&program));
        }
    }
}
