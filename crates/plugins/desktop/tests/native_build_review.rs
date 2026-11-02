//! Checks native companion member declarations on hosts without the Apple SDK [D198,D203,D266].
use std::collections::BTreeMap;

#[test]
fn surface_capture_stored_properties_have_distinct_names() {
    let source = include_str!("../native/SurfaceCapture.swift");
    let mut declarations = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let Some(member) = line.strip_prefix("    private ") else {
            continue;
        };
        let Some(binding) = member
            .strip_prefix("let ")
            .or_else(|| member.strip_prefix("var "))
        else {
            continue;
        };
        let name = binding
            .split(|ch: char| !ch.is_alphanumeric() && ch != '_')
            .next()
            .unwrap_or_default();
        let line = index + 1;
        assert!(
            !declarations.contains_key(name),
            "SurfaceCapture stored property {name} is declared at lines {} and {line}; the queue and encoding state require distinct names",
            declarations.get(name).unwrap_or(&0)
        );
        declarations.insert(name, line);
    }
    assert!(declarations.len() > 10, "capture member scan is nonempty");
}

#[test]
fn window_targets_use_an_independent_capture_filter() {
    let source = include_str!("../native/SurfaceCapture.swift");
    assert!(
        source.contains("filter = SCContentFilter(desktopIndependentWindow: window)"),
        "window streams must bind ScreenCaptureKit to their selected window"
    );
    assert!(
        source.contains("sourceRect = nil"),
        "the system captures the full bounds of an independently filtered window"
    );
}
