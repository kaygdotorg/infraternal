#!/usr/bin/env python3
"""Fixture tests for scripts/doc-coverage: what counts as an item and what counts as documented (D345).

Each case feeds a tiny source file to the scanner and checks the per-kind (documented, total)
pairs and the code-line count. Run directly or through `scripts/verify`.
"""

import importlib.machinery
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
loader = importlib.machinery.SourceFileLoader("doc_coverage", os.path.join(HERE, "doc-coverage"))
spec = importlib.util.spec_from_loader("doc_coverage", loader)
dc = importlib.util.module_from_spec(spec)
loader.exec_module(dc)


def scan(fn, src):
    counts = dc.new_counts()
    loc = fn(src, counts)
    return {k: tuple(v) for k, v in counts.items()}, loc


RUST = '''//! Module doc.

/// Documented, with an attribute between.
#[inline]
pub fn a() {}

pub fn undocumented() {
    fn nested() {} // nested fns are not counted
}

/// A type.
pub struct S { f: u8 } // fields are not counted

impl S {
    /// A method.
    pub const fn m(&self) -> u8 { 0 }
    fn private(&self) {}
}

impl core::fmt::Display for S {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { Ok(()) } // trait impl: skipped
}

/// A constant. The string has "// not a comment" and a lifetime 'a below.
const C: &str = "// nope /* nope */";
static RAW: &str = r#"fn fake() {} /// not a doc"#;

mod inner {
    //! Inner modules document themselves with `//!`.
    pub fn deep() {}
}
'''

TS = '''/** Module doc, separated from the first item by a blank line. */

/** Documented. */
export function a() {}
function b() { const local = 1; function nested() {} }
export const arrow = (x: number) => x + 1;
/** A constant. */
export const VALUE = 3;
export class K {
    /** Method. */
    run() {}
    other(a: number) { if (a) { return /re\\/gex/.test("}"); } }
}
export interface I { x: number }
const tpl = `${"}"} {`;
'''

SWIFT = '''/// Role: what this file is for.
import Foundation

/// A documented type.
struct Box {
    /// A documented property.
    var width = 0
    func area() -> Int { return width }
}
func helper() {}
'''


class DocCoverage(unittest.TestCase):
    def test_rust(self):
        counts, loc = scan(dc.scan_rust, RUST)
        self.assertEqual(counts["mod"], (2, 2))  # the file and `mod inner`
        self.assertEqual(counts["fn"], (2, 5))  # a, m documented; undocumented, private, deep not; fmt/nested skipped
        self.assertEqual(counts["type"], (1, 1))
        self.assertEqual(counts["const"], (1, 2))
        self.assertEqual(loc, 18)  # no doc, plain-comment-only or blank lines

    def test_typescript(self):
        counts, _ = scan(dc.scan_ts, TS)
        self.assertEqual(counts["mod"], (1, 1))
        self.assertEqual(counts["fn"], (2, 5))  # a, run documented; b, arrow, other not; nested skipped
        self.assertEqual(counts["type"], (0, 2))  # K and I
        self.assertEqual(counts["const"], (1, 2))  # VALUE documented; tpl is not

    def test_typescript_first_item_comment_is_not_the_module_doc(self):
        counts, _ = scan(dc.scan_ts, "/** Only the item. */\nexport function f() {}\n")
        self.assertEqual((counts["mod"], counts["fn"]), ((0, 1), (1, 1)))

    def test_swift(self):
        counts, _ = scan(dc.scan_swift, SWIFT)
        self.assertEqual(counts["mod"], (1, 1))
        self.assertEqual(counts["type"], (1, 1))
        self.assertEqual(counts["const"], (1, 1))
        self.assertEqual(counts["fn"], (0, 2))  # area (member) and helper

    def test_ratchet_compares_exact_fractions(self):
        units = {"u": {"documented": 99, "total": 100}}
        self.assertEqual(dc.dropped(units, {"u": {"documented": 990, "total": 1000}}), [])
        self.assertEqual(dc.dropped(units, {"u": {"documented": 100, "total": 100}}), ["u"])
        self.assertEqual(dc.dropped(units, {"u": {"documented": 98, "total": 100}}), [])


if __name__ == "__main__":
    unittest.main()
