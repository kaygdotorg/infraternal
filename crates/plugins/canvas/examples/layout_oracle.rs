//! Test-only line bridge exposing the shipping reducer, including rollback and close history (#243).
#![allow(clippy::unwrap_used, clippy::expect_used)]
use infraternal_plugin_canvas::{model::Document, reducer::reduce};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};

/// Reads one JSON object per stdin line with a `document` and a list of
/// `intents`. Replays the intents in order and writes one line per input: an
/// array with, for each intent, `{"accepted": bool, "document": ...}` where the
/// document is the state after that intent. Accepted `close` intents are
/// remembered so later intents can be refused for already-closed windows.
/// Panics on malformed input; this is a test tool, not a service.
fn main() {
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in io::stdin().lock().lines() {
        let input: Value = serde_json::from_str(&line.unwrap()).unwrap();
        let mut document = Document(input["document"].clone());
        assert!(document.valid());
        let mut closed = Vec::new();
        let mut results = Vec::new();
        for intent in input["intents"].as_array().unwrap() {
            // Storage reduces a clone and commits only success; a refusal never changes canonical state.
            let mut next = document.clone();
            let accepted = reduce(&mut next, intent, &closed).is_ok();
            if accepted {
                if intent["type"] == "close" {
                    closed.push(intent["window_id"].as_str().unwrap().to_owned());
                }
                document = next;
            }
            results.push(json!({"accepted":accepted,"document":document}));
        }
        serde_json::to_writer(&mut out, &results).unwrap();
        writeln!(out).unwrap();
    }
}
