//! Applies stable-ID semantic intents to the existing JSON representation; storage supplies permanent close IDs [183,243].
use crate::model::{self, Document};
use serde_json::{Value, json};
fn is_closed(closed: &[String], id: &str) -> bool {
    closed.iter().any(|seen| seen == id)
}
fn s<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    model::string(value, key).ok_or(())
}
#[derive(Clone, Copy)]
enum IntentCheck {
    None,
    View,
    Window,
    Split,
    Resize,
    Weight,
    Pin,
}
struct IntentRule {
    fields: &'static [&'static str],
    strings: &'static [&'static str],
    check: IntentCheck,
}
fn intent_rule(kind: &str) -> Option<IntentRule> {
    // Keep shape and value checks in one kind dispatch so each intent has one
    // authoritative list of accepted and required keys.
    Some(match kind {
        "view.add" => IntentRule {
            fields: &["type", "view"],
            strings: &[],
            check: IntentCheck::View,
        },
        "view.remove" => IntentRule {
            fields: &["type", "view_id"],
            strings: &["view_id"],
            check: IntentCheck::None,
        },
        "open" => IntentRule {
            fields: &["type", "view_id", "column_id", "window", "after"],
            strings: &["view_id", "column_id"],
            check: IntentCheck::Window,
        },
        "split" => IntentRule {
            fields: &[
                "type",
                "view_id",
                "anchor_id",
                "axis",
                "column_id",
                "window",
            ],
            strings: &["view_id", "anchor_id", "axis", "column_id"],
            check: IntentCheck::Split,
        },
        "close" => IntentRule {
            fields: &["type", "window_id"],
            strings: &["window_id"],
            check: IntentCheck::None,
        },
        "move" | "membership.add" => IntentRule {
            fields: &["type", "view_id", "window_id", "column_id", "after"],
            strings: &["view_id", "window_id", "column_id"],
            check: IntentCheck::None,
        },
        "resize" => IntentRule {
            fields: &["type", "window_id", "height", "span", "rows", "row"],
            strings: &["window_id"],
            check: IntentCheck::Resize,
        },
        "weight" => IntentRule {
            fields: &["type", "view_id", "column_id", "weight"],
            strings: &["view_id", "column_id"],
            check: IntentCheck::Weight,
        },
        "membership.remove" => IntentRule {
            fields: &["type", "view_id", "window_id"],
            strings: &["view_id", "window_id"],
            check: IntentCheck::None,
        },
        "pin" => IntentRule {
            fields: &["type", "view_id", "node_id", "position"],
            strings: &["view_id", "node_id"],
            check: IntentCheck::Pin,
        },
        _ => return None,
    })
}
fn check_intent(value: &Value, check: IntentCheck) -> bool {
    match check {
        IntentCheck::View => value.get("view").is_some_and(model::view),
        IntentCheck::Window | IntentCheck::Split => {
            value.get("window").is_some_and(model::window)
                && (matches!(check, IntentCheck::Window)
                    || matches!(model::string(value, "axis"), Some("right" | "down")))
        }
        IntentCheck::Resize => [
            ("height", 0.05, 10_000.0, false),
            ("span", 1.0, 64.0, true),
            ("rows", 1.0, 64.0, true),
            ("row", 0.0, 64.0, true),
        ]
        .iter()
        .all(|(key, lo, hi, whole)| {
            value.get(key).is_none_or(|v| {
                v.is_null()
                    || v.as_f64()
                        .is_some_and(|n| model::finite(n, *lo, *hi) && (!whole || n.fract() == 0.0))
            })
        }),
        IntentCheck::Weight => model::numeric(value, "weight", 0.1, 10.0),
        IntentCheck::Pin => value
            .get("position")
            .is_none_or(|p| p.is_null() || model::point(p, 100_000.0)),
        IntentCheck::None => true,
    }
}
#[must_use]
pub fn valid_intent(value: &Value) -> bool {
    let Some(kind) = model::string(value, "type") else {
        return false;
    };
    let Some(rule) = intent_rule(kind) else {
        return false;
    };
    if !model::shape(value, rule.fields)
        || !rule
            .strings
            .iter()
            .all(|key| model::string(value, key).is_some())
        || value
            .get("after")
            .is_some_and(|v| !v.is_null() && !v.as_str().is_some_and(model::text))
    {
        return false;
    }
    check_intent(value, rule.check)
}
fn columns<'a>(doc: &'a mut Document, id: &str) -> Result<&'a mut Vec<Value>, ()> {
    let view = doc
        .0
        .get_mut("views")
        .and_then(Value::as_array_mut)
        .ok_or(())?
        .iter_mut()
        .find(|v| model::string(v, "id") == Some(id))
        .ok_or(())?;
    view.get_mut("layout")
        .and_then(|l| l.get_mut("columns"))
        .and_then(Value::as_array_mut)
        .ok_or(())
}
fn insert(
    cols: &mut Vec<Value>,
    column_id: &str,
    window: Value,
    after: Option<&str>,
) -> Result<(), ()> {
    if cols
        .iter()
        .flat_map(model::windows)
        .any(|w| w.get("id") == window.get("id"))
    {
        return Err(());
    }
    if !cols
        .iter()
        .any(|c| model::string(c, "id") == Some(column_id))
    {
        cols.push(json!({"id":column_id,"weight":1.0,"windows":[]}));
    }
    let col = cols
        .iter_mut()
        .find(|c| model::string(c, "id") == Some(column_id))
        .ok_or(())?;
    let wins = col
        .get_mut("windows")
        .and_then(Value::as_array_mut)
        .ok_or(())?;
    let offset = after.map_or(0, |id| {
        wins.iter()
            .position(|w| model::string(w, "id") == Some(id))
            .map_or(wins.len(), |i| i + 1)
    });
    wins.insert(offset, window);
    Ok(())
}
fn remove(cols: &mut [Value], id: &str) -> Option<Value> {
    for col in cols {
        let wins = col.get_mut("windows")?.as_array_mut()?;
        if let Some(at) = wins.iter().position(|w| model::string(w, "id") == Some(id)) {
            return Some(wins.remove(at));
        }
    }
    None
}
/// Reduces against current state. The caller discards the working document on any error.
/// # Errors
/// Refuses invalid bounds, missing destinations and reuse of stable IDs.
#[allow(clippy::result_unit_err, clippy::too_many_lines)]
pub fn reduce(doc: &mut Document, intent: &Value, closed: &[String]) -> Result<(), ()> {
    if !doc.valid() || !valid_intent(intent) {
        return Err(());
    }
    let kind = s(intent, "type")?;
    match kind {
        "view.add" => {
            let view = intent.get("view").ok_or(())?;
            let empty = view
                .get("layout")
                .is_some_and(|l| match model::string(l, "type") {
                    Some("tiled") => l
                        .get("columns")
                        .and_then(Value::as_array)
                        .is_some_and(Vec::is_empty),
                    Some("graph") => l
                        .get("pinned")
                        .and_then(Value::as_object)
                        .is_some_and(serde_json::Map::is_empty),
                    _ => false,
                });
            if !empty || model::views(&doc.0).any(|v| v.get("id") == view.get("id")) {
                return Err(());
            }
            doc.0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .push(view.clone());
        }
        "view.remove" => {
            let id = s(intent, "view_id")?;
            doc.0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .retain(|v| model::string(v, "id") != Some(id));
        }
        "open" | "split" => {
            let window = intent.get("window").ok_or(())?;
            let id = s(window, "id")?;
            if is_closed(closed, id) || doc.windows().any(|w| model::string(w, "id") == Some(id)) {
                return Err(());
            }
            if kind == "split" && is_closed(closed, s(intent, "anchor_id")?) {
                return Ok(());
            }
            let cols = columns(doc, s(intent, "view_id")?)?;
            if kind == "open" {
                insert(
                    cols,
                    s(intent, "column_id")?,
                    window.clone(),
                    model::string(intent, "after"),
                )?;
            } else {
                crate::tiling::split(
                    cols,
                    s(intent, "anchor_id")?,
                    s(intent, "axis")?,
                    s(intent, "column_id")?,
                    window.clone(),
                )?;
            }
        }
        "close" => {
            let id = s(intent, "window_id")?;
            for view in doc
                .0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
            {
                if let Some(cols) = view
                    .get_mut("layout")
                    .and_then(|l| l.get_mut("columns"))
                    .and_then(Value::as_array_mut)
                {
                    remove(cols, id);
                }
            }
        }
        "move" => {
            let id = s(intent, "window_id")?;
            if is_closed(closed, id) {
                return Ok(());
            }
            let cols = columns(doc, s(intent, "view_id")?)?;
            if let Some(window) = remove(cols, id) {
                insert(
                    cols,
                    s(intent, "column_id")?,
                    window,
                    model::string(intent, "after"),
                )?;
            }
        }
        "resize" => {
            let id = s(intent, "window_id")?;
            if is_closed(closed, id) {
                return Ok(());
            }
            for view in doc
                .0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
            {
                if let Some(cols) = view
                    .get_mut("layout")
                    .and_then(|l| l.get_mut("columns"))
                    .and_then(Value::as_array_mut)
                {
                    for col in cols {
                        for window in col
                            .get_mut("windows")
                            .and_then(Value::as_array_mut)
                            .ok_or(())?
                        {
                            if model::string(window, "id") == Some(id) {
                                for field in ["height", "span", "rows", "row"] {
                                    if let Some(value) = intent.get(field).filter(|v| !v.is_null())
                                    {
                                        window[field] = value.clone();
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "weight" => {
            let cols = columns(doc, s(intent, "view_id")?)?;
            if let Some(col) = cols
                .iter_mut()
                .find(|c| model::string(c, "id") == model::string(intent, "column_id"))
            {
                col["weight"] = intent["weight"].clone();
            }
        }
        "membership.add" => {
            let id = s(intent, "window_id")?;
            if is_closed(closed, id) {
                return Ok(());
            }
            let window = doc
                .windows()
                .find(|w| model::string(w, "id") == Some(id))
                .cloned()
                .ok_or(())?;
            insert(
                columns(doc, s(intent, "view_id")?)?,
                s(intent, "column_id")?,
                window,
                model::string(intent, "after"),
            )?;
        }
        "membership.remove" => {
            remove(
                columns(doc, s(intent, "view_id")?)?,
                s(intent, "window_id")?,
            );
        }
        "pin" => {
            let view = doc
                .0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .iter_mut()
                .find(|v| model::string(v, "id") == model::string(intent, "view_id"))
                .ok_or(())?;
            let pins = view
                .get_mut("layout")
                .and_then(|l| l.get_mut("pinned"))
                .and_then(Value::as_object_mut)
                .ok_or(())?;
            let id = s(intent, "node_id")?;
            if let Some(position) = intent.get("position").filter(|v| !v.is_null()) {
                pins.insert(id.into(), position.clone());
            } else {
                pins.remove(id);
            }
        }
        _ => return Err(()),
    }
    if doc.valid() { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn document() -> Document {
        Document(
            json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[{"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[]}}]}),
        )
    }
    fn open(id: &str) -> Value {
        json!({"type":"open","view_id":"console","column_id":id,"window":{"id":id,"target":{"type":"settings","section":"appearance"}}})
    }
    #[test]
    fn independent_edits_commute_and_close_wins_in_both_orders() {
        for sample in 0..128 {
            let a = format!("a{sample}");
            let b = format!("b{sample}");
            let mut doc = document();
            let closed = Vec::new();
            reduce(&mut doc, &open(&a), &closed).unwrap();
            reduce(&mut doc, &open(&b), &closed).unwrap();
            let resize = json!({"type":"resize","window_id":a,"height":2.0});
            let moved =
                json!({"type":"move","view_id":"console","window_id":b,"column_id":a,"after":a});
            let mut left = doc.clone();
            let mut right = doc.clone();
            reduce(&mut left, &resize, &closed).unwrap();
            reduce(&mut left, &moved, &closed).unwrap();
            reduce(&mut right, &moved, &closed).unwrap();
            reduce(&mut right, &resize, &closed).unwrap();
            assert_eq!(left, right);
            let close = json!({"type":"close","window_id":a});
            let tombstones = vec![a.clone()];
            reduce(&mut left, &close, &closed).unwrap();
            reduce(&mut left, &resize, &tombstones).unwrap();
            reduce(&mut right, &resize, &closed).unwrap();
            reduce(&mut right, &close, &closed).unwrap();
            assert_eq!(left, right);
            assert!(!left.windows().any(|w| w["id"] == a));
            assert!(reduce(&mut left, &open(&a), &tombstones).is_err());
        }
    }
    #[test]
    fn split_divides_only_its_own_band() {
        let mut doc = document();
        let closed = Vec::new();
        reduce(&mut doc, &open("a"), &closed).unwrap();
        let mut b = open("b");
        b["column_id"] = json!("a");
        b["after"] = json!("a");
        reduce(&mut doc, &b, &closed).unwrap();
        let split = json!({"type":"split","view_id":"console","anchor_id":"b","axis":"right","column_id":"right","window":{"id":"new","target":{"type":"settings","section":"appearance"}}});
        reduce(&mut doc, &split, &closed).unwrap();
        assert_eq!(doc.windows().find(|w| w["id"] == "a").unwrap()["span"], 2);
        assert_eq!(doc.windows().find(|w| w["id"] == "b").unwrap()["row"], 1);
        assert_eq!(doc.windows().find(|w| w["id"] == "new").unwrap()["row"], 1);
    }
    #[test]
    fn sample_corpus_preserves_strict_variant_fields_and_round_trips() {
        for value in [
            json!({"type":"resize","window_id":"w","height":2.0,"rows":2}),
            json!({"type":"pin","view_id":"mesh","node_id":"n","position":{"x":1,"y":2}}),
            open("w"),
        ] {
            assert!(valid_intent(&value));
            let bytes = serde_json::to_vec(&value).unwrap();
            assert_eq!(value, serde_json::from_slice::<Value>(&bytes).unwrap());
        }
        for value in [
            json!({"type":"close","window_id":"w","account":"b"}),
            json!({"type":"resize","window_id":"w","span":1.5}),
            json!({"type":"open","view_id":"v","column_id":"c","window":{"id":"w","target":{"type":"settings","section":"a","id":"other"}}}),
        ] {
            assert!(!valid_intent(&value));
        }
    }
}
