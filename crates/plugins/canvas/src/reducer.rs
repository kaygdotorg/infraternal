//! Applies stable-ID semantic intents to the existing JSON representation; storage supplies permanent close IDs [183,243].
use crate::model::{self, Document};
use serde_json::Value;
fn is_closed(closed: &[String], id: &str) -> bool {
    closed.iter().any(|seen| seen == id)
}
fn s<'a>(value: &'a Value, key: &str) -> Result<&'a str, ()> {
    model::string(value, key).ok_or(())
}
/// Carries the validated type into reduction without reparsing its JSON string.
#[derive(Clone, Copy, PartialEq, Eq)]
enum IntentKind {
    ViewAdd,
    ViewRemove,
    ViewUpdate,
    Target,
    Open,
    Split,
    Close,
    Move,
    MembershipAdd,
    Resize,
    Weight,
    MembershipRemove,
    Pin,
    Look,
}
struct IntentRule {
    kind: IntentKind,
    fields: &'static [&'static str],
    strings: &'static [&'static str],
}
// One table row per intent in a single match is the point (each intent has one authoritative list of keys); a new intent is a new row, not a new function.
#[allow(clippy::too_many_lines)]
fn intent_rule(kind: &str) -> Option<IntentRule> {
    // Keep shape and value checks in one kind dispatch so each intent has one
    // authoritative list of accepted and required keys.
    Some(match kind {
        "view.add" => IntentRule {
            kind: IntentKind::ViewAdd,
            fields: &["type", "view"],
            strings: &[],
        },
        "view.remove" => IntentRule {
            kind: IntentKind::ViewRemove,
            fields: &["type", "view_id"],
            strings: &["view_id"],
        },
        "view.update" => IntentRule {
            kind: IntentKind::ViewUpdate,
            fields: &["type", "view_id", "cell", "name"],
            strings: &["view_id"],
        },
        "target" => IntentRule {
            kind: IntentKind::Target,
            fields: &["type", "window_id", "target"],
            strings: &["window_id"],
        },
        "open" => IntentRule {
            kind: IntentKind::Open,
            fields: &[
                "type",
                "view_id",
                "column_id",
                "window",
                "after",
                "column_after",
            ],
            strings: &["view_id", "column_id"],
        },
        "split" => IntentRule {
            kind: IntentKind::Split,
            fields: &[
                "type",
                "view_id",
                "anchor_id",
                "axis",
                "column_id",
                "window",
            ],
            strings: &["view_id", "anchor_id", "axis", "column_id"],
        },
        "close" => IntentRule {
            kind: IntentKind::Close,
            fields: &["type", "window_id"],
            strings: &["window_id"],
        },
        "move" => IntentRule {
            kind: IntentKind::Move,
            fields: &[
                "type",
                "view_id",
                "window_id",
                "column_id",
                "after",
                "column_after",
            ],
            strings: &["view_id", "window_id", "column_id"],
        },
        "membership.add" => IntentRule {
            kind: IntentKind::MembershipAdd,
            fields: &[
                "type",
                "view_id",
                "window_id",
                "column_id",
                "after",
                "column_after",
            ],
            strings: &["view_id", "window_id", "column_id"],
        },
        "resize" => IntentRule {
            kind: IntentKind::Resize,
            fields: &["type", "window_id", "height", "span", "rows", "row"],
            strings: &["window_id"],
        },
        "weight" => IntentRule {
            kind: IntentKind::Weight,
            fields: &["type", "view_id", "column_id", "weight"],
            strings: &["view_id", "column_id"],
        },
        "membership.remove" => IntentRule {
            kind: IntentKind::MembershipRemove,
            fields: &["type", "view_id", "window_id"],
            strings: &["view_id", "window_id"],
        },
        "pin" => IntentRule {
            kind: IntentKind::Pin,
            fields: &["type", "view_id", "node_id", "position"],
            strings: &["view_id", "node_id"],
        },
        "look.set" => IntentRule {
            kind: IntentKind::Look,
            fields: &["type", "look"],
            strings: &[],
        },
        _ => return None,
    })
}
fn check_intent(value: &Value, kind: IntentKind) -> bool {
    match kind {
        IntentKind::ViewAdd => value.get("view").is_some_and(model::view),
        IntentKind::ViewUpdate => {
            value.get("cell").is_none_or(|p| model::point(p, 1000.0))
                && value
                    .get("name")
                    .is_none_or(|v| v.as_str().is_some_and(model::text))
        }
        IntentKind::Target => value.get("target").is_some_and(model::target),
        IntentKind::Open | IntentKind::Split => {
            value.get("window").is_some_and(model::window)
                && (matches!(kind, IntentKind::Open)
                    || matches!(model::string(value, "axis"), Some("right" | "down")))
        }
        IntentKind::Resize => [
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
        IntentKind::Weight => model::numeric(value, "weight", 0.1, 10.0),
        IntentKind::Look => value.get("look").is_some_and(model::look),
        IntentKind::Pin => value
            .get("position")
            .is_none_or(|p| p.is_null() || model::point(p, 100_000.0)),
        _ => true,
    }
}
fn validated_intent(value: &Value) -> Option<IntentRule> {
    let rule = intent_rule(model::string(value, "type")?)?;
    if !model::shape(value, rule.fields)
        || !rule
            .strings
            .iter()
            .all(|key| model::string(value, key).is_some())
        || ["after", "column_after"].iter().any(|key| {
            value
                .get(key)
                .is_some_and(|v| !v.is_null() && !v.as_str().is_some_and(model::text))
        })
    {
        return None;
    }
    check_intent(value, rule.kind).then_some(rule)
}
#[must_use]
pub fn valid_intent(value: &Value) -> bool {
    validated_intent(value).is_some()
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
    column_after: Option<&Value>,
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
        let at = column_after.map_or(cols.len(), |value| {
            value.as_str().map_or(0, |id| {
                cols.iter()
                    .position(|c| model::string(c, "id") == Some(id))
                    .map_or(cols.len(), |i| i + 1)
            })
        });
        cols.insert(at, model::column(column_id, 1.0, Vec::new()));
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
/// Empty tracks crossed by a span remain part of the grid; other empty columns no longer consume capacity.
#[allow(clippy::cast_precision_loss)]
fn prune(columns: &mut Vec<Value>) {
    // Validation bounds the difference to at most 64, exactly representable in f64.
    for at in (0..columns.len()).rev() {
        let covered = columns[..at].iter().enumerate().any(|(from, col)| {
            model::windows(col)
                .any(|w| w.get("span").and_then(Value::as_f64).unwrap_or(1.0) > (at - from) as f64)
        });
        if model::windows(&columns[at]).next().is_none() && !covered {
            columns.remove(at);
        }
    }
}
/// Reduces against current state. The caller discards the working document on any error.
/// # Errors
/// Refuses invalid bounds, missing destinations and reuse of stable IDs.
#[allow(clippy::result_unit_err)]
pub fn reduce(doc: &mut Document, intent: &Value, closed: &[String]) -> Result<(), ()> {
    if !doc.valid() {
        return Err(());
    }
    let kind = validated_intent(intent).ok_or(())?.kind;
    match kind {
        IntentKind::ViewAdd => {
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
            if !empty {
                return Err(());
            }
            if let Some(existing) = model::views(&doc.0).find(|v| v.get("id") == view.get("id")) {
                // Stable built-in IDs can be offered concurrently; existing contents remain canonical.
                return if existing.get("kind") == view.get("kind")
                    && existing["layout"]["type"] == view["layout"]["type"]
                {
                    Ok(())
                } else {
                    Err(())
                };
            }
            doc.0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .push(view.clone());
        }
        IntentKind::ViewUpdate => {
            let id = s(intent, "view_id")?;
            if let Some(view) = doc
                .0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .iter_mut()
                .find(|v| model::string(v, "id") == Some(id))
            {
                for field in ["cell", "name"] {
                    if let Some(value) = intent.get(field) {
                        view[field] = value.clone();
                    }
                }
            }
        }
        IntentKind::Target => {
            let id = s(intent, "window_id")?;
            if !is_closed(closed, id) {
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
                                    window["target"] = intent["target"].clone();
                                }
                            }
                        }
                    }
                }
            }
        }
        IntentKind::ViewRemove => {
            let id = s(intent, "view_id")?;
            doc.0
                .get_mut("views")
                .and_then(Value::as_array_mut)
                .ok_or(())?
                .retain(|v| model::string(v, "id") != Some(id));
        }
        IntentKind::Open | IntentKind::Split => {
            let window = intent.get("window").ok_or(())?;
            let id = s(window, "id")?;
            if is_closed(closed, id) || doc.windows().any(|w| model::string(w, "id") == Some(id)) {
                return Err(());
            }
            if kind == IntentKind::Split && is_closed(closed, s(intent, "anchor_id")?) {
                return Ok(());
            }
            let cols = columns(doc, s(intent, "view_id")?)?;
            if kind == IntentKind::Open {
                insert(
                    cols,
                    s(intent, "column_id")?,
                    window.clone(),
                    model::string(intent, "after"),
                    intent.get("column_after"),
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
        IntentKind::Close => {
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
        IntentKind::Move => {
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
                    intent.get("column_after"),
                )?;
            }
        }
        IntentKind::Resize => {
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
        IntentKind::Weight => {
            let cols = columns(doc, s(intent, "view_id")?)?;
            if let Some(col) = cols
                .iter_mut()
                .find(|c| model::string(c, "id") == model::string(intent, "column_id"))
            {
                col["weight"] = intent["weight"].clone();
            }
        }
        IntentKind::MembershipAdd => {
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
                intent.get("column_after"),
            )?;
        }
        IntentKind::MembershipRemove => {
            remove(
                columns(doc, s(intent, "view_id")?)?,
                s(intent, "window_id")?,
            );
        }
        IntentKind::Pin => {
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
        IntentKind::Look => {
            // The whole look is replaced: the server orders edits, so the last one to arrive is the account's look on every device.
            doc.0["look"] = intent.get("look").ok_or(())?.clone();
        }
    }
    if matches!(
        kind,
        IntentKind::Close | IntentKind::Move | IntentKind::MembershipRemove
    ) {
        for view in doc
            .0
            .get_mut("views")
            .and_then(Value::as_array_mut)
            .ok_or(())?
        {
            if let Some(columns) = view
                .get_mut("layout")
                .and_then(|l| l.get_mut("columns"))
                .and_then(Value::as_array_mut)
            {
                prune(columns);
            }
        }
    }
    if doc.valid() { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
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
    fn view_metadata_targets_and_column_neighbours_are_semantic() {
        let mut doc = document();
        reduce(&mut doc, &open("a"), &[]).unwrap();
        let mut b = open("b");
        b["column_after"] = Value::Null;
        reduce(&mut doc, &b, &[]).unwrap();
        assert_eq!(doc.0["views"][0]["layout"]["columns"][0]["id"], "b");
        reduce(
            &mut doc,
            &json!({"type":"view.update","view_id":"console","cell":{"x":2,"y":3},"name":"Work"}),
            &[],
        )
        .unwrap();
        assert_eq!(doc.0["views"][0]["cell"], json!({"x":2,"y":3}));
        let target = json!({"type":"settings","section":"shortcuts"});
        reduce(
            &mut doc,
            &json!({"type":"target","window_id":"a","target":target}),
            &[],
        )
        .unwrap();
        assert_eq!(
            doc.windows().find(|w| w["id"] == "a").unwrap()["target"],
            target
        );
        reduce(&mut doc, &json!({"type":"close","window_id":"a"}), &[]).unwrap();
        reduce(
            &mut doc,
            &json!({"type":"target","window_id":"a","target":target}),
            &["a".into()],
        )
        .unwrap();
        assert!(!doc.windows().any(|w| w["id"] == "a"));
        assert!(!valid_intent(
            &json!({"type":"view.update","view_id":"console","cell":{"x":1001,"y":0}})
        ));
        assert!(!valid_intent(
            &json!({"type":"target","window_id":"a","target":{"type":"unknown"}})
        ));
    }
    #[test]
    fn concurrent_builtin_view_creation_preserves_existing_contents() {
        let mut doc = document();
        reduce(&mut doc, &open("window"), &[]).unwrap();
        let before = doc.clone();
        let mut view = doc.0["views"][0].clone();
        view["layout"]["columns"] = json!([]);
        reduce(&mut doc, &json!({"type":"view.add","view":view}), &[]).unwrap();
        assert_eq!(doc, before);
        view["layout"] = json!({"type":"graph","pinned":{}});
        assert!(reduce(&mut doc, &json!({"type":"view.add","view":view}), &[]).is_err());
    }
    #[test]
    fn repeated_open_close_does_not_exhaust_column_capacity() {
        let mut doc = document();
        for i in 0..70 {
            let id = format!("window-{i}");
            reduce(&mut doc, &open(&id), &[]).unwrap();
            reduce(&mut doc, &json!({"type":"close","window_id":id}), &[]).unwrap();
        }
        assert_eq!(doc.0["views"][0]["layout"]["columns"], json!([]));
    }
    #[test]
    fn nullable_resize_preserves_existing_values_and_absent_fields() {
        let mut doc = document();
        reduce(&mut doc, &open("a"), &[]).unwrap();
        reduce(
            &mut doc,
            &json!({"type":"resize","window_id":"a","height":null,"rows":2}),
            &[],
        )
        .unwrap();
        let window = doc.windows().next().unwrap();
        assert!(window.get("height").is_none());
        assert_eq!(window["rows"], 2);
        reduce(
            &mut doc,
            &json!({"type":"resize","window_id":"a","height":3,"span":2,"row":1}),
            &[],
        )
        .unwrap();
        let before = doc.clone();
        reduce(&mut doc, &json!({"type":"resize","window_id":"a","height":null,"span":null,"rows":null,"row":null}), &[]).unwrap();
        assert_eq!(doc, before);
        assert!(doc.valid());
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

    fn look() -> Value {
        let theme = |id: &str| json!({"id":id,"name":id,"tint":75,"blur":25,"grain":0,"font":"maple-mono-nf","colors":"mocha","uiSize":100,"background":"aurora","customSolid":"#3b4252","custom":{"stops":["#7a9cff","#cba6f7"],"angle":135}});
        json!({"v":1,"selected":"tinted","basics":{"colors":"mocha","font":"maple-mono-nf","uiSize":100},"themes":[theme("solid"),theme("tinted"),theme("custom-1")]})
    }
    #[test]
    fn the_accounts_look_is_set_whole_validated_and_part_of_the_document() {
        let mut doc = document();
        assert!(
            doc.0.get("look").is_none(),
            "a document without a look is still valid"
        );
        let intent = json!({"type":"look.set","look":look()});
        assert!(valid_intent(&intent));
        reduce(&mut doc, &intent, &[]).unwrap();
        assert_eq!(doc.0["look"], look());
        assert!(doc.valid());
        // Setting it again changes nothing (a no-op does not make a new revision), and a later look replaces the earlier one whole.
        let before = doc.clone();
        reduce(&mut doc, &intent, &[]).unwrap();
        assert_eq!(doc, before);
        let mut next = look();
        next["selected"] = json!("custom-1");
        next["themes"].as_array_mut().unwrap().pop();
        reduce(&mut doc, &json!({"type":"look.set","look":next}), &[]).unwrap();
        assert_eq!(doc.0["look"]["themes"].as_array().unwrap().len(), 2);
    }
    #[test]
    fn a_look_out_of_bounds_is_refused_and_leaves_the_document_alone() {
        let mut doc = document();
        let bad = |edit: &dyn Fn(&mut Value)| {
            let mut value = look();
            edit(&mut value);
            json!({"type":"look.set","look":value})
        };
        let cases = [
            bad(&|v| v["themes"][0]["tint"] = json!(101)),
            bad(&|v| v["themes"][0]["blur"] = json!(-1)),
            bad(&|v| v["themes"][0]["grain"] = json!(12.5)),
            bad(&|v| v["themes"][0]["uiSize"] = json!(10)),
            bad(&|v| v["basics"]["uiSize"] = json!(900)),
            bad(&|v| v["themes"][0]["customSolid"] = json!("red")),
            bad(&|v| v["themes"][0]["custom"]["stops"] = json!(["#ffffff"])),
            bad(&|v| {
                v["themes"][0]["custom"]["stops"] =
                    json!(["#ffffff", "#000000", "#111111", "#222222", "#333333"]);
            }),
            bad(&|v| v["themes"][0]["custom"]["angle"] = json!(361)),
            bad(&|v| v["themes"][0]["name"] = json!("x".repeat(201))),
            bad(&|v| v["themes"][0]["extra"] = json!(1)),
            bad(&|v| v["themes"][1]["id"] = json!("solid")),
            bad(&|v| v["v"] = json!(2)),
            bad(&|v| {
                let t = v["themes"][0].clone();
                for n in 0..16 {
                    let mut c = t.clone();
                    c["id"] = json!(format!("n{n}"));
                    v["themes"].as_array_mut().unwrap().push(c);
                }
            }),
            json!({"type":"look.set"}),
            json!({"type":"look.set","look":look(),"extra":1}),
        ];
        for case in &cases {
            assert!(!valid_intent(case), "{case}");
            assert!(reduce(&mut doc, case, &[]).is_err());
        }
        assert_eq!(doc, document());
        // A document that carries an out-of-range look is not a valid document either.
        doc.0["look"] = look();
        doc.0["look"]["themes"][0]["tint"] = json!(500);
        assert!(!doc.valid());
    }
    #[test]
    fn a_full_look_fits_in_one_intent() {
        let mut value = look();
        let one = value["themes"][0].clone();
        let list = value["themes"].as_array_mut().unwrap();
        list.clear();
        for n in 0..16 {
            let mut t = one.clone();
            t["id"] = json!(format!("custom-{n}"));
            t["name"] = json!("A theme with a long name");
            t["font"] = json!("fantasque-sans-mono");
            list.push(t);
        }
        let intent = json!({"type":"look.set","look":value});
        assert!(valid_intent(&intent));
        assert!(
            intent.to_string().len() < crate::model::MAX_INPUT,
            "{} bytes",
            intent.to_string().len()
        );
    }
}
