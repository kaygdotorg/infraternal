//! Merges first-device imports and recognizes historical recovery views without duplicating targets [178,180,248].
use infraternal_plugin_canvas::model::{Document, string};
use serde_json::Value;

/// Presentation metadata never makes a target new. Prefer stable host identities when both references carry them.
fn same_target(a: &Value, b: &Value) -> bool {
    if a["type"] != b["type"] {
        return false;
    }
    match string(a, "type") {
        Some("session") => {
            a["id"] == b["id"]
                && match (a.get("hostId"), b.get("hostId")) {
                    (Some(a), Some(b)) => a == b,
                    _ => a["host"] == b["host"],
                }
        }
        Some("settings") => a["section"] == b["section"],
        _ => a["host"] == b["host"],
    }
}

/// Only import absent targets; a second device never replaces canonical order, names, geometry or graph pins.
#[cold]
pub(super) fn merge(document: &mut Document, mut incoming: Document) -> Result<(), ()> {
    let mut seen: Vec<Value> = document.windows().map(|w| w["target"].clone()).collect();
    let views = document.0["views"].as_array_mut().ok_or(())?;
    for mut view in incoming.0["views"].as_array_mut().ok_or(())?.drain(..) {
        let Some(columns) = view["layout"]["columns"].as_array_mut() else {
            continue;
        };
        // Keep empty tracks only while a retained spanning window crosses them.
        let mut end = 0;
        let mut retained = Vec::new();
        for (index, mut column) in columns.drain(..).enumerate() {
            let windows = column["windows"].as_array_mut().ok_or(())?;
            windows.retain_mut(|window| {
                let target = &window["target"];
                if seen.iter().any(|old| same_target(old, target)) {
                    return false;
                }
                seen.push(target.clone());
                end = end.max(
                    index + usize::try_from(window["span"].as_u64().unwrap_or(1)).unwrap_or(64),
                );
                // Imported IDs cannot collide with canonical memberships or durable close tombstones.
                window["id"] = Value::from(uuid::Uuid::new_v4().to_string());
                true
            });
            if !windows.is_empty() || index < end {
                column["id"] = Value::from(uuid::Uuid::new_v4().to_string());
                retained.push(column);
            }
        }
        if retained.is_empty() {
            continue;
        }
        let same_kind = |v: &Value| v["kind"] == view["kind"] && v["layout"]["type"] == "tiled";
        let name = string(&view, "name").unwrap_or("");
        let destination = views
            .iter()
            .position(|v| {
                same_kind(v)
                    && (v["name"] == name
                        || name
                            .strip_prefix("Recovered: ")
                            .is_some_and(|base| v["name"] == base))
            })
            .or_else(|| views.iter().position(same_kind));
        if let Some(index) = destination {
            views[index]["layout"]["columns"]
                .as_array_mut()
                .ok_or(())?
                .extend(retained);
        } else {
            // Graphs cannot gain tiled memberships; refuse instead of duplicating that kind.
            if views.iter().any(|v| v["kind"] == view["kind"]) {
                return Err(());
            }
            // A surviving stale-device copy becomes an ordinary view, even if its original is gone.
            let mut base = name;
            while let Some(rest) = base.strip_prefix("Recovered: ") {
                base = rest;
            }
            if base != name {
                view["name"] = Value::from(base);
            }
            if views.iter().any(|v| v["id"] == view["id"]) {
                view["id"] = Value::from(uuid::Uuid::new_v4().to_string());
            }
            view["layout"]["columns"] = Value::Array(retained);
            views.push(view);
        }
    }
    Ok(())
}

/// Only exact prefix/base-name/kind pairs identify historical recovery output.
// Both the load probe and write repair use the same recognition invariant.
#[inline(never)]
fn recovered(views: &[Value], view: &Value) -> bool {
    string(view, "name")
        .and_then(|name| name.strip_prefix("Recovered: "))
        .is_some_and(|name| {
            views.iter().any(|original| {
                original["id"] != view["id"]
                    && original["kind"] == view["kind"]
                    && original["name"] == name
            })
        })
}

#[cold]
pub(super) fn needed(document: &Document) -> bool {
    document.0["views"]
        .as_array()
        .is_some_and(|views| views.iter().any(|view| recovered(views, view)))
}

/// Prefix alone is insufficient: a recovery view must also name an existing view of its original kind.
/// Removing those views before merging excludes their own duplicate targets from the canonical seen set.
/// A committed snapshot records their removal, so repeated loads and stale-device imports converge idempotently.
pub(super) fn repair(document: &mut Document) -> Result<bool, ()> {
    let views = document.0["views"].as_array().ok_or(())?;
    let ids: Vec<Value> = views
        .iter()
        .filter(|view| recovered(views, view))
        .map(|v| v["id"].clone())
        .collect();
    if ids.is_empty() {
        return Ok(false);
    }
    let mut recovered = Document::default();
    let incoming = recovered.0["views"].as_array_mut().ok_or(())?;
    document.0["views"]
        .as_array_mut()
        .ok_or(())?
        .retain(|view| {
            if ids.contains(&view["id"]) {
                incoming.push(view.clone());
                false
            } else {
                true
            }
        });
    merge(document, recovered)?;
    Ok(true)
}
