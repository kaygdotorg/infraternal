//! Merges first-device imports and recognizes historical recovery views without duplicating targets [178,180,248].
use infraternal_plugin_canvas::model::{Document, MAX_DOCUMENT, string};
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

/// Share UUID generation and JSON assignment across membership, column and view imports [243].
#[inline(never)]
fn fresh_id(value: &mut Value) {
    value["id"] = Value::from(uuid::Uuid::new_v4().to_string());
}

/// Only import absent targets; a second device never replaces canonical order, names, geometry or graph pins.
pub(super) fn merge(
    document: &mut Document,
    incoming: Vec<Value>,
    imported: bool,
) -> Result<(), ()> {
    let mut seen: Vec<Value> = document.windows().map(|w| w["target"].clone()).collect();
    let views = document.0["views"].as_array_mut().ok_or(())?;
    for mut view in incoming {
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
                // Device imports need fresh IDs to avoid durable close tombstones.
                // Persisted recovery memberships already own their IDs: queued edits must still address them.
                if imported {
                    fresh_id(window);
                }
                true
            });
            if !windows.is_empty() || index < end {
                fresh_id(&mut column);
                retained.push(column);
            }
        }
        if retained.is_empty() {
            continue;
        }
        let name = string(&view, "name").unwrap_or("");
        let base = name.strip_prefix("Recovered: ");
        let mut destination = None;
        let mut existing_kind = false;
        // Prefer the first matching name, falling back to the first tiled view
        // of that kind. One pass also records the graph-only refusal case.
        for (index, existing) in views.iter().enumerate() {
            if existing["kind"] != view["kind"] {
                continue;
            }
            existing_kind = true;
            if existing["layout"]["type"] != "tiled" {
                continue;
            }
            if destination.is_none() {
                destination = Some(index);
            }
            if existing["name"] == name || base.is_some_and(|base| existing["name"] == base) {
                destination = Some(index);
                break;
            }
        }
        if let Some(index) = destination {
            views[index]["layout"]["columns"]
                .as_array_mut()
                .ok_or(())?
                .extend(retained);
        } else {
            // Graphs cannot gain tiled memberships; refuse instead of duplicating that kind.
            if existing_kind {
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
                fresh_id(&mut view);
            }
            view["layout"]["columns"] = Value::Array(retained);
            views.push(view);
        }
    }
    Ok(())
}

/// Only exact prefix/base-name/kind pairs identify historical recovery output.
fn recovered(views: &[Value], view: &Value) -> bool {
    string(view, "name")
        .and_then(|name| name.strip_prefix("Recovered: "))
        .is_some_and(|name| {
            views.iter().any(|original| {
                // A stripped base name is strictly shorter, so this cannot match the view itself.
                original["kind"] == view["kind"] && original["name"] == name
            })
        })
}

/// True if the document holds any recovery view, that is, one whose name marks it as a copy of an existing view of the same kind.
pub(super) fn needed(document: &Document) -> bool {
    document.0["views"]
        .as_array()
        .is_some_and(|views| views.iter().any(|view| recovered(views, view)))
}

/// Prefix alone is insufficient: a recovery view must also name an existing view of its original kind.
/// Removing those views before merging excludes their own duplicate targets from the canonical seen set.
/// A committed snapshot records their removal, so repeated loads and stale-device imports converge idempotently.
// Keep synchronous mutation state separate from the asynchronous transaction frame.
/// Merges recovery views back into the views they were copied from and removes them. Returns `Ok(true)` if the document changed and `Ok(false)` if nothing was needed. If merging cannot fit the document's size limits it leaves the document as it was, so the account stays editable. Fails if the views are not an array.
#[inline(never)]
pub(super) fn repair(document: &mut Document) -> Result<bool, ()> {
    let views = document.0["views"].as_array().ok_or(())?;
    if !needed(document) {
        return Ok(false);
    }
    // Repair is optional maintenance: a valid account must stay editable even
    // when combining its views cannot fit the document or per-view bounds.
    let mut candidate = document.clone();
    let mut incoming = Vec::new();
    candidate.0["views"]
        .as_array_mut()
        .ok_or(())?
        .retain_mut(|view| {
            // Recognition reads the retained original, including any recovery base
            // that this candidate has already removed. No second index list is needed.
            let remove = recovered(views, view);
            if remove {
                // The removed membership owns its data; move it instead of cloning its entire layout.
                incoming.push(view.take());
            }
            !remove
        });
    if merge(&mut candidate, incoming, false).is_err() {
        return Ok(false);
    }
    candidate.0["revision"] = Value::from(candidate.revision() + 1);
    candidate.normalize();
    if !candidate.valid()
        || !serde_json::to_string(&candidate.0).is_ok_and(|json| json.len() <= MAX_DOCUMENT)
    {
        return Ok(false);
    }
    *document = candidate;
    Ok(true)
}
