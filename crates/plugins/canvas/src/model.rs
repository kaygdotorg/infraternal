//! Validates the existing v1 JSON document in place, reusing the server's JSON representation [180,243,248].
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const MAX_DOCUMENT: usize = 48 * 1024;
pub const MAX_INPUT: usize = 8 * 1024;
pub const MAX_RECEIPTS: i64 = 65_536;
pub const CHECKPOINT: i64 = 128;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(transparent)]
pub struct Document(pub Value);
impl Default for Document {
    fn default() -> Self {
        Self(json!({"format":"infraternal.canvas","version":1,"revision":0,"views":[]}))
    }
}
#[must_use]
pub fn text(value: &str) -> bool {
    !value.is_empty() && value.encode_utf16().take(201).count() <= 200
}
#[must_use]
pub fn finite(value: f64, low: f64, high: f64) -> bool {
    value.is_finite() && (low..=high).contains(&value)
}
#[must_use]
pub fn shape(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|v| v.keys().all(|key| fields.contains(&key.as_str())))
}
#[must_use]
pub fn string<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str().filter(|s| text(s))
}
pub(crate) fn numeric(value: &Value, key: &str, low: f64, high: f64) -> bool {
    value
        .get(key)
        .and_then(Value::as_f64)
        .is_some_and(|v| finite(v, low, high))
}
fn optional_number(value: &Value, key: &str, low: f64, high: f64, whole: bool) -> bool {
    value.get(key).is_none_or(|n| {
        n.as_f64()
            .is_some_and(|v| finite(v, low, high) && (!whole || v.fract() == 0.0))
    })
}
pub(crate) fn point(value: &Value, limit: f64) -> bool {
    shape(value, &["x", "y"])
        && numeric(value, "x", -limit, limit)
        && numeric(value, "y", -limit, limit)
}
pub(crate) fn target(value: &Value) -> bool {
    match string(value, "type") {
        Some("session") => {
            shape(
                value,
                &[
                    "type", "id", "host", "hostId", "user", "address", "name", "pinned",
                ],
            ) && string(value, "id").is_some()
                && string(value, "host").is_some()
                && value.get("hostId").is_none_or(|v| {
                    v.as_str().is_some_and(|id| {
                        uuid::Uuid::parse_str(id).is_ok_and(|uuid| {
                            uuid.hyphenated()
                                .encode_lower(&mut uuid::Uuid::encode_buffer())
                                == id
                        })
                    })
                })
                && ["user", "address", "name"]
                    .iter()
                    .all(|key| value.get(key).is_none() || string(value, key).is_some())
                && value.get("pinned").is_none_or(Value::is_boolean)
        }
        Some("settings") => {
            shape(value, &["type", "section"]) && string(value, "section").is_some()
        }
        Some("containers" | "logs") => {
            shape(value, &["type", "host"]) && string(value, "host").is_some()
        }
        _ => false,
    }
}
pub(crate) fn window(value: &Value) -> bool {
    shape(value, &["id", "target", "height", "span", "rows", "row"])
        && string(value, "id").is_some()
        && value.get("target").is_some_and(target)
        && optional_number(value, "height", 0.05, 10_000.0, false)
        && optional_number(value, "span", 1.0, 64.0, true)
        && optional_number(value, "rows", 1.0, 64.0, true)
        && optional_number(value, "row", 0.0, 64.0, true)
}
pub(crate) fn view(value: &Value) -> bool {
    shape(value, &["id", "kind", "name", "cell", "layout"])
        && ["id", "kind", "name"]
            .iter()
            .all(|key| string(value, key).is_some())
        && value.get("cell").is_some_and(|p| point(p, 1000.0))
        && match value.get("layout") {
            Some(layout) if string(layout, "type") == Some("tiled") => {
                shape(layout, &["type", "columns"])
                    && layout
                        .get("columns")
                        .and_then(Value::as_array)
                        .is_some_and(|cols| {
                            cols.len() <= 64
                                && cols.iter().all(|c| {
                                    shape(c, &["id", "weight", "windows"])
                                        && string(c, "id").is_some()
                                        && numeric(c, "weight", 0.1, 10.0)
                                        && c.get("windows").and_then(Value::as_array).is_some_and(
                                            |wins| wins.len() <= 256 && wins.iter().all(window),
                                        )
                                })
                        })
            }
            Some(layout) if string(layout, "type") == Some("graph") => {
                shape(layout, &["type", "pinned"])
                    && layout
                        .get("pinned")
                        .and_then(Value::as_object)
                        .is_some_and(|pins| {
                            pins.len() <= 256
                                && pins.iter().all(|(id, p)| text(id) && point(p, 100_000.0))
                        })
            }
            _ => false,
        }
}
/// How many themes one account's look may hold. An intent carries the whole list, and an intent is at most `MAX_INPUT` bytes.
pub(crate) const MAX_THEMES: usize = 16;
/// Accepts an integer numeric field inside the supplied inclusive bounds.
fn whole(value: &Value, key: &str, low: f64, high: f64) -> bool {
    numeric(value, key, low, high)
        && value
            .get(key)
            .and_then(Value::as_f64)
            .is_some_and(|v| v.fract() == 0.0)
}
/// Checks for a six-digit CSS hex colour string.
fn hex(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit())
    })
}
/// Colour schemes offered by `packages/ui/src/themes.ts`. Keep the server's wire validation in step with the browser's fixed choices.
const SCHEME_IDS: &[&str] = &[
    "paper", "ink", "latte", "mocha", "dawn", "rosepine", "nord", "tokyo", "gruvbox", "dracula",
    "solarized-light", "solarized-dark", "everforest-light", "everforest-dark", "kanagawa-lotus",
    "kanagawa-wave", "ayu-light", "ayu-dark", "github-light", "github-dark", "flexoki-light",
    "flexoki-dark", "gruvbox-light", "tokyo-day", "frappe", "macchiato", "owl-light", "owl-night",
];

/// Font ids offered by `packages/ui/src/fonts.ts`; these are account data, not arbitrary labels.
const FONT_IDS: &[&str] = &[
    "maple-mono-nf", "geist-mono", "jetbrains-mono", "commit-mono", "monaspace-neon", "ibm-plex-mono",
    "cascadia-code", "fira-code", "source-code-pro", "iosevka", "victor-mono", "recursive-mono",
    "martian-mono", "intel-one-mono", "fantasque-sans-mono", "hack", "inconsolata", "0xproto", "lilex",
    "monaspace-argon", "monaspace-xenon", "monaspace-radon", "monaspace-krypton",
];

/// Background ids offered by `apps/tracer/src/canvas/themes/backgrounds.ts` and `gradients.ts`.
const BACKGROUND_IDS: &[&str] = &[
    "custom", "solid-custom", "solid", "solid-accent", "solid-red", "solid-yellow", "solid-green", "solid-cyan",
    "solid-blue", "solid-magenta", "aurora", "dusk", "lagoon", "ember", "meadow", "orchid", "sunrise", "haze",
    "horizon",
];

/// Checks that a JSON string is one of the choices shipped by the client.
fn known_id(value: Option<&Value>, choices: &[&str]) -> bool {
    value.and_then(Value::as_str).is_some_and(|id| choices.contains(&id))
}

/// Confirms that the selected theme id points to an entry carried by this account look.
fn selected_theme_exists(value: &Value) -> bool {
    let Some(selected) = string(value, "selected") else {
        return false;
    };
    value.get("themes").and_then(Value::as_array).is_some_and(|themes| {
        themes.iter().any(|entry| entry.get("id").and_then(Value::as_str) == Some(selected))
    })
}

/// One theme of the account's look: ids must name shipped fonts, Colour schemes and backgrounds, with numbers within their ranges.
fn theme(value: &Value) -> bool {
    shape(
        value,
        &[
            "id",
            "name",
            "tint",
            "blur",
            "grain",
            "font",
            "colors",
            "uiSize",
            "background",
            "customSolid",
            "custom",
        ],
    ) && ["id", "name", "font", "colors", "background"]
        .iter()
        .all(|key| string(value, key).is_some())
        && known_id(value.get("font"), FONT_IDS)
        && known_id(value.get("colors"), SCHEME_IDS)
        && known_id(value.get("background"), BACKGROUND_IDS)
        && ["tint", "blur", "grain"]
            .iter()
            .all(|key| whole(value, key, 0.0, 100.0))
        && whole(value, "uiSize", 50.0, 150.0)
        && value.get("customSolid").is_some_and(hex)
        && value.get("custom").is_some_and(|custom| {
            shape(custom, &["stops", "angle"])
                && whole(custom, "angle", 0.0, 360.0)
                && custom
                    .get("stops")
                    .and_then(Value::as_array)
                    .is_some_and(|stops| (2..=4).contains(&stops.len()) && stops.iter().all(hex))
        })
}
/// The account's look (D322): the list of themes, which one is selected, and the starting Colour, font and size the built-in themes were made from.
/// It lives in the canvas document so every device of the account shows the same look; only the camera stays per device (D178).
pub(crate) fn look(value: &Value) -> bool {
    shape(
        value,
        &[
            "v",
            "selected",
            "basics",
            "themes",
            "windowSizes",
            "extendedInfo",
        ],
    ) && value.get("v").and_then(Value::as_u64) == Some(1)
        && string(value, "selected").is_some()
        && value.get("basics").is_some_and(|basics| {
            shape(basics, &["colors", "font", "uiSize"])
                && known_id(basics.get("colors"), SCHEME_IDS)
                && known_id(basics.get("font"), FONT_IDS)
                && whole(basics, "uiSize", 50.0, 150.0)
        })
        && value
            .get("themes")
            .and_then(Value::as_array)
            .is_some_and(|themes| {
                themes.len() <= MAX_THEMES
                    && themes.iter().all(theme)
                    && themes.iter().enumerate().all(|(at, t)| {
                        !themes[..at]
                            .iter()
                            .any(|seen| seen.get("id") == t.get("id"))
                    })
            })
        && selected_theme_exists(value)
        && value.get("windowSizes").is_none_or(|sizes| {
            shape(sizes, &["phone", "desktop"])
                && matches!(
                    sizes.get("phone").and_then(Value::as_str),
                    Some("full" | "edge" | "comfortable")
                )
                && matches!(
                    sizes.get("desktop").and_then(Value::as_str),
                    Some("comfortable" | "wide" | "full")
                )
        })
        && value.get("extendedInfo").is_none_or(Value::is_boolean)
}
pub(crate) fn views(doc: &Value) -> impl Iterator<Item = &Value> {
    doc.get("views")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}
pub(crate) fn columns(view: &Value) -> impl Iterator<Item = &Value> {
    view.get("layout")
        .and_then(|l| l.get("columns"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}
pub(crate) fn windows(column: &Value) -> impl Iterator<Item = &Value> {
    column
        .get("windows")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}
#[must_use]
pub fn object(fields: Vec<(&str, Value)>) -> Value {
    let mut object = serde_json::Map::new();
    for (key, value) in fields {
        object.insert(key.into(), value);
    }
    Value::Object(object)
}
/// Builds the shared JSON shape for a newly created tiled column.
pub(crate) fn column(id: &str, weight: f64, windows: Vec<Value>) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("id".into(), Value::String(id.into()));
    object.insert("weight".into(), Value::from(weight));
    object.insert("windows".into(), Value::Array(windows));
    Value::Object(object)
}
impl Document {
    #[must_use]
    pub fn revision(&self) -> i64 {
        self.0.get("revision").and_then(Value::as_i64).unwrap_or(0)
    }
    pub fn windows(&self) -> impl Iterator<Item = &Value> {
        views(&self.0).flat_map(columns).flat_map(windows)
    }
    /// Checks reference shape and cardinality; the host checks encoded bytes at commit.
    #[must_use]
    pub fn valid(&self) -> bool {
        let doc = &self.0;
        if !shape(doc, &["format", "version", "revision", "views", "look"])
            || doc.get("look").is_some_and(|value| !look(value))
            || string(doc, "format") != Some("infraternal.canvas")
            || doc.get("version").and_then(Value::as_u64) != Some(1)
            || !doc
                .get("revision")
                .and_then(Value::as_i64)
                .is_some_and(|v| (0..=9_007_199_254_740_991).contains(&v))
        {
            return false;
        }
        let Some(views) = doc.get("views").and_then(Value::as_array) else {
            return false;
        };
        if views.len() > 64 || !views.iter().all(view) {
            return false;
        }
        let mut view_ids = Vec::new();
        let mut targets = Vec::<(&str, &Value)>::new();
        let mut total = 0;
        for view in views {
            let Some(id) = string(view, "id") else {
                return false;
            };
            if view_ids.contains(&id) {
                return false;
            }
            view_ids.push(id);
            let mut column_ids = Vec::new();
            let mut window_ids = Vec::new();
            for column in columns(view) {
                let Some(id) = string(column, "id") else {
                    return false;
                };
                if column_ids.contains(&id) {
                    return false;
                }
                column_ids.push(id);
                for window in windows(column) {
                    total += 1;
                    let Some(id) = string(window, "id") else {
                        return false;
                    };
                    if total > 256 || window_ids.contains(&id) {
                        return false;
                    }
                    window_ids.push(id);
                    let Some(target) = window.get("target") else {
                        return false;
                    };
                    if targets
                        .iter()
                        .any(|(seen, old)| *seen == id && *old != target)
                    {
                        return false;
                    }
                    targets.push((id, target));
                }
            }
        }
        true
    }
    /// Numeric spellings do not make identical legacy layouts become different recovery views.
    pub fn normalize(&mut self) {
        fn floats(value: &mut Value, keys: &[&str]) {
            for key in keys {
                if let Some(number) = value.get(key).and_then(Value::as_f64) {
                    value[*key] = Value::from(number);
                }
            }
        }
        if let Some(views) = self.0.get_mut("views").and_then(Value::as_array_mut) {
            for view in views {
                if let Some(cell) = view.get_mut("cell") {
                    floats(cell, &["x", "y"]);
                }
                if let Some(layout) = view.get_mut("layout") {
                    if let Some(columns) = layout.get_mut("columns").and_then(Value::as_array_mut) {
                        for column in columns {
                            floats(column, &["weight"]);
                            if let Some(windows) =
                                column.get_mut("windows").and_then(Value::as_array_mut)
                            {
                                for window in windows {
                                    floats(window, &["height"]);
                                }
                            }
                        }
                    }
                    if let Some(pins) = layout.get_mut("pinned").and_then(Value::as_object_mut) {
                        for point in pins.values_mut() {
                            floats(point, &["x", "y"]);
                        }
                    }
                }
            }
        }
    }
}

/// Checks document bounds and canonical reference spellings.
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_document_has_strict_shape_and_bounds() {
        let mut doc = Document::default();
        assert!(doc.valid());
        doc.0["content"] = json!("unexpected");
        assert!(!doc.valid());
        doc.0.as_object_mut().unwrap().remove("content");
        let view = json!({"id":"console","kind":"console","name":"Console","cell":{"x":0,"y":0},"layout":{"type":"tiled","columns":[]}});
        doc.0["views"] = json!([view]);
        assert!(doc.valid());
        let copied = doc.0["views"][0].clone();
        doc.0["views"].as_array_mut().unwrap().push(copied);
        assert!(!doc.valid());
        doc.0["views"].as_array_mut().unwrap().pop();
        doc.0["views"][0]["cell"]["x"] = json!(2000);
        assert!(!doc.valid());
        assert!(!text(&"x".repeat(201)));
    }

    /// Requires every account look identifier to name a shipped choice and the selected theme to exist.
    #[test]
    fn account_look_ids_are_known_and_selection_is_present() {
        let valid = json!({
            "v": 1,
            "selected": "solid",
            "basics": {"colors": "ink", "font": "geist-mono", "uiSize": 100},
            "themes": [{
                "id": "solid", "name": "Solid", "tint": 100, "blur": 0, "grain": 0,
                "font": "geist-mono", "colors": "ink", "uiSize": 100,
                "background": "aurora", "customSolid": "#3b4252",
                "custom": {"stops": ["#7a9cff", "#cba6f7"], "angle": 135}
            }]
        });
        let mut document = Document::default();
        document.0["look"] = valid.clone();
        assert!(document.valid());

        for pointer in [
            "/selected",
            "/basics/colors",
            "/basics/font",
            "/themes/0/font",
            "/themes/0/colors",
            "/themes/0/background",
        ] {
            let mut invalid = valid.clone();
            *invalid.pointer_mut(pointer).unwrap() = json!("unknown-id");
            document.0["look"] = invalid;
            assert!(!document.valid(), "accepted unknown id at {pointer}");
        }

        let mut invalid = valid;
        invalid["selected"] = json!("custom-9");
        document.0["look"] = invalid;
        assert!(!document.valid(), "accepted a selected theme missing from the list");
    }

    #[test]
    fn graph_pin_coordinates_include_both_limits_but_refuse_the_next_integer() {
        let mut doc = Document::default();
        doc.0["views"] = json!([{
            "id":"mesh","kind":"mesh","name":"Mesh","cell":{"x":0,"y":0},
            "layout":{"type":"graph","pinned":{"node":{"x":-100_000,"y":100_000}}}
        }]);
        assert!(doc.valid());

        doc.0["views"][0]["layout"]["pinned"]["node"]["x"] = json!(-100_001);
        assert!(!doc.valid());
        doc.0["views"][0]["layout"]["pinned"]["node"]["x"] = json!(-100_000);
        doc.0["views"][0]["layout"]["pinned"]["node"]["y"] = json!(100_001);
        assert!(!doc.valid());
    }

    #[test]
    fn session_name_pin_is_optional_and_boolean() {
        let mut value = json!({"type":"session","id":"session","host":"host","name":"build"});
        assert!(target(&value));
        value["pinned"] = json!(true);
        assert!(target(&value));
        value["pinned"] = json!(false);
        assert!(target(&value));
        value["pinned"] = json!("true");
        assert!(!target(&value));
    }

    #[test]
    fn host_id_requires_canonical_lowercase_hyphenated_text() {
        let mut value = json!({"type":"session","id":"session","host":"host"});
        value["hostId"] = json!("550e8400-e29b-41d4-a716-446655440000");
        assert!(target(&value));
        value["hostId"] = json!("550E8400-E29B-41D4-A716-446655440000");
        assert!(!target(&value));
        value["hostId"] = json!("550e8400e29b41d4a716446655440000");
        assert!(!target(&value));
    }
}
