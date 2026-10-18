//! Validates the bounded v1 reference document without accepting content or configuration [180].
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const MAX_DOCUMENT: usize = 48 * 1024;
pub const MAX_INPUT: usize = 8 * 1024;
pub const MAX_RECEIPTS: i64 = 65_536;
pub const CHECKPOINT: i64 = 128;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Document {
    pub format: String,
    pub version: u8,
    pub revision: i64,
    pub views: Vec<View>,
}
impl Default for Document {
    fn default() -> Self {
        Self {
            format: "infraternal.canvas".into(),
            version: 1,
            revision: 0,
            views: vec![],
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct View {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub cell: Point,
    pub layout: Layout,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Layout {
    Tiled { columns: Vec<Column> },
    Graph { pinned: BTreeMap<String, Point> },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub id: String,
    pub weight: f64,
    pub windows: Vec<Window>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub id: String,
    pub target: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row: Option<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Target {
    Session {
        id: String,
        host: String,
        #[serde(default, rename = "hostId", skip_serializing_if = "Option::is_none")]
        host_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Settings {
        section: String,
    },
    Containers {
        host: String,
    },
    Logs {
        host: String,
    },
}
#[must_use]
pub fn text(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= 200
}
#[must_use]
pub fn finite(value: f64, low: f64, high: f64) -> bool {
    value.is_finite() && (low..=high).contains(&value)
}
impl Target {
    #[must_use]
    pub fn valid(&self) -> bool {
        match self {
            Self::Session {
                id,
                host,
                host_id,
                user,
                address,
                name,
            } => {
                text(id)
                    && text(host)
                    && host_id.as_ref().is_none_or(|id| {
                        uuid::Uuid::parse_str(id).is_ok_and(|uuid| uuid.to_string() == *id)
                    })
                    && [user, address, name]
                        .iter()
                        .all(|item| item.as_ref().is_none_or(|s| text(s)))
            }
            Self::Settings { section } => text(section),
            Self::Containers { host } | Self::Logs { host } => text(host),
        }
    }
}
impl Window {
    #[must_use]
    pub fn valid(&self) -> bool {
        text(&self.id)
            && self.target.valid()
            && self.height.is_none_or(|v| finite(v, 0.05, 10_000.0))
            && self.span.is_none_or(|v| (1..=64).contains(&v))
            && self.rows.is_none_or(|v| (1..=64).contains(&v))
            && self.row.is_none_or(|v| v <= 64)
    }
}
impl Document {
    #[must_use]
    pub fn valid(&self) -> bool {
        if self.format != "infraternal.canvas"
            || self.version != 1
            || !(0..=9_007_199_254_740_991).contains(&self.revision)
            || self.views.len() > 64
        {
            return false;
        }
        let mut views = HashSet::new();
        let mut targets = HashMap::new();
        let mut count = 0;
        for view in &self.views {
            if !text(&view.id)
                || !views.insert(&view.id)
                || !text(&view.kind)
                || !text(&view.name)
                || !finite(view.cell.x, -1000.0, 1000.0)
                || !finite(view.cell.y, -1000.0, 1000.0)
            {
                return false;
            }
            match &view.layout {
                Layout::Tiled { columns } => {
                    if columns.len() > 64 {
                        return false;
                    }
                    let mut column_ids = HashSet::new();
                    let mut windows = HashSet::new();
                    for column in columns {
                        if !text(&column.id)
                            || !column_ids.insert(&column.id)
                            || !finite(column.weight, 0.1, 10.0)
                        {
                            return false;
                        }
                        for window in &column.windows {
                            count += 1;
                            if count > 256 || !window.valid() || !windows.insert(&window.id) {
                                return false;
                            }
                            if let Some(target) = targets.insert(&window.id, &window.target)
                                && target != &window.target
                            {
                                return false;
                            }
                        }
                    }
                }
                Layout::Graph { pinned } => {
                    if pinned.len() > 256
                        || pinned.iter().any(|(id, p)| {
                            !text(id)
                                || !finite(p.x, -100_000.0, 100_000.0)
                                || !finite(p.y, -100_000.0, 100_000.0)
                        })
                    {
                        return false;
                    }
                }
            }
        }
        serde_json::to_vec(self).is_ok_and(|bytes| bytes.len() <= MAX_DOCUMENT)
    }
    pub fn windows(&self) -> impl Iterator<Item = &Window> {
        self.views
            .iter()
            .flat_map(|view| match &view.layout {
                Layout::Tiled { columns } => columns.as_slice(),
                Layout::Graph { .. } => &[],
            })
            .flat_map(|column| &column.windows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reference_document_has_strict_shape_and_bounds() {
        let mut doc = Document::default();
        assert!(doc.valid());
        assert!(serde_json::from_str::<Document>(r#"{"format":"infraternal.canvas","version":1,"revision":0,"views":[],"content":"unexpected"}"#).is_err());
        doc.views.push(View {
            id: "console".into(),
            kind: "console".into(),
            name: "Console".into(),
            cell: Point { x: 0.0, y: 0.0 },
            layout: Layout::Tiled { columns: vec![] },
        });
        assert!(doc.valid());
        doc.views.push(doc.views[0].clone());
        assert!(!doc.valid());
        doc.views.pop();
        doc.views[0].cell.x = f64::INFINITY;
        assert!(!doc.valid());
        assert!(!text(&"x".repeat(201)));
    }
}
