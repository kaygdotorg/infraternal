//! Reduces one semantic intent against current state; storage supplies permanent close tombstones [183].
use crate::model::{Column, Document, Layout, Point, View, Window, finite};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    pub op_id: String,
    pub base_revision: i64,
    pub intent: Intent,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Initialize {
    pub op_id: String,
    pub document: Document,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum Intent {
    #[serde(rename = "view.add")]
    ViewAdd { view: View },
    #[serde(rename = "view.remove")]
    ViewRemove { view_id: String },
    #[serde(rename = "open")]
    Open {
        view_id: String,
        column_id: String,
        window: Window,
        after: Option<String>,
    },
    #[serde(rename = "split")]
    Split {
        view_id: String,
        anchor_id: String,
        axis: Axis,
        column_id: String,
        window: Window,
    },
    #[serde(rename = "close")]
    Close { window_id: String },
    #[serde(rename = "move")]
    Move {
        view_id: String,
        window_id: String,
        column_id: String,
        after: Option<String>,
    },
    #[serde(rename = "resize")]
    Resize {
        window_id: String,
        height: Option<f64>,
        span: Option<u8>,
        rows: Option<u8>,
        row: Option<u8>,
    },
    #[serde(rename = "weight")]
    Weight {
        view_id: String,
        column_id: String,
        weight: f64,
    },
    #[serde(rename = "membership.add")]
    MembershipAdd {
        view_id: String,
        column_id: String,
        window_id: String,
        after: Option<String>,
    },
    #[serde(rename = "membership.remove")]
    MembershipRemove { view_id: String, window_id: String },
    #[serde(rename = "pin")]
    Pin {
        view_id: String,
        node_id: String,
        position: Option<Point>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Axis {
    Right,
    Down,
}
fn columns<'a>(doc: &'a mut Document, id: &str) -> Result<&'a mut Vec<Column>, ()> {
    match &mut doc
        .views
        .iter_mut()
        .find(|view| view.id == id)
        .ok_or(())?
        .layout
    {
        Layout::Tiled { columns } => Ok(columns),
        Layout::Graph { .. } => Err(()),
    }
}
fn insert(
    cols: &mut Vec<Column>,
    column_id: &str,
    window: Window,
    after: Option<&str>,
) -> Result<(), ()> {
    if cols
        .iter()
        .flat_map(|c| &c.windows)
        .any(|w| w.id == window.id)
    {
        return Err(());
    }
    if !cols.iter().any(|c| c.id == column_id) {
        cols.push(Column {
            id: column_id.into(),
            weight: 1.0,
            windows: vec![],
        });
    }
    let col = cols.iter_mut().find(|c| c.id == column_id).ok_or(())?;
    let offset = after.map_or(0, |id| {
        col.windows
            .iter()
            .position(|w| w.id == id)
            .map_or(col.windows.len(), |i| i + 1)
    });
    col.windows.insert(offset, window);
    Ok(())
}
fn remove(cols: &mut [Column], id: &str) -> Option<Window> {
    for col in cols {
        if let Some(index) = col.windows.iter().position(|w| w.id == id) {
            return Some(col.windows.remove(index));
        }
    }
    None
}
/// The caller discards the working document on error; no partial mutations may be committed.
/// # Errors
/// Rejects nonexistent destinations, ID reuse and out-of-bounds final state.
#[allow(clippy::too_many_lines, clippy::result_unit_err)]
pub fn reduce<S: std::hash::BuildHasher>(
    doc: &mut Document,
    intent: &Intent,
    closed: &HashSet<String, S>,
) -> Result<(), ()> {
    // Bounds apply to the intent even when a close makes the edit a no-op.
    let valid = match intent {
        Intent::Open { window, .. } | Intent::Split { window, .. } => window.valid(),
        Intent::Resize {
            height,
            span,
            rows,
            row,
            ..
        } => {
            height.is_none_or(|v| finite(v, 0.05, 10_000.0))
                && span.is_none_or(|v| (1..=64).contains(&v))
                && rows.is_none_or(|v| (1..=64).contains(&v))
                && row.is_none_or(|v| v <= 64)
        }
        Intent::Weight { weight, .. } => finite(*weight, 0.1, 10.0),
        Intent::Pin { position, .. } => position.as_ref().is_none_or(|p| {
            finite(p.x, -100_000.0, 100_000.0) && finite(p.y, -100_000.0, 100_000.0)
        }),
        _ => true,
    };
    if !valid {
        return Err(());
    }
    match intent {
        Intent::ViewAdd { view } => {
            let empty = match &view.layout {
                Layout::Tiled { columns } => columns.is_empty(),
                Layout::Graph { pinned } => pinned.is_empty(),
            };
            if !empty || doc.views.iter().any(|v| v.id == view.id) {
                return Err(());
            }
            doc.views.push(view.clone());
        }
        Intent::ViewRemove { view_id } => doc.views.retain(|v| v.id != *view_id),
        Intent::Open {
            view_id,
            column_id,
            window,
            after,
        } => {
            if closed.contains(&window.id) || doc.windows().any(|w| w.id == window.id) {
                return Err(());
            }
            insert(
                columns(doc, view_id)?,
                column_id,
                window.clone(),
                after.as_deref(),
            )?;
        }
        Intent::Split {
            view_id,
            anchor_id,
            axis,
            column_id,
            window,
        } => {
            if closed.contains(&window.id) || doc.windows().any(|w| w.id == window.id) {
                return Err(());
            }
            // Closing the anchor wins even if a stale split arrives afterwards.
            if closed.contains(anchor_id) {
                return Ok(());
            }
            let cols = columns(doc, view_id)?;
            crate::tiling::split(cols, anchor_id, axis, column_id, window.clone())?;
        }
        Intent::Close { window_id } => {
            for view in &mut doc.views {
                if let Layout::Tiled { columns } = &mut view.layout {
                    remove(columns, window_id);
                }
            }
        }
        Intent::Move {
            view_id,
            window_id,
            column_id,
            after,
        } => {
            if closed.contains(window_id) {
                return Ok(());
            }
            let cols = columns(doc, view_id)?;
            if let Some(window) = remove(cols, window_id) {
                insert(cols, column_id, window, after.as_deref())?;
            }
        }
        Intent::Resize {
            window_id,
            height,
            span,
            rows,
            row,
        } => {
            if closed.contains(window_id) {
                return Ok(());
            }
            for view in &mut doc.views {
                if let Layout::Tiled { columns } = &mut view.layout {
                    for window in columns
                        .iter_mut()
                        .flat_map(|c| &mut c.windows)
                        .filter(|w| w.id == *window_id)
                    {
                        if height.is_some() {
                            window.height = *height;
                        }
                        if span.is_some() {
                            window.span = *span;
                        }
                        if rows.is_some() {
                            window.rows = *rows;
                        }
                        if row.is_some() {
                            window.row = *row;
                        }
                    }
                }
            }
        }
        Intent::Weight {
            view_id,
            column_id,
            weight,
        } => {
            let cols = columns(doc, view_id)?;
            // A stale resize of a removed column is harmless.
            if let Some(col) = cols.iter_mut().find(|c| c.id == *column_id) {
                col.weight = *weight;
            }
        }
        Intent::MembershipAdd {
            view_id,
            column_id,
            window_id,
            after,
        } => {
            if closed.contains(window_id) {
                return Ok(());
            }
            let window = doc
                .windows()
                .find(|w| w.id == *window_id)
                .cloned()
                .ok_or(())?;
            insert(columns(doc, view_id)?, column_id, window, after.as_deref())?;
        }
        Intent::MembershipRemove { view_id, window_id } => {
            remove(columns(doc, view_id)?, window_id);
        }
        Intent::Pin {
            view_id,
            node_id,
            position,
        } => {
            let view = doc.views.iter_mut().find(|v| v.id == *view_id).ok_or(())?;
            let Layout::Graph { pinned } = &mut view.layout else {
                return Err(());
            };
            if let Some(position) = position {
                pinned.insert(node_id.clone(), position.clone());
            } else {
                pinned.remove(node_id);
            }
        }
    }
    if doc.valid() { Ok(()) } else { Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Point, Target};
    fn document() -> Document {
        Document {
            views: vec![View {
                id: "console".into(),
                kind: "console".into(),
                name: "Console".into(),
                cell: Point { x: 0.0, y: 0.0 },
                layout: Layout::Tiled { columns: vec![] },
            }],
            ..Document::default()
        }
    }
    fn open(id: &str) -> Intent {
        Intent::Open {
            view_id: "console".into(),
            column_id: id.into(),
            window: Window {
                id: id.into(),
                target: Target::Settings {
                    section: "appearance".into(),
                },
                height: None,
                span: None,
                rows: None,
                row: None,
            },
            after: None,
        }
    }
    #[test]
    fn split_divides_only_its_own_band() {
        let mut doc = document();
        let closed = HashSet::new();
        reduce(&mut doc, &open("a"), &closed).unwrap();
        let Intent::Open { mut window, .. } = open("b") else {
            panic!("open")
        };
        window.id = "b".into();
        reduce(
            &mut doc,
            &Intent::Open {
                view_id: "console".into(),
                column_id: "a".into(),
                window,
                after: Some("a".into()),
            },
            &closed,
        )
        .unwrap();
        let Intent::Open { window, .. } = open("new") else {
            panic!("open")
        };
        reduce(
            &mut doc,
            &Intent::Split {
                view_id: "console".into(),
                anchor_id: "b".into(),
                axis: Axis::Right,
                column_id: "right".into(),
                window,
            },
            &closed,
        )
        .unwrap();
        assert_eq!(doc.windows().find(|w| w.id == "a").unwrap().span, Some(2));
        assert_eq!(doc.windows().find(|w| w.id == "b").unwrap().row, Some(1));
        assert_eq!(doc.windows().find(|w| w.id == "new").unwrap().row, Some(1));
    }
    #[test]
    fn independent_edits_commute_and_close_wins_in_both_orders() {
        for sample in 0..128 {
            let a = format!("a{sample}");
            let b = format!("b{sample}");
            let mut doc = document();
            let closed = HashSet::new();
            reduce(&mut doc, &open(&a), &closed).unwrap();
            reduce(&mut doc, &open(&b), &closed).unwrap();
            let resize = Intent::Resize {
                window_id: a.clone(),
                height: Some(2.0),
                span: None,
                rows: None,
                row: None,
            };
            let moved = Intent::Move {
                view_id: "console".into(),
                window_id: b,
                column_id: a.clone(),
                after: Some(a.clone()),
            };
            let mut left = doc.clone();
            let mut right = doc.clone();
            reduce(&mut left, &resize, &closed).unwrap();
            reduce(&mut left, &moved, &closed).unwrap();
            reduce(&mut right, &moved, &closed).unwrap();
            reduce(&mut right, &resize, &closed).unwrap();
            assert_eq!(left, right);
            let close = Intent::Close {
                window_id: a.clone(),
            };
            let mut tombstones = HashSet::new();
            tombstones.insert(a.clone());
            reduce(&mut left, &close, &closed).unwrap();
            reduce(&mut left, &resize, &tombstones).unwrap();
            reduce(&mut right, &resize, &closed).unwrap();
            reduce(&mut right, &close, &closed).unwrap();
            assert_eq!(left, right);
            assert!(!left.windows().any(|w| w.id == a));
            assert!(reduce(&mut left, &open(&a), &tombstones).is_err());
        }
    }
}
