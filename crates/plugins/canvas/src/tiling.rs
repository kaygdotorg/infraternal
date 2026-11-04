//! Splits flat JSON column/band geometry without introducing a second document representation [212,243].
use crate::model;
use serde_json::{Value, json};
//
// Vocabulary used below: a canvas is a left-to-right list of columns. Each
// column holds windows. A window sits at a `row` inside its column, is `rows`
// bands tall, and spans `span` columns to the right (itself included). Rows are
// counted in whole bands, at most 64 of them, so one `u128` bit mask can mark
// which bands of a column are taken.

/// The mutable `windows` array of a column; `Err` if the column has none.
fn wins_mut(column: &mut Value) -> Result<&mut Vec<Value>, ()> {
    column
        .get_mut("windows")
        .and_then(Value::as_array_mut)
        .ok_or(())
}
/// Reads a small integer field (`span`, `row` or `rows`) from a window, or
/// `default` when the field is absent.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn band(window: &Value, key: &str, default: u8) -> u8 {
    // The document/intent validator already requires integral values in 0..=64.
    window
        .get(key)
        .and_then(Value::as_f64)
        .map_or(default, |v| v as u8)
}
/// Finds the inclusive column range `(start, end)` that contains column `at`
/// and is tied together by multi-column windows. Windows in different groups
/// never overlap horizontally, so a vertical split only has to shift rows
/// inside one group. A column outside every group is its own group `(at, at)`.
fn range(columns: &[Value], at: usize) -> (usize, usize) {
    let mut start = 0;
    while start < columns.len() {
        let mut end = start;
        let mut cursor = start;
        while cursor <= end {
            for w in model::windows(&columns[cursor]) {
                end =
                    end.max((cursor + usize::from(band(w, "span", 1)) - 1).min(columns.len() - 1));
            }
            cursor += 1;
        }
        if at <= end {
            return (start, end);
        }
        start = end + 1;
    }
    (at, at)
}
/// Bit mask of the `rows` bands starting at `row` (bit N is band N).
fn mask(row: u8, rows: u8) -> u128 {
    ((1_u128 << rows) - 1) << row
}
/// True when none of the bands in `bits` is taken in any of the `span`
/// columns starting at `column`. `taken` holds one band mask per column.
fn free(taken: &[u128], column: usize, span: usize, bits: u128) -> bool {
    taken[column..column + span].iter().all(|v| v & bits == 0)
}
/// Marks the bands in `bits` as taken in the `span` columns starting at `column`.
fn mark(taken: &mut [u128], column: usize, span: usize, bits: u128) {
    for v in &mut taken[column..column + span] {
        *v |= bits;
    }
}
/// Normalizes the layout so every window has an explicit `span`, `rows` and
/// non-overlapping `row`.
///
/// Pass one clamps each span to the columns that exist and keeps the explicit
/// rows that do not collide with an earlier window (colliding ones lose their
/// `row`). Pass two gives each row-less window the first free position at or
/// below the previous window of its column. `Err` if a column has no `windows`
/// array or the rows would run past band 64.
fn settle(columns: &mut [Value]) -> Result<(), ()> {
    let mut taken = vec![0_u128; columns.len()];
    let count = columns.len();
    for (index, column) in columns.iter_mut().enumerate() {
        for w in wins_mut(column)? {
            let span = usize::from(band(w, "span", 1)).min(count - index);
            w["span"] = json!(span);
            let rows = band(w, "rows", 1);
            w["rows"] = json!(rows);
            if w.get("row").is_some() {
                let row = band(w, "row", 0);
                let bits = mask(row, rows);
                if free(&taken, index, span, bits) {
                    mark(&mut taken, index, span, bits);
                } else {
                    w.as_object_mut().ok_or(())?.remove("row");
                }
            }
        }
    }
    for (index, column) in columns.iter_mut().enumerate() {
        let mut cursor = 0_u8;
        for w in wins_mut(column)? {
            let span = usize::from(band(w, "span", 1));
            let rows = band(w, "rows", 1);
            if w.get("row").is_none() {
                while cursor <= 64 && !free(&taken, index, span, mask(cursor, rows)) {
                    cursor += 1;
                }
                if cursor > 64 {
                    return Err(());
                }
                w["row"] = json!(cursor);
                mark(&mut taken, index, span, mask(cursor, rows));
            }
            cursor = cursor.max(band(w, "row", 0).checked_add(rows).ok_or(())?);
        }
    }
    Ok(())
}
/// Splits the window `anchor` in two and puts `new` in the freed space.
///
/// `axis == "right"` places `new` beside the anchor. A multi-column anchor
/// gives its right half of the span to `new`. A one-column anchor makes room by
/// inserting a new column `column_id` after it, with half of the anchor
/// column's `weight`, and widening every other window that crossed it. Any
/// other `axis` places `new` below the anchor: rows at or under the anchor shift
/// down by one within the connected column group, and a `height` is halved
/// between the two windows.
///
/// The layout is normalized first and each column ends sorted by `row`.
/// `Err` (a refusal, with `columns` possibly half-edited) when the anchor is
/// missing, `column_id` already exists, or a number would overflow; callers
/// must therefore work on a copy and keep it only on success.
#[allow(clippy::too_many_lines)]
pub(crate) fn split(
    columns: &mut Vec<Value>,
    anchor: &str,
    axis: &str,
    column_id: &str,
    mut new: Value,
) -> Result<(), ()> {
    settle(columns)?;
    let col = columns
        .iter()
        .position(|c| model::windows(c).any(|w| model::string(w, "id") == Some(anchor)))
        .ok_or(())?;
    let at = model::windows(&columns[col])
        .position(|w| model::string(w, "id") == Some(anchor))
        .ok_or(())?;
    let original = wins_mut(&mut columns[col])?.get(at).cloned().ok_or(())?;
    let span = band(&original, "span", 1);
    let row = band(&original, "row", 0);
    let rows = band(&original, "rows", 1);
    if axis == "right" {
        new["row"] = json!(row);
        new["rows"] = json!(rows);
        if new.get("height").is_none()
            && let Some(height) = original.get("height")
        {
            new["height"] = height.clone();
        }
        if span > 1 {
            let left = span.div_ceil(2);
            wins_mut(&mut columns[col])?[at]["span"] = json!(left);
            new["span"] = json!(span - left);
            wins_mut(&mut columns[col + usize::from(left)])?.push(new);
        } else {
            if columns
                .iter()
                .any(|c| model::string(c, "id") == Some(column_id))
            {
                return Err(());
            }
            for (index, column) in columns.iter_mut().enumerate() {
                for w in wins_mut(column)? {
                    if model::string(w, "id") != Some(anchor)
                        && index <= col
                        && col < index + usize::from(band(w, "span", 1))
                    {
                        w["span"] = json!(band(w, "span", 1).checked_add(1).ok_or(())?);
                    }
                }
            }
            let weight = columns[col]
                .get("weight")
                .and_then(Value::as_f64)
                .ok_or(())?
                / 2.0;
            columns[col]["weight"] = json!(weight);
            new["span"] = json!(1);
            columns.insert(col + 1, model::column(column_id, weight, vec![new]));
        }
    } else {
        let (from, to) = range(columns, col);
        let boundary = row.checked_add(rows).ok_or(())?;
        for (index, column) in columns.iter_mut().enumerate().take(to + 1).skip(from) {
            for w in wins_mut(column)? {
                let start = band(w, "row", 0);
                let height = band(w, "rows", 1);
                if start >= boundary {
                    w["row"] = json!(start.checked_add(1).ok_or(())?);
                } else if start + height >= boundary
                    && !(index < col + usize::from(span)
                        && col < index + usize::from(band(w, "span", 1)))
                {
                    w["rows"] = json!(height.checked_add(1).ok_or(())?);
                }
            }
        }
        if let Some(height) = original.get("height").and_then(Value::as_f64) {
            wins_mut(&mut columns[col])?[at]["height"] = json!(height / 2.0);
            if new.get("height").is_none() {
                new["height"] = json!(height / 2.0);
            }
        }
        new["row"] = json!(boundary);
        new["rows"] = json!(1);
        new["span"] = json!(span);
        wins_mut(&mut columns[col])?.push(new);
    }
    for column in columns {
        wins_mut(column)?.sort_unstable_by_key(|w| band(w, "row", 0));
    }
    Ok(())
}
