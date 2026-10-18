//! Splits the existing flat column/band geometry in document units, preserving neighbours' occupied bands [212].
use crate::{
    model::{Column, Window},
    reducer::Axis,
};

fn range(columns: &[Column], at: usize) -> (usize, usize) {
    let mut start = 0;
    while start < columns.len() {
        let mut end = start;
        let mut cursor = start;
        while cursor <= end {
            for window in &columns[cursor].windows {
                end = end.max(
                    (cursor + usize::from(window.span.unwrap_or(1)) - 1).min(columns.len() - 1),
                );
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
fn mask(row: u8, rows: u8) -> u128 {
    ((1_u128 << rows) - 1) << row
}
fn free(taken: &[u128], column: usize, span: usize, bits: u128) -> bool {
    taken[column..column + span]
        .iter()
        .all(|occupied| occupied & bits == 0)
}
fn mark(taken: &mut [u128], column: usize, span: usize, bits: u128) {
    for occupied in &mut taken[column..column + span] {
        *occupied |= bits;
    }
}
fn settle(columns: &mut [Column]) -> Result<(), ()> {
    let mut taken = vec![0_u128; columns.len()];
    let count = columns.len();
    // Preserve explicit unoccupied bands first, then place implicit rows in list order.
    for (index, column) in columns.iter_mut().enumerate() {
        for window in &mut column.windows {
            let span = usize::from(window.span.unwrap_or(1)).min(count - index);
            window.span = Some(u8::try_from(span).map_err(|_| ())?);
            let rows = window.rows.unwrap_or(1);
            window.rows = Some(rows);
            if let Some(row) = window.row {
                let bits = mask(row, rows);
                if free(&taken, index, span, bits) {
                    mark(&mut taken, index, span, bits);
                } else {
                    window.row = None;
                }
            }
        }
    }
    for (index, column) in columns.iter_mut().enumerate() {
        let mut cursor = 0_u8;
        for window in &mut column.windows {
            let span = usize::from(window.span.unwrap_or(1));
            let rows = window.rows.unwrap_or(1);
            if window.row.is_none() {
                while cursor <= 64 && !free(&taken, index, span, mask(cursor, rows)) {
                    cursor += 1;
                }
                if cursor > 64 {
                    return Err(());
                }
                window.row = Some(cursor);
                mark(&mut taken, index, span, mask(cursor, rows));
            }
            cursor = cursor.max(window.row.unwrap_or(0).checked_add(rows).ok_or(())?);
        }
    }
    Ok(())
}
/// Caller owns a disposable working document; failed bounds never reach persistence.
pub(crate) fn split(
    columns: &mut Vec<Column>,
    anchor: &str,
    axis: &Axis,
    column_id: &str,
    mut new: Window,
) -> Result<(), ()> {
    settle(columns)?;
    let col = columns
        .iter()
        .position(|c| c.windows.iter().any(|w| w.id == anchor))
        .ok_or(())?;
    let at = columns[col]
        .windows
        .iter()
        .position(|w| w.id == anchor)
        .ok_or(())?;
    let original = columns[col].windows[at].clone();
    let span = original.span.unwrap_or(1);
    let row = original.row.unwrap_or(0);
    let rows = original.rows.unwrap_or(1);
    match axis {
        Axis::Right => {
            new.row = Some(row);
            new.rows = Some(rows);
            new.height = new.height.or(original.height);
            if span > 1 {
                let left = span.div_ceil(2);
                columns[col].windows[at].span = Some(left);
                new.span = Some(span - left);
                columns[col + usize::from(left)].windows.push(new);
            } else {
                if columns.iter().any(|c| c.id == column_id) {
                    return Err(());
                }
                for (index, column) in columns.iter_mut().enumerate() {
                    for window in &mut column.windows {
                        if window.id != anchor
                            && index <= col
                            && col < index + usize::from(window.span.unwrap_or(1))
                        {
                            window.span = Some(window.span.unwrap_or(1).checked_add(1).ok_or(())?);
                        }
                    }
                }
                let weight = columns[col].weight / 2.0;
                columns[col].weight = weight;
                new.span = Some(1);
                columns.insert(
                    col + 1,
                    Column {
                        id: column_id.into(),
                        weight,
                        windows: vec![new],
                    },
                );
            }
        }
        Axis::Down => {
            let (from, to) = range(columns, col);
            let boundary = row.checked_add(rows).ok_or(())?;
            for (index, column) in columns.iter_mut().enumerate().take(to + 1).skip(from) {
                for window in &mut column.windows {
                    let start = window.row.unwrap_or(0);
                    let height = window.rows.unwrap_or(1);
                    if start >= boundary {
                        window.row = Some(start.checked_add(1).ok_or(())?);
                    } else if start + height >= boundary
                        && !(index < col + usize::from(span)
                            && col < index + usize::from(window.span.unwrap_or(1)))
                    {
                        window.rows = Some(height.checked_add(1).ok_or(())?);
                    }
                }
            }
            if let Some(height) = original.height {
                columns[col].windows[at].height = Some(height / 2.0);
                new.height = new.height.or(Some(height / 2.0));
            }
            new.row = Some(boundary);
            new.rows = Some(1);
            new.span = Some(span);
            columns[col].windows.push(new);
        }
    }
    for column in columns {
        column.windows.sort_by_key(|w| w.row.unwrap_or(0));
    }
    Ok(())
}
