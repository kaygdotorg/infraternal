//! Shared text presentation for operator output: aligned tables, human sizes and ages (#239, D202, D299).
//!
//! The CLI core and every plugin that presents its own records use these helpers, so
//! a table printed by the core and a table printed by a plugin follow the same rules:
//! a header only when there are two rows or more, every column as wide as its widest
//! value, only the last column wraps, and the whole table fits the width it is given.
//! Raw values (byte counts, epoch times) belong in `--json`; people get the units here.

use serde_json::Value;

/// How the answer reads at a glance; the CLI maps it to a state word and a mark.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tone {
    /// Working as asked: running, done.
    Good,
    /// Deliberately off or idle.
    Idle,
    /// Needs a person to do something.
    Attention,
}

/// What a plugin hands the CLI for one reply: the one-line answer, the aligned detail,
/// the next commands that are true for this state, and the machine form for `--json`.
#[derive(Clone, Debug, PartialEq)]
pub struct Presented {
    /// State of what the reply describes.
    pub tone: Tone,
    /// One plain sentence that answers the request.
    pub message: String,
    /// Aligned detail lines (tables, key/value blocks); may be empty.
    pub body: String,
    /// Commands that are useful in this state; empty when nothing is needed.
    pub next: Vec<String>,
    /// Stable JSON for the envelope's `data`.
    pub data: Value,
}

/// A column's tint for the terminal. The core passes one; plugins print plain text.
pub type Tint<'a> = &'a dyn Fn(usize, &str) -> Option<&'static str>;

/// Terminal escape that ends a tint.
const RESET: &str = "\u{1b}[0m";
/// Narrowest a shrunk column may become before the table gives up and overflows.
const MIN_COLUMN: usize = 6;
/// Blank columns between two table columns, and between a label and its value in `pairs`.
const GAP: usize = 2;

/// Render rows as an aligned table indented by `indent` columns and fitted to `width`.
///
/// `header` is printed only when there are at least two rows (a one-row answer needs no
/// labels). Columns other than the last are truncated with an ellipsis when the table
/// is too wide; the last column wraps at word boundaries.
#[must_use]
pub fn table(
    header: &[&str],
    rows: &[Vec<String>],
    indent: usize,
    width: usize,
    tint: Option<Tint<'_>>,
) -> String {
    let columns = header.len();
    if columns == 0 || rows.is_empty() {
        return String::new();
    }
    let show_header = rows.len() >= 2;
    let cells = |row: usize, column: usize| rows[row].get(column).map_or("", String::as_str);
    let mut widths: Vec<usize> = (0..columns)
        .map(|column| {
            let mut widest = if show_header {
                header[column].chars().count()
            } else {
                0
            };
            for row in 0..rows.len() {
                widest = widest.max(cells(row, column).chars().count());
            }
            widest.max(1)
        })
        .collect();
    let available = width.saturating_sub(indent);
    let gaps = GAP * (columns - 1);
    // Shrink the last column first (it can wrap), then the widest of the others.
    while widths.iter().sum::<usize>() + gaps > available {
        let last = columns - 1;
        if widths[last] > MIN_COLUMN.max(12) {
            widths[last] -= 1;
            continue;
        }
        let widest = (0..last).max_by_key(|column| widths[*column]);
        match widest {
            Some(column) if widths[column] > MIN_COLUMN => widths[column] -= 1,
            _ if widths[last] > MIN_COLUMN => widths[last] -= 1,
            _ => break,
        }
    }
    let mut out = String::new();
    if show_header {
        let labels: Vec<String> = header.iter().map(|label| label.to_uppercase()).collect();
        push_row(&mut out, &labels, &widths, indent, None);
    }
    for row in rows {
        push_row(&mut out, row, &widths, indent, tint);
    }
    out
}

/// Appends one table row to `out`, as one or more lines: every cell but the last is truncated
/// to its column width, the last wraps. A tint colours only a cell's first line. Trailing
/// spaces are trimmed.
fn push_row(
    out: &mut String,
    row: &[String],
    widths: &[usize],
    indent: usize,
    tint: Option<Tint<'_>>,
) {
    let last = widths.len() - 1;
    let wrapped: Vec<Vec<String>> = widths
        .iter()
        .enumerate()
        .map(|(column, width)| {
            let text = row.get(column).map_or("", String::as_str);
            if column == last {
                wrap(text, *width)
            } else {
                vec![truncate(text, *width)]
            }
        })
        .collect();
    let height = wrapped.iter().map(Vec::len).max().unwrap_or(1);
    for line in 0..height {
        out.push_str(&" ".repeat(indent));
        for (column, width) in widths.iter().enumerate() {
            let text = wrapped[column].get(line).map_or("", String::as_str);
            let used = text.chars().count();
            match tint
                .and_then(|tint| tint(column, text))
                .filter(|_| line == 0)
            {
                Some(code) if !text.is_empty() => {
                    out.push_str(code);
                    out.push_str(text);
                    out.push_str(RESET);
                }
                _ => out.push_str(text),
            }
            if column != last {
                out.push_str(&" ".repeat(width.saturating_sub(used) + GAP));
            }
        }
        // A padded empty last cell would leave trailing spaces.
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }
}

/// Cut `text` to `width` characters, ending in an ellipsis when something was removed.
#[must_use]
pub fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('…');
    cut
}

/// Break `text` into lines of at most `width` characters at word boundaries.
/// A word longer than the width is split.
#[must_use]
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let length = word.chars().count();
        if !line.is_empty() && line.chars().count() + 1 + length > width {
            lines.push(std::mem::take(&mut line));
        }
        if length > width {
            let mut chars = word.chars();
            while chars.clone().count() > width {
                line.extend(chars.by_ref().take(width));
                lines.push(std::mem::take(&mut line));
            }
            line.extend(chars);
        } else {
            if !line.is_empty() {
                line.push(' ');
            }
            line.push_str(word);
        }
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Aligned `label  value` lines; values wrap under their own column.
#[must_use]
pub fn pairs(rows: &[(&str, String)], indent: usize, width: usize) -> String {
    let label = rows
        .iter()
        .map(|(label, _)| label.chars().count())
        .max()
        .unwrap_or(0);
    let value_column = indent + label + GAP;
    let room = width.saturating_sub(value_column).max(12);
    let mut out = String::new();
    for (name, value) in rows {
        for (index, line) in wrap(value, room).iter().enumerate() {
            out.push_str(&" ".repeat(if index == 0 { indent } else { value_column }));
            if index == 0 {
                out.push_str(name);
                out.push_str(&" ".repeat(label - name.chars().count() + GAP));
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// A byte count in decimal units with at most one decimal below 10: `0 B`, `950 B`, `1.5 MB`, `18 MB`.
#[must_use]
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    if count < 1000 {
        return format!("{count} B");
    }
    // Integer arithmetic in tenths of a unit, rounded half up, so no float is needed.
    let count = u128::from(count);
    let mut unit = 0;
    let mut divisor: u128 = 1;
    let mut tenths = count * 10;
    while (tenths + divisor / 2) / divisor >= 10_000 && unit + 1 < UNITS.len() {
        divisor *= 1000;
        unit += 1;
        tenths = count * 10;
    }
    let tenths = (tenths + divisor / 2) / divisor;
    if tenths < 100 {
        format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[unit])
    } else {
        format!("{} {}", (tenths + 5) / 10, UNITS[unit])
    }
}

/// How long ago something happened, in the unit a person would say: `now`, `12 s ago`, `3 min ago`, `2 h ago`, `4 d ago`.
#[must_use]
pub fn age(seconds: u64) -> String {
    match seconds {
        0..=1 => "now".to_owned(),
        2..=59 => format!("{seconds} s ago"),
        60..=3599 => format!("{} min ago", seconds / 60),
        3600..=86399 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86400),
    }
}

#[cfg(test)]
mod tests {
    use super::{age, bytes, pairs, table, truncate, wrap};

    fn rows(items: &[&[&str]]) -> Vec<Vec<String>> {
        items
            .iter()
            .map(|row| row.iter().map(|cell| (*cell).to_owned()).collect())
            .collect()
    }

    #[test]
    fn a_table_has_a_header_only_from_two_rows() {
        let one = table(&["Name", "State"], &rows(&[&["mesh", "on"]]), 0, 80, None);
        assert_eq!(one, "mesh  on\n");
        let two = table(
            &["Name", "State"],
            &rows(&[&["mesh", "on"], &["relay", "off"]]),
            0,
            80,
            None,
        );
        assert_eq!(two, "NAME   STATE\nmesh   on\nrelay  off\n");
    }

    #[test]
    fn a_table_fits_its_width_by_wrapping_only_the_last_column() {
        let text = table(
            &["Peer", "Note"],
            &rows(&[&["a", "one two three four five six seven"], &["b", "x"]]),
            0,
            24,
            None,
        );
        assert!(
            text.lines().all(|line| line.chars().count() <= 24),
            "{text}"
        );
        assert!(text.lines().count() > 3, "wrapped: {text}");
    }

    #[test]
    fn wide_leading_columns_are_cut_with_an_ellipsis() {
        let text = table(
            &["A", "B"],
            &rows(&[&["abcdefghijklmnopqrstuvwxyz", "1"], &["x", "2"]]),
            0,
            16,
            None,
        );
        assert!(text.contains('…'), "{text}");
        assert!(
            text.lines().all(|line| line.chars().count() <= 16),
            "{text}"
        );
    }

    #[test]
    fn tint_wraps_text_after_padding_is_measured() {
        let tint =
            |column: usize, text: &str| (column == 0 && text == "mesh").then_some("\u{1b}[32m");
        let text = table(
            &["Name", "State"],
            &rows(&[&["mesh", "on"], &["relay", "off"]]),
            0,
            80,
            Some(&tint),
        );
        assert!(text.contains("\u{1b}[32mmesh\u{1b}[0m   on"), "{text:?}");
    }

    #[test]
    fn sizes_and_ages_use_units_a_person_would_say() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_500), "1.5 kB");
        assert_eq!(bytes(18_056_740), "18 MB");
        assert_eq!(bytes(19_041_052), "19 MB");
        assert_eq!(bytes(999_999), "1.0 MB");
        assert_eq!(age(0), "now");
        assert_eq!(age(12), "12 s ago");
        assert_eq!(age(180), "3 min ago");
        assert_eq!(age(7300), "2 h ago");
        assert_eq!(age(400_000), "4 d ago");
    }

    #[test]
    fn pairs_align_values_and_wrap_under_them() {
        let text = pairs(
            &[
                ("Role", "host".to_owned()),
                ("Version", "0.1.0 edge".to_owned()),
            ],
            2,
            40,
        );
        assert_eq!(text, "  Role     host\n  Version  0.1.0 edge\n");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(wrap("", 5), vec![String::new()]);
    }
}
