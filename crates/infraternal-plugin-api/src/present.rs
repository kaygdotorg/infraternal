//! Shared text presentation for operator output: aligned tables, human sizes and ages (#239, D202, D299).
//!
//! The CLI core and every plugin that presents its own records use these helpers, so
//! a table printed by the core and a table printed by a plugin follow the same rules:
//! a header only when there are two rows or more, every column as wide as its widest
//! value, and only the last column wraps. Long words stay intact so they can be copied.
//! Raw values (byte counts, epoch times) belong in `--json`; people get the units here.

use serde_json::Value;
use unicode_width::{UnicodeWidthChar as _, UnicodeWidthStr};

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
                header[column].to_uppercase().width()
            } else {
                0
            };
            for row in 0..rows.len() {
                widest = widest.max(cells(row, column).width());
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
            let used = text.width();
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

/// Shorten a cell to its column width with an ASCII marker.
#[must_use]
pub fn truncate(text: &str, width: usize) -> String {
    if text.width() <= width {
        return text.to_owned();
    }
    let marker = ".".repeat(width.min(3));
    let mut available = width - marker.len();
    let mut cut = String::new();
    for character in text.chars() {
        let columns = character.width().unwrap_or(0);
        if columns > available {
            break;
        }
        available -= columns;
        cut.push(character);
    }
    cut.push_str(&marker);
    cut
}

/// Wrap prose at word boundaries. Keep a long word intact so URLs and command
/// arguments can still be copied. The terminal can display them on several lines.
#[must_use]
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.width() + 1 + word.width() > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() || lines.is_empty() {
        lines.push(line);
    }
    lines
}

/// Treat pipes and terminals with missing or dumb terminal metadata as plain text.
#[must_use]
pub fn interactive(is_terminal: bool) -> bool {
    is_terminal && std::env::var_os("TERM").is_some_and(|term| !term.is_empty() && term != "dumb")
}

/// Use terminal glyphs only when the effective locale declares UTF-8.
#[must_use]
pub fn supports_unicode(is_terminal: bool) -> bool {
    interactive(is_terminal)
        && ["LC_ALL", "LC_CTYPE", "LANG"]
            .into_iter()
            .filter_map(std::env::var_os)
            .find(|locale| !locale.is_empty())
            .is_some_and(|locale| {
                let locale = locale.to_string_lossy().to_ascii_lowercase();
                locale.contains("utf-8") || locale.contains("utf8")
            })
}

/// Put a list marker on each item's first line and align its continuations.
#[must_use]
pub fn bullets(items: &[String], indent: usize, width: usize, unicode: bool) -> String {
    use std::fmt::Write as _;

    let marker = if unicode { "•" } else { "-" };
    let margin = " ".repeat(indent);
    let mut out = String::new();
    for item in items {
        for (index, line) in wrap(item, width.saturating_sub(indent + 2))
            .iter()
            .enumerate()
        {
            let prefix = if index == 0 { marker } else { " " };
            let _ = writeln!(out, "{margin}{prefix} {line}");
        }
    }
    out
}

/// Frame text that fits in the available columns. Keep long unbroken values
/// intact and unframed when the window is too narrow to contain them.
#[must_use]
pub fn panel(body: &str, indent: usize, width: usize, unicode: bool) -> String {
    use std::fmt::Write as _;

    let content = body.lines().map(UnicodeWidthStr::width).max().unwrap_or(0);
    if !unicode || content == 0 || content + indent + 4 > width {
        let margin = " ".repeat(indent);
        return body
            .lines()
            .map(|line| format!("{margin}{line}\n"))
            .collect();
    }
    let margin = " ".repeat(indent);
    let rule = "─".repeat(content + 2);
    let mut out = format!("{margin}┌{rule}┐\n");
    for line in body.lines() {
        let padding = " ".repeat(content - line.width());
        let _ = writeln!(out, "{margin}│ {line}{padding} │");
    }
    let _ = writeln!(out, "{margin}└{rule}┘");
    out
}

/// Render an aligned table in a frame on a Unicode terminal.
#[must_use]
pub fn terminal_table(
    header: &[&str],
    rows: &[Vec<String>],
    indent: usize,
    width: usize,
    unicode: bool,
) -> String {
    let room = width.saturating_sub(indent + if unicode { 4 } else { 0 });
    panel(&table(header, rows, 0, room, None), indent, width, unicode)
}

/// Aligned `label  value` lines; values wrap under their own column.
#[must_use]
pub fn pairs(rows: &[(&str, String)], indent: usize, width: usize) -> String {
    let label = rows
        .iter()
        .map(|(label, _)| label.width())
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
                out.push_str(&" ".repeat(label - name.width() + GAP));
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
    //! Pins the output shared by the CLI and plugin presenters.

    use super::{age, bullets, bytes, pairs, table, terminal_table, truncate, wrap};

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

    /// A narrow table shortens its leading columns with a plain marker.
    #[test]
    fn wide_leading_columns_are_cut_with_an_ascii_marker() {
        let text = table(
            &["A", "B"],
            &rows(&[&["abcdefghijklmnopqrstuvwxyz", "1"], &["x", "2"]]),
            0,
            16,
            None,
        );
        assert!(text.contains("..."), "{text}");
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

    /// Tables count display columns, including the extra column for a wide character.
    #[test]
    fn terminal_and_plain_tables_have_aligned_columns() {
        let data = rows(&[&["大阪", "on"], &["relay", "off"]]);
        assert_eq!(
            terminal_table(&["Name", "State"], &data, 0, 80, true),
            "┌──────────────┐\n│ NAME   STATE │\n│ 大阪   on    │\n│ relay  off   │\n└──────────────┘\n"
        );
        assert_eq!(
            terminal_table(&["Name", "State"], &data, 0, 80, false),
            "NAME   STATE\n大阪   on\nrelay  off\n"
        );
    }

    /// Long copyable values stay intact even if the line has to overflow.
    #[test]
    fn wrapping_preserves_commands_and_urls() {
        let url = "https://server.example.org/#join=fake-code";
        assert_eq!(wrap(&format!("Open {url}"), 20), ["Open", url]);
        assert_eq!(
            bullets(&["Run this command again".to_owned()], 0, 16, false),
            "- Run this\n  command again\n"
        );
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

    /// Key/value blocks align their value columns and keep empty values printable.
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
        assert_eq!(truncate("abcdef", 4), "a...");
        assert_eq!(wrap("", 5), vec![String::new()]);
    }
}
