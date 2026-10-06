//! Alacritty VT state and bounded repaint serialization, including parser continuations [13].
#![forbid(unsafe_code)]
use crate::frame::MAX_FRAME;
use alacritty_terminal::{
    event::VoidListener,
    grid::{Charsets, Dimensions, Grid},
    index::{Column, Line},
    term::{
        Config, Term, TermMode,
        cell::{Cell, Flags},
    },
    vte::ansi::{self, CharsetIndex, Color, CursorShape, NamedColor, StandardCharset},
};
use std::{fmt::Write as _, io};
const SCROLLBACK: usize = 10_000;
#[derive(Clone, Copy)]
struct Size {
    cols: u16,
    rows: u16,
}
impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        usize::from(self.rows)
    }
    fn screen_lines(&self) -> usize {
        usize::from(self.rows)
    }
    fn columns(&self) -> usize {
        usize::from(self.cols)
    }
}
#[derive(Default)]
struct Observer {
    margins: Option<(u16, u16)>,
    alt: Option<bool>,
    complete: bool,
    tab: Option<u16>,
    charset: u8,
    reset: bool,
    saved_charset: u8,
}
impl vte::Perform for Observer {
    fn print(&mut self, _: char) {
        self.complete = true;
    }
    fn execute(&mut self, byte: u8) {
        if byte == 0x0e {
            self.charset = 1;
        }
        if byte == 0x0f {
            self.charset = 0;
        }
        if matches!(byte, 0x18 | 0x1a) {
            self.complete = true;
        }
    }
    fn csi_dispatch(
        &mut self,
        params: &vte::Params,
        intermediates: &[u8],
        ignore: bool,
        action: char,
    ) {
        self.complete = true;
        if ignore {
            return;
        }
        if intermediates.is_empty() && action == 's' {
            self.saved_charset = self.charset;
        }
        if intermediates.is_empty() && action == 'u' {
            self.charset = self.saved_charset;
        }
        if intermediates.is_empty() && action == 'g' {
            self.tab = Some(
                params
                    .iter()
                    .next()
                    .and_then(|p| p.first())
                    .copied()
                    .unwrap_or(0),
            );
        }
        if intermediates.is_empty() && action == 'r' {
            let mut values = params.iter();
            let top = values
                .next()
                .and_then(|p| p.first())
                .copied()
                .unwrap_or(1)
                .max(1);
            let bottom = values.next().and_then(|p| p.first()).copied().unwrap_or(0);
            self.margins = Some((top, bottom));
        }
        if intermediates == b"?"
            && matches!(action, 'h' | 'l')
            // Alacritty/vte recognizes only 1049 as an alternate-screen mode.
            // Observing ignored 47/1047 would retain a stale primary grid and
            // repaint it over live text even though the runtime never switched.
            && params.iter().any(|p| matches!(p, [1049]))
        {
            self.alt = Some(action == 'h');
        }
    }
    fn esc_dispatch(&mut self, intermediates: &[u8], _: bool, byte: u8) {
        self.complete = true;
        if intermediates.is_empty() {
            match byte {
                b'c' => {
                    self.margins = Some((1, 0));
                    self.charset = 0;
                    self.reset = true;
                }
                b'H' => self.tab = Some(4),
                b'7' => self.saved_charset = self.charset,
                b'8' => self.charset = self.saved_charset,
                b'n' => self.charset = 2,
                b'o' => self.charset = 3,
                _ => {}
            }
        }
    }
    fn osc_dispatch(&mut self, _: &[&[u8]], _: bool) {
        self.complete = true;
    }
    fn unhook(&mut self) {
        self.complete = true;
    }
}
pub struct Terminal {
    term: Term<VoidListener>,
    parser: ansi::Processor,
    observer: Observer,
    observer_parser: vte::Parser,
    pending: Vec<u8>,
    primary: Option<Grid<Cell>>,
    margins: (u16, u16),
    size: Size,
    tabs: Vec<bool>,
}
impl Terminal {
    pub fn new(cols: u16, rows: u16) -> io::Result<Self> {
        if cols == 0 || rows == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal dimensions must be nonzero",
            ));
        }
        let size = Size { cols, rows };
        Ok(Self {
            term: Term::new(
                Config {
                    scrolling_history: SCROLLBACK,
                    ..Config::default()
                },
                &size,
                VoidListener,
            ),
            parser: ansi::Processor::new(),
            observer: Observer::default(),
            observer_parser: vte::Parser::new(),
            pending: Vec::new(),
            primary: None,
            margins: (1, rows),
            size,
            tabs: (0..cols).map(|col| col % 8 == 0).collect(),
        })
    }
    pub fn process(&mut self, bytes: &[u8]) {
        let mut parsed = 0;
        for (i, &byte) in bytes.iter().enumerate() {
            // Printable ASCII in ground state cannot change observer metadata.
            // Skip the second parser here; Alacritty still receives every byte.
            if (0x20..0x7f).contains(&byte) && self.pending.is_empty() {
                continue;
            }
            let string = self
                .pending
                .get(1)
                .is_some_and(|start| matches!(start, b']' | b'P' | b'_' | b'^' | b'X'));
            if byte == 0x1b && !string {
                self.pending.clear();
            }
            if !self.pending.is_empty() || byte == 0x1b || byte >= 0xc0 {
                if self.pending.len() < 4096 {
                    self.pending.push(byte);
                } else if byte == 0x1b {
                    self.pending[4095] = byte;
                }
            }
            self.observer.complete = false;
            self.observer_parser.advance(&mut self.observer, &[byte]);
            if self.observer.reset {
                self.tabs = (0..self.size.cols).map(|col| col % 8 == 0).collect();
                self.primary = None;
                self.observer.reset = false;
            }
            if let Some(action) = self.observer.tab.take() {
                self.parser.advance(&mut self.term, &bytes[parsed..i]);
                parsed = i;
                let col = self.term.grid().cursor.point.column.0;
                if action == 3 {
                    self.tabs.fill(false);
                } else if let Some(tab) = self.tabs.get_mut(col)
                    && (action == 0 || action == 4)
                {
                    *tab = action == 4;
                }
            }
            if let Some(alt) = self.observer.alt.take() {
                self.parser.advance(&mut self.term, &bytes[parsed..i]);
                parsed = i;
                if alt && !self.term.mode().contains(TermMode::ALT_SCREEN) {
                    self.primary = Some(primary_tail(self.term.grid()));
                }
                if !alt {
                    self.primary = None;
                }
            }
            if let Some((top, bottom)) = self.observer.margins.take() {
                let bottom = if bottom == 0 { self.size.rows } else { bottom };
                if top < bottom && bottom <= self.size.rows {
                    self.margins = (top, bottom);
                }
            }
            if self.observer.complete {
                self.pending.clear();
                // OSC dispatch occurs at ESC, before the following ST '\'.
                // Preserve that escape state so the next byte is not printed.
                if byte == 0x1b {
                    self.pending.push(byte);
                }
            }
            // C0 actions already changed the grid; replaying them inside an
            // unfinished CSI would move the restored cursor a second time.
            if !self.observer.complete
                && byte < 0x20
                && byte != 0x1b
                && self.pending.last() == Some(&byte)
            {
                self.pending.pop();
            }
            // VTE bounds its own control-string storage. Keeping this prefix
            // reproduces that parser state without retaining unbounded OSC.
        }
        self.parser.advance(&mut self.term, &bytes[parsed..]);
    }
    pub fn resize(&mut self, cols: u16, rows: u16) -> io::Result<()> {
        if cols == 0 || rows == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal dimensions must be nonzero",
            ));
        }
        let old_cols = self.size.cols;
        self.tabs.resize(usize::from(cols), false);
        for col in old_cols..cols {
            self.tabs[usize::from(col)] = col % 8 == 0;
        }
        self.size = Size { cols, rows };
        self.term.resize(self.size);
        self.margins = (1, rows);
        if let Some(primary) = &mut self.primary {
            primary.resize(true, usize::from(rows), usize::from(cols));
        }
        Ok(())
    }
    #[allow(clippy::too_many_lines)]
    pub fn snapshot(&self) -> io::Result<Vec<u8>> {
        let alt = self.term.mode().contains(TermMode::ALT_SCREEN);
        let primary = self.primary.as_ref().unwrap_or(self.term.grid());
        let mut out = String::from("\x1bc\x1b[?6l\x1b[r\x1b[?7h");
        for index in 0..=258 {
            if let Some(color) = self.term.colors()[index] {
                let prefix = if index < 256 {
                    format!("4;{index}")
                } else {
                    (index - 256 + 10).to_string()
                };
                let _ = write!(
                    out,
                    "\x1b]{prefix};rgb:{:02x}/{:02x}/{:02x}\x1b\\",
                    color.r, color.g, color.b
                );
            }
        }
        // Tail is deliberately limited: a frozen frame cannot exceed 1 MiB.
        // Scrollback is emitted oldest first into the primary screen, then the
        // primary and alternate screens are restored independently.
        let prefix_len = out.len();
        let mut tail = Vec::new();
        let history = primary.history_size().min(256);
        for line in -(i32::try_from(history).unwrap_or(0))..0 {
            let mut text = String::new();
            row(&mut text, primary, line, self.size.cols);
            text.push_str("\x1b[0m");
            if !primary[Line(line)][Column(primary.columns() - 1)]
                .flags
                .contains(Flags::WRAPLINE)
            {
                text.push_str("\r\n");
            }
            tail.push(text);
        }
        paint(&mut out, primary, self.size);
        if alt {
            out.push_str("\x1b[?1049h");
            paint(&mut out, self.term.grid(), self.size);
        }
        let mode = self.term.mode();
        for (flag, number) in [
            (TermMode::APP_CURSOR, 1),
            (TermMode::SHOW_CURSOR, 25),
            (TermMode::LINE_WRAP, 7),
            (TermMode::MOUSE_REPORT_CLICK, 1000),
            (TermMode::MOUSE_DRAG, 1002),
            (TermMode::MOUSE_MOTION, 1003),
            (TermMode::FOCUS_IN_OUT, 1004),
            (TermMode::UTF8_MOUSE, 1005),
            (TermMode::SGR_MOUSE, 1006),
            (TermMode::ALTERNATE_SCROLL, 1007),
            (TermMode::BRACKETED_PASTE, 2004),
        ] {
            let _ = write!(
                out,
                "\x1b[?{number}{}",
                if mode.contains(flag) { 'h' } else { 'l' }
            );
        }
        out.push_str(if mode.contains(TermMode::APP_KEYPAD) {
            "\x1b="
        } else {
            "\x1b>"
        });
        let _ = write!(
            out,
            "\x1b[4{}\x1b[20{}",
            if mode.contains(TermMode::INSERT) {
                'h'
            } else {
                'l'
            },
            if mode.contains(TermMode::LINE_FEED_NEW_LINE) {
                'h'
            } else {
                'l'
            }
        );
        out.push_str("\x1b[3g");
        for (col, set) in self.tabs.iter().enumerate() {
            if *set {
                let _ = write!(out, "\x1b[1;{}H\x1bH", col + 1);
            }
        }
        let style = self.term.cursor_style();
        let shape = match style.shape {
            CursorShape::Underline => 3,
            CursorShape::Beam => 5,
            _ => 1,
        };
        let _ = write!(out, "\x1b[{} q", shape + u8::from(!style.blinking));
        let keyboard = u8::from(mode.contains(TermMode::DISAMBIGUATE_ESC_CODES))
            | (u8::from(mode.contains(TermMode::REPORT_EVENT_TYPES)) << 1)
            | (u8::from(mode.contains(TermMode::REPORT_ALTERNATE_KEYS)) << 2)
            | (u8::from(mode.contains(TermMode::REPORT_ALL_KEYS_AS_ESC)) << 3)
            | (u8::from(mode.contains(TermMode::REPORT_ASSOCIATED_TEXT)) << 4);
        let _ = write!(out, "\x1b[={keyboard}u");
        let (top, bottom) = self.margins;
        let _ = write!(out, "\x1b[{top};{bottom}r");
        if mode.contains(TermMode::ORIGIN) {
            out.push_str("\x1b[?6h");
        }
        let cursor = &self.term.grid().cursor;
        let cursor_row = cursor.point.line.0 + 1
            - if mode.contains(TermMode::ORIGIN) {
                i32::from(top) - 1
            } else {
                0
            };
        let _ = write!(out, "\x1b[{cursor_row};{}H", cursor.point.column.0 + 1);
        attrs(&mut out, &cursor.template);
        charsets(&mut out, cursor.charsets, self.observer.charset);
        if cursor.input_needs_wrap {
            // CUP clears pending wrap. Rewrite the last cell to recreate it.
            let cell = &self.term.grid()[cursor.point];
            attrs(&mut out, cell);
            out.push(cell.c);
            attrs(&mut out, &cursor.template);
        }
        let limit = MAX_FRAME - 9;
        let base_len = out.len() + self.pending.len();
        if base_len > limit {
            return Err(io::Error::other(
                "screen repaint exceeds frozen frame limit",
            ));
        }
        let scroll = format!("\x1b[{}S", self.size.rows);
        let mut available = (limit - base_len).saturating_sub(scroll.len());
        let mut first = tail.len();
        for (index, line) in tail.iter().enumerate().rev() {
            if line.len() > available {
                break;
            }
            available -= line.len();
            first = index;
        }
        let mut bytes = Vec::with_capacity(
            base_len + tail[first..].iter().map(String::len).sum::<usize>() + scroll.len(),
        );
        bytes.extend_from_slice(&out.as_bytes()[..prefix_len]);
        for line in &tail[first..] {
            bytes.extend_from_slice(line.as_bytes());
        }
        if first < tail.len() {
            bytes.extend_from_slice(scroll.as_bytes());
        }
        bytes.extend_from_slice(&out.as_bytes()[prefix_len..]);
        bytes.extend_from_slice(&self.pending);
        Ok(bytes)
    }
}
// Retain only the repaint tail when entering the alternate screen. Cloning a
// full 10,000-line history would double its memory and stall vim startup.
fn primary_tail(grid: &Grid<Cell>) -> Grid<Cell> {
    let history = grid.history_size().min(256);
    let mut copy = Grid::new(grid.screen_lines(), grid.columns(), history);
    copy.initialize_all();
    for line in
        -i32::try_from(history).unwrap_or(0)..i32::try_from(grid.screen_lines()).unwrap_or(0)
    {
        copy[Line(line)] = grid[Line(line)].clone();
    }
    copy.cursor = grid.cursor.clone();
    copy.saved_cursor = grid.saved_cursor.clone();
    copy
}

fn paint(out: &mut String, grid: &Grid<Cell>, size: Size) {
    out.push_str("\x1b(B\x0f\x1b[?6l\x1b[r\x1b[4l\x1b[H\x1b[2J");
    for line in 0..i32::from(size.rows) {
        if line == 0
            || !grid[Line(line - 1)][Column(grid.columns() - 1)]
                .flags
                .contains(Flags::WRAPLINE)
        {
            let _ = write!(out, "\x1b[{};1H", line + 1);
        }
        row(out, grid, line, size.cols);
    }
    let saved = &grid.saved_cursor;
    let _ = write!(
        out,
        "\x1b[{};{}H",
        saved.point.line.0 + 1,
        saved.point.column.0 + 1
    );
    attrs(out, &saved.template);
    charsets(out, saved.charsets, 0);
    out.push_str("\x1b7");
    let cursor = &grid.cursor;
    let _ = write!(
        out,
        "\x1b[{};{}H",
        cursor.point.line.0 + 1,
        cursor.point.column.0 + 1
    );
    attrs(out, &cursor.template);
    charsets(out, cursor.charsets, 0);
}
fn row(out: &mut String, grid: &Grid<Cell>, line: i32, cols: u16) {
    if line < -(i32::try_from(grid.history_size()).unwrap_or(0))
        || line >= i32::try_from(grid.screen_lines()).unwrap_or(0)
    {
        return;
    }
    let mut previous: Option<&Cell> = None;
    for col in 0..usize::from(cols).min(grid.columns()) {
        let cell = &grid[Line(line)][Column(col)];
        if cell
            .flags
            .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
        {
            continue;
        }
        if previous.is_none_or(|p| {
            p.fg != cell.fg || p.bg != cell.bg || p.flags != cell.flags || p.extra != cell.extra
        }) {
            attrs(out, cell);
        }
        out.push(cell.c);
        if let Some(chars) = cell.zerowidth() {
            for c in chars {
                out.push(*c);
            }
        }
        previous = Some(cell);
    }
}
fn attrs(out: &mut String, cell: &Cell) {
    out.push_str("\x1b[0m");
    if let Some(link) = cell.hyperlink() {
        let _ = write!(out, "\x1b]8;id={};{}\x1b\\", link.id(), link.uri());
    } else {
        out.push_str("\x1b]8;;\x1b\\");
    }
    for (flag, sgr) in [
        (Flags::BOLD, "1"),
        (Flags::DIM, "2"),
        (Flags::ITALIC, "3"),
        (Flags::UNDERLINE, "4"),
        (Flags::DOUBLE_UNDERLINE, "4:2"),
        (Flags::UNDERCURL, "4:3"),
        (Flags::DOTTED_UNDERLINE, "4:4"),
        (Flags::DASHED_UNDERLINE, "4:5"),
        (Flags::INVERSE, "7"),
        (Flags::HIDDEN, "8"),
        (Flags::STRIKEOUT, "9"),
    ] {
        if cell.flags.contains(flag) {
            let _ = write!(out, "\x1b[{sgr}m");
        }
    }
    color(out, cell.fg, 38);
    color(out, cell.bg, 48);
    if let Some(c) = cell.underline_color() {
        color(out, c, 58);
    }
}
fn charsets(out: &mut String, sets: Charsets, active: u8) {
    for (index, designator) in [
        (CharsetIndex::G0, '('),
        (CharsetIndex::G1, ')'),
        (CharsetIndex::G2, '*'),
        (CharsetIndex::G3, '+'),
    ] {
        let code = match sets[index] {
            StandardCharset::Ascii => 'B',
            StandardCharset::SpecialCharacterAndLineDrawing => '0',
        };
        let _ = write!(out, "\x1b{designator}{code}");
    }
    out.push_str(match active {
        1 => "\x0e",
        2 => "\x1bn",
        3 => "\x1bo",
        _ => "\x0f",
    });
}

fn color(out: &mut String, color: Color, base: u8) {
    match color {
        Color::Spec(c) => {
            let _ = write!(out, "\x1b[{base};2;{};{};{}m", c.r, c.g, c.b);
        }
        Color::Indexed(n) => {
            let _ = write!(out, "\x1b[{base};5;{n}m");
        }
        Color::Named(NamedColor::Foreground | NamedColor::Background) => {}
        Color::Named(n) => {
            let value = n as u16;
            if value < 16 {
                let sgr = if value < 8 {
                    30 + value
                } else {
                    90 + value - 8
                } + if base == 48 { 10 } else { 0 };
                let _ = write!(out, "\x1b[{sgr}m");
            }
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/terminal.rs"]
mod checks;

#[cfg(test)]
#[path = "../tests/unit/terminal_budgets.rs"]
mod measurements;
