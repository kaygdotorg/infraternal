//! Snapshot adapter over libghostty-vt 1.0's bounded state [13][94].
//! The stable C API has a binary snapshot codec, while existing clients resume
//! from VT escape sequences. This read-only adapter accesses engine-owned
//! screen and cell state to produce that bounded replay without a mirror VT.
const std = @import("std");
const c = @import("terminal/c/terminal.zig");
const vt = @import("terminal/main.zig");
const lib = @import("terminal/lib.zig");
const Writer = std.Io.Writer;
const SnapshotError = Writer.Error || error{Unrepresentable};
const unicode = @import("unicode/main.zig");

/// Byte count on success, zero on overflow, max usize for a state requiring
/// nonprinting upstream restoration. Serialization never mutates the source.
pub fn snapshot(handle: c.Terminal, buf: [*]u8, len: usize, tail: usize) callconv(lib.calling_conv) usize {
    const t = c.zigTerminal(handle) orelse return 0;
    var w = Writer.fixed(buf[0..len]);
    serialize(t, &w, tail) catch |err| return if (err == error.Unrepresentable) std.math.maxInt(usize) else 0;
    return w.end;
}

fn serialize(t: *const vt.Terminal, w: *Writer, tail: usize) SnapshotError!void {
    // OSC 133 click settings and live prompt state affect interaction. VT
    // painting cannot import retained cell/row semantics without triggering
    // actions, so reject those while allowing history metadata outside the
    // bounded export tail to be omitted.
    // C initialization starts at false, while RIS starts at true. Restoring
    // false through OSC 133 would itself create unimportable semantic state.
    if (t.flags.shell_redraws_prompt != .true) return error.Unrepresentable;
    // The bounded painter cannot recreate a boundary wrap flag independently
    // of adjacent history or scrolling. Refuse these states until upstream
    // exposes nonprinting row-wrap restoration instead of emitting a lossy VT.
    inline for (.{ .primary, .alternate }) |key| {
        if (t.screens.get(key)) |screen| {
            // `seen` is a screen-wide aggregate over all history. The bounded
            // snapshot may omit the rows it summarizes, so only the live click
            // behavior must be preserved here; retained rows are checked below.
            if (screen.semantic_prompt.click != .none or screen.cursor.semantic_content != .output or screen.cursor.semantic_content_clear_eol) return error.Unrepresentable;
            // Cursor copies can inherit protection into a screen whose sticky
            // mode is off. VT can set protection only by selecting a mode;
            // reject this construction gap rather than changing later erase.
            if (screen.protected_mode == .off and (screen.cursor.protected or if (screen.saved_cursor) |saved| saved.protected else false)) return error.Unrepresentable;
            // Validate the exported extent, not intentionally omitted older
            // history. Frozen v1 permits tail truncation, so a screen-wide
            // `seen` aggregate may differ when its marked rows fall outside
            // this range. This bounds validation to visible rows plus the tail
            // instead of scanning ~10k stored rows on every Snapshot request.
            const history = screen.pages.total_rows - t.rows;
            const first_exported = history - @min(history, tail);
            var semantic_rows = screen.pages.rowIterator(.right_down, .{ .screen = .{ .x = 0, .y = @intCast(first_exported) } }, null);
            while (semantic_rows.next()) |semantic_row| {
                if (semantic_row.rowAndCell().row.semantic_prompt != .none) return error.Unrepresentable;
                for (semantic_row.cells(.all)) |value| {
                    if (value.semantic_content != .output or (screen.protected_mode == .off and value.protected)) return error.Unrepresentable;
                }
            }
            const p = screen.pages.pin(.{ .active = .{ .x = 0, .y = t.rows - 1 } }).?;
            if (p.rowAndCell().row.wrap) return error.Unrepresentable;
            const first = screen.pages.pin(.{ .active = .{ .x = 0, .y = 0 } }).?;
            if (first.rowAndCell().row.wrap_continuation) return error.Unrepresentable;
            var previous_wrap = first.rowAndCell().row.wrap;
            for (1..t.rows) |y| {
                const current = screen.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
                if (current.rowAndCell().row.wrap_continuation and !previous_wrap) return error.Unrepresentable;
                if (y + 1 == t.rows and previous_wrap and !current.rowAndCell().row.wrap_continuation) return error.Unrepresentable;
                previous_wrap = current.rowAndCell().row.wrap;
            }
        }
    }
    try w.writeAll("\x1bc\x1b[?6l\x1b[r\x1b[?7h\x1b[?2027l");
    // DECSM stores values independently of live modes. Seed these before
    // painting, because screen and cursor modes can have destructive effects.
    const defaults: vt.modes.ModeState = .{};
    const mode_info = @typeInfo(vt.modes.Mode).@"enum";
    inline for (mode_info.field_names, mode_info.field_values) |name, value| {
        const mode: vt.modes.Mode = @enumFromInt(value);
        const tag = vt.modes.ModeTag.fromMode(mode);
        const saved = @field(t.modes.saved, name);
        if (saved != @field(defaults.saved, name)) {
            if (tag.ansi) return error.Unrepresentable;
            try w.print("\x1b[?{d}{c}\x1b[?{d}s\x1b[?{d}{c}", .{ tag.value, @as(u8, if (saved) 'h' else 'l'), tag.value, tag.value, @as(u8, if (defaults.get(mode)) 'h' else 'l') });
        }
    }
    try restoreColors(w, t);
    const primary = t.screens.get(.primary).?;
    // Printing changes the terminal-global REP source. Reconstruct the
    // inactive screen first so its final character cannot win on replay.
    if (t.screens.active_key == .primary) {
        if (t.screens.get(.alternate)) |alt| {
            try w.writeAll("\x1b[?47h");
            try paint(w, t, alt);
            try w.writeAll("\x1b[?47l");
        }
    }
    const history = primary.pages.total_rows - t.rows;
    const count = @min(history, tail);
    if (count != 0) {
        // A truncated first row cannot inherit wrap from a discarded predecessor.
        const first_history = primary.pages.pin(.{ .screen = .{ .x = 0, .y = @intCast(history - count) } }).?;
        if (first_history.rowAndCell().row.wrap_continuation) return error.Unrepresentable;
        // Inactive-screen restoration copies cursor state and leaves global
        // margins/styles live. Start history in an absolute, neutral context;
        // otherwise its first row can wrap or scroll only an interior region.
        try w.writeAll("\x1b(B\x1b*B\x1b+B\x0f\x1b[?2027l\x1b[?7h\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[H\x1b[0m\x1b[0\"q\x1b]8;;\x1b\\");
        // Each lookup resolves one row, never one cell through full history.
        var skip_first = false;
        for (history - count..history) |y| {
            const p = primary.pages.pin(.{ .screen = .{ .x = 0, .y = @intCast(y) } }).?;
            skip_first = try row(w, p, skip_first);
            if (!p.rowAndCell().row.wrap) try w.writeAll("\x1b[0m\r\n");
        }
        // CRLF has already scrolled the earlier rows. Push only the remaining
        // painted rows, excluding the trailing blank cursor row; SU zero means
        // one on VT, so omit it rather than creating padding history.
        const remaining = @min(count, @as(usize, t.rows) - 1);
        if (remaining != 0) try w.print("\x1b[{d}S", .{remaining});
    }
    try paint(w, t, primary);
    if (t.screens.active_key == .alternate) {
        const alt = t.screens.get(.alternate).?;
        // 47 preserves saved cursors and content, unlike 1049 which saves and
        // clears on every set, including nested sets. Continuations retain
        // their original 47/1047/1049 behavior in the real engine.
        try w.writeAll("\x1b[?47h");
        try paint(w, t, alt);
    }
    // Modes with screen-switching or reset side effects are represented by
    // the screen construction above, rather than dispatched a second time.
    inline for (@typeInfo(vt.modes.Mode).@"enum".field_values) |value| {
        const mode: vt.modes.Mode = @enumFromInt(value);
        const tag = vt.modes.ModeTag.fromMode(mode);
        if (!(tag.value == 47 or tag.value == 1047 or tag.value == 1049 or tag.value == 1048 or tag.value == 6 or tag.value == 7 or tag.value == 69 or tag.value == 2026)) {
            try w.print("\x1b[{s}{d}{c}", .{ if (tag.ansi) "" else "?", tag.value, @as(u8, if (t.modes.get(mode)) 'h' else 'l') });
        }
    }
    try restoreMouse(w, t);
    try w.writeAll("\x1b[?6l\x1b[3g");
    for (0..t.cols) |x| if (t.tabstops.get(@intCast(x))) {
        try w.print("\x1b[1;{d}H\x1bH", .{x + 1});
    };
    try restoreRep(w, t);
    try regions(w, t);
    try w.print("\x1b[?7{c}", .{@as(u8, if (t.modes.get(.wraparound)) 'h' else 'l')});
    const screen = t.screens.active;
    try cursorShape(w, t, screen);
    try liveCursor(w, t, screen, t.modes.get(.origin), true);
    // A wide print at the right margin with wrapping disabled is ignored by
    // the grid, but Ghostty still records it as the REP source. This also
    // handles a pending cursor whose edge cell has a different character.
    if (screen.cursor.pending_wrap) {
        if (t.previous_char) |cp| {
            const saved_anchor = if (screen.saved_cursor) |saved| saved.pending_wrap and saved.x == screen.cursor.x and saved.y == screen.cursor.y and saved.origin == t.modes.get(.origin) else false;
            // liveCursor already reprints the edge cell to recreate pending
            // wrap. If that cell's base codepoint is also the REP source, a
            // second wrap-disabled print would clear the restored pending flag.
            const edge_rep_matches = if (saved_anchor) false else pendingEdgeRepMatches(screen, cp);
            if (unicode.table.get(cp).width == 2 and !saved_anchor and !edge_rep_matches) {
                try w.writeAll("\x1b[?7l\x1b[?2027l\x1b(B\x1b*B\x1b+B\x0f");
                try codepoint(w, cp);
                try w.print("\x1b[?7{c}\x1b[?2027{c}", .{ @as(u8, if (t.modes.get(.wraparound)) 'h' else 'l'), @as(u8, if (t.modes.get(.grapheme_cluster)) 'h' else 'l') });
                try charset(w, screen.charset);
            }
        }
    }
    try w.print("\x1b[4{c}", .{@as(u8, if (t.modes.get(.insert)) 'h' else 'l')});
}

/// Whether recreating the pending cursor already restored its REP source.
/// Grapheme extensions do not replace the terminal's base-codepoint REP source.
fn pendingEdgeRepMatches(screen: *const vt.Screen, cp: u21) bool {
    const cursor = screen.cursor;
    var p = screen.pages.pin(.{ .active = .{ .x = cursor.x, .y = cursor.y } }) orelse return false;
    if (p.rowAndCell().cell.wide == .spacer_tail and p.x > 0) p.x -= 1;
    const value = p.rowAndCell().cell;
    return value.hasText() and value.codepoint() == cp;
}

// Mouse booleans are independent of the effective reporting fields. Every
// mouse mode write, including a false value, replaces its effective field.
// Repeat a source-compatible selector last so enumeration order cannot choose
// reporting behavior. Refuse states with no selector preserving all booleans.
fn restoreMouse(w: *Writer, t: *const vt.Terminal) SnapshotError!void {
    const event_modes = [_]vt.modes.Mode{ .mouse_event_x10, .mouse_event_normal, .mouse_event_button, .mouse_event_any };
    const event: ?vt.modes.Mode = switch (t.flags.mouse_event) {
        .none => null,
        .x10 => .mouse_event_x10,
        .normal => .mouse_event_normal,
        .button => .mouse_event_button,
        .any => .mouse_event_any,
    };
    try mouseSelector(w, t, &event_modes, event);
    const format_modes = [_]vt.modes.Mode{ .mouse_format_utf8, .mouse_format_sgr, .mouse_format_urxvt, .mouse_format_sgr_pixels };
    const format: ?vt.modes.Mode = switch (t.flags.mouse_format) {
        .x10 => null,
        .utf8 => .mouse_format_utf8,
        .sgr => .mouse_format_sgr,
        .urxvt => .mouse_format_urxvt,
        .sgr_pixels => .mouse_format_sgr_pixels,
    };
    try mouseSelector(w, t, &format_modes, format);
}

fn mouseSelector(w: *Writer, t: *const vt.Terminal, modes: []const vt.modes.Mode, selected: ?vt.modes.Mode) SnapshotError!void {
    if (selected) |mode| {
        if (!t.modes.get(mode)) return error.Unrepresentable;
        try w.print("\x1b[?{d}h", .{vt.modes.ModeTag.fromMode(mode).value});
        return;
    }
    for (modes) |mode| {
        if (!t.modes.get(mode)) {
            try w.print("\x1b[?{d}l", .{vt.modes.ModeTag.fromMode(mode).value});
            return;
        }
    }
    return error.Unrepresentable;
}

// Transient single shifts can survive a screen switch or cursor restore.
// Every painter/REP ASCII prologue designates G2/G3 as ASCII as well as G0,
// so a pending shift is consumed by an identity-mapped print. Restore the
// source designations and pending shift only after all reconstruction prints.
// Restore terminal-global REP independently of repaint traversal. Reuse a
// matching cell when possible, otherwise an erased scratch cell. Never seed
// into occupied content: some states need a nonprinting upstream setter.
fn restoreRep(w: *Writer, t: *const vt.Terminal) SnapshotError!void {
    const cp = t.previous_char orelse return;
    // A temporary seed must be erasable even when the live screen remembers
    // ISO protection. DEC/off permits ordinary ECH; final cursor restoration
    // reselects the source mode. Never select DEC for an originally off screen.
    if (t.screens.active.protected_mode != .off) try w.writeAll("\x1b[1\"q\x1b[0\"q");

    const screen = t.screens.active;
    const width = unicode.table.get(cp).width;
    const saved_anchor = if (screen.saved_cursor) |saved| saved.pending_wrap and saved.x == screen.cursor.x and saved.y == screen.cursor.y and saved.origin == t.modes.get(.origin) else false;
    if (screen.cursor.pending_wrap and width != 2 and !saved_anchor) {
        var p = screen.pages.pin(.{ .active = .{ .x = screen.cursor.x, .y = screen.cursor.y } }).?;
        if (p.rowAndCell().cell.wide == .spacer_tail and p.x > 0) p.x -= 1;
        const value = p.rowAndCell().cell;
        if (value.hasText() and value.codepoint() != cp) return error.Unrepresentable;
    }
    try w.writeAll("\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[?2027l\x1b(B\x1b*B\x1b+B\x0f");
    if (width == 2) {
        if (t.cols < 2) return error.Unrepresentable;
        try w.print("\x1b[1;{d}H\x1b[?7l", .{t.cols});
        try codepoint(w, cp);
        return;
    }
    var scratch: ?struct { pin: vt.PageList.Pin, y: usize } = null;
    for (0..t.rows) |y| {
        const p = screen.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
        for (p.cells(.all), 0..) |*value, x| {
            var at = p;
            at.x = @intCast(x);
            if (value.hasText() and value.codepoint() == cp) {
                if (value.wide == .wide and width == 1 and x <= 1 and y > 0) {
                    const above = p.up(1).?;
                    const above_cells = above.cells(.all);
                    // Reprinting this narrow base over its stored wide glyph
                    // would narrow the preceding spacer head. Seed elsewhere.
                    if (above_cells[above_cells.len - 1].wide == .spacer_head) continue;
                }
                try w.print("\x1b[{d};{d}H\x1b[?7h", .{ y + 1, x + 1 });
                try cell(w, at, value);
                return;
            }
            if (!value.hasText() and value.wide == .narrow and !p.rowAndCell().row.wrap) scratch = .{ .pin = at, .y = y };
        }
    }
    const chosen = scratch orelse return error.Unrepresentable;
    const p = chosen.pin;
    try w.print("\x1b[{d};{d}H\x1b[?7l\x1b]8;;\x1b\\{f}", .{ chosen.y + 1, p.x + 1, effectiveStyle(p, p.rowAndCell().cell).formatterVt() });
    try codepoint(w, cp);
    try w.print("\x1b[{d}G\x1b[X", .{p.x + 1});
}

fn paint(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen) SnapshotError!void {
    // Screen entry copies the inactive screen's pending single shift. The
    // destination has no reconstructed saved cursor yet, so DECRC restores
    // its default charset without printing or changing terminal-global REP.
    // Clear the inherited shift before constructing the source DECSC record;
    // charset designation alone cannot cancel it when the saved shift is null.
    try w.writeAll("\x1b8");
    try w.writeAll("\x1b(B\x1b*B\x1b+B\x0f\x1b[?2027l\x1b[?7h\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[H\x1b[2J\x1b]8;;\x1b\\");
    if (screen.saved_cursor) |saved| {
        // A saved cursor can lie outside margins changed after DECSC. Use
        // temporary full margins so CUP cannot clamp its absolute position;
        // DECSC stores origin but not the margins, restored independently.
        try w.print("\x1b[?6l\x1b[?69l\x1b[r\x1b[?6{c}", .{@as(u8, if (saved.origin) 'h' else 'l')});
        if (saved.pending_wrap and saved.x + 1 < t.cols) {
            try w.print("\x1b[?69h\x1b[1;{d}s", .{saved.x + 1});
        }
        try w.print("\x1b[{d};{d}H", .{ saved.y + 1, saved.x + 1 });
        if (saved.pending_wrap) {
            // Build DECSC before repainting: its pending cursor can refer to
            // a cell that has since become empty or a wide spacer head.
            // A temporary narrow print establishes wrap at the saved margin;
            // the subsequent full grid repaint removes it without touching
            // the saved position/style/charset or pending-wrap bit.
            try w.writeAll("\x1b(B\x1b*B\x1b+B\x0f\x1b[?2027l\x1b[?7h ");
        }
        try w.print("{f}\x1b[{d}\"q", .{ saved.style.formatterVt(), @as(u8, if (saved.protected) 1 else 0) });
        try charset(w, saved.charset);
        try w.writeAll("\x1b7");
    }
    // Discard temporary DECSC construction cells. Consume a saved single
    // shift before painting text, while retaining it in the saved record.
    try w.writeAll("\x1b(B\x1b*B\x1b+B\x0f\x1b[?2027l\x1b[?7h\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[H");
    if (screen.saved_cursor) |saved| {
        if (saved.charset.single_shift != null and t.previous_char != null) try w.writeAll(" \x1b[H");
    }
    try w.writeAll("\x1b[2J\x1b]8;;\x1b\\");
    var wrap = false;
    var skip_first = false;
    for (0..t.rows) |y| {
        if (!wrap) try w.print("\x1b[{d};1H", .{y + 1});
        const p = screen.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
        skip_first = try row(w, p, skip_first);
        wrap = p.rowAndCell().row.wrap;
    }
    // A screen has its own complete Kitty flag stack, including pop state.
    const keys = screen.kitty_keyboard;
    try w.print("\x1b[={d}u", .{keys.flags[0].int()});
    // Rebuild the complete eight-entry ring, including entries behind a
    // wrapped index: future pops can expose any of them.
    for (1..keys.flags.len) |i| try w.print("\x1b[>{d}u", .{keys.flags[i].int()});
    try w.print("\x1b[>{d}u", .{keys.flags[0].int()});
    for (1..@as(usize, keys.idx) + 1) |i| try w.print("\x1b[>{d}u", .{keys.flags[i].int()});
    try cursorShape(w, t, screen);
    try regions(w, t);
    try liveCursor(w, t, screen, false, false);
}

fn regions(w: *Writer, t: *const vt.Terminal) SnapshotError!void {
    try w.print("\x1b[?6l\x1b[?69{c}", .{@as(u8, if (t.modes.get(.enable_left_and_right_margin)) 'h' else 'l')});
    const r = t.scrolling_region;
    if (t.modes.get(.enable_left_and_right_margin)) try w.print("\x1b[{d};{d}s", .{ r.left + 1, r.right + 1 });
    try w.print("\x1b[{d};{d}r", .{ r.top + 1, r.bottom + 1 });
}

fn cursorShape(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen) SnapshotError!void {
    const shape: u8 = switch (screen.cursor.cursor_style) {
        .block => 1,
        .underline => 3,
        .bar => 5,
        .block_hollow => 1,
    };
    try w.print("\x1b[{d} q", .{shape + @as(u8, if (t.modes.get(.cursor_blinking)) 0 else 1)});
}

fn position(w: *Writer, t: *const vt.Terminal, x: u16, y: u16, origin: bool) SnapshotError!void {
    const r = t.scrolling_region;
    if (origin and (y < r.top or y > r.bottom or x < r.left or x > r.right)) {
        // DECRC can restore an absolute position outside later margins; CUP
        // in origin mode clamps it. The saved cursor is the existing absolute
        // anchor and relative movement retains its outside-region position.
        const saved = screenSaved: {
            const saved = t.screens.active.saved_cursor orelse return error.Unrepresentable;
            if (!saved.origin) return error.Unrepresentable;
            break :screenSaved saved;
        };
        if ((y < saved.y and saved.y >= r.top and y < r.top) or
            (y > saved.y and saved.y <= r.bottom and y > r.bottom) or
            (x > saved.x and saved.x <= r.right and x > r.right)) return error.Unrepresentable;
        try w.writeAll("\x1b8");
        if (saved.pending_wrap) {
            // Clear wrap using a vertical move that returns to this exact
            // anchor, including anchors outside the current scroll region.
            if (saved.y == 0 or saved.y == r.top) {
                try w.writeAll("\x1b[A");
            } else if (saved.y + 1 == t.rows or saved.y == r.bottom) {
                try w.writeAll("\x1b[B");
            } else if (saved.y < r.top or saved.y <= r.bottom) {
                try w.writeAll("\x1b[A\x1b[B");
            } else try w.writeAll("\x1b[B\x1b[A");
        }
        if (y != saved.y) try w.print("\x1b[{d}{c}", .{ if (y > saved.y) y - saved.y else saved.y - y, @as(u8, if (y > saved.y) 'B' else 'A') });
        if (x != saved.x) try w.print("\x1b[{d}{c}", .{ if (x > saved.x) x - saved.x else saved.x - x, @as(u8, if (x > saved.x) 'C' else 'D') });
        return;
    }
    try w.print("\x1b[{d};{d}H", .{ @as(i32, y) + 1 - @as(i32, if (origin) r.top else 0), @as(i32, x) + 1 - @as(i32, if (origin and t.modes.get(.enable_left_and_right_margin)) r.left else 0) });
}

fn liveCursor(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen, origin: bool, final_live: bool) SnapshotError!void {
    const cursor = screen.cursor;
    try w.print("\x1b[?6{c}", .{@as(u8, if (origin) 'h' else 'l')});
    try position(w, t, cursor.x, cursor.y, origin);
    if (cursor.pending_wrap) {
        try w.writeAll("\x1b[?7h");
        const saved_anchor = if (screen.saved_cursor) |saved| saved.pending_wrap and saved.x == cursor.x and saved.y == cursor.y and (saved.origin == origin or !final_live) else false;
        if (saved_anchor) {
            // DECRC restores pending wrap without printing or clamping to
            // subsequently changed margins, and preserves the REP source.
            try w.writeAll("\x1b8");
        } else try recreateWrap(w, t, screen, cursor.x, cursor.y, origin);
        try w.print("\x1b[?7{c}", .{@as(u8, if (t.modes.get(.wraparound)) 'h' else 'l')});
    }
    try w.print("\x1b[?2027{c}", .{@as(u8, if (t.modes.get(.grapheme_cluster)) 'h' else 'l')});
    try w.print("{f}\x1b[{d}\"q", .{ cursor.style.formatterVt(), @as(u8, if (cursor.protected) 1 else 0) });
    // EPA/DECSCA-off clear only live protection, retaining the last selected
    // mode. Ordinary ECH protects ISO cells but needs a selective flag for DEC.
    switch (screen.protected_mode) {
        .iso => try w.writeAll("\x1bV"),
        .dec => try w.writeAll("\x1b[1\"q"),
        .off => {},
    }
    if (!cursor.protected) try w.writeAll("\x1bW");
    try cursorLink(w, cursor.hyperlink);
    try charset(w, screen.charset);
}

fn recreateWrap(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen, x: u16, y: u16, origin: bool) SnapshotError!void {
    var p = screen.pages.pin(.{ .active = .{ .x = x, .y = y } }).?;
    if (p.rowAndCell().cell.wide == .spacer_tail and x > 0) p.x -= 1;
    try position(w, t, p.x, y, origin);
    try w.writeAll("\x1b(B\x1b*B\x1b+B\x0f\x1b[?2027l");
    const value = p.rowAndCell().cell;
    const right = if (x > t.scrolling_region.right) t.cols - 1 else t.scrolling_region.right;
    if (!value.hasText() or x != right) return error.Unrepresentable;
    try cell(w, p, value);
}

fn charset(w: *Writer, state: vt.Screen.CharsetState) SnapshotError!void {
    inline for (.{ .{ "G0", '(' }, .{ "G1", ')' }, .{ "G2", '*' }, .{ "G3", '+' } }) |entry| {
        const set = state.charsets.get(@field(vt.CharsetSlot, entry[0]));
        try w.print("\x1b{c}{c}", .{ @as(u8, entry[1]), @as(u8, switch (set) {
            .utf8, .ascii => 'B',
            .british => 'A',
            .dec_special => '0',
        }) });
    }
    try w.writeAll(switch (state.gl) {
        .G0 => "\x0f",
        .G1 => "\x0e",
        .G2 => "\x1bn",
        .G3 => "\x1bo",
    });
    try w.writeAll(switch (state.gr) {
        .G0 => "",
        .G1 => "\x1b~",
        .G2 => "\x1b}",
        .G3 => "\x1b|",
    });
    if (state.single_shift) |slot| try w.writeAll(if (slot == .G2) "\x1bN" else "\x1bO");
}

fn row(w: *Writer, p: vt.PageList.Pin, skip_first: bool) SnapshotError!bool {
    // A narrow base widened by its grapheme may already have been emitted
    // across the preceding spacer head. Reprinting it over a wide cell would
    // narrow that head. The remaining cells start after its continuation.
    if (skip_first) try w.writeAll("\x1b]8;;\x1b\\");
    var last: ?vt.Style = null;
    var last_link: usize = 0;
    var protected: ?bool = null;
    var empty: usize = 0;
    for (p.cells(.all), 0..) |*value, x| {
        if (skip_first and x == 0) continue;
        if (value.wide == .spacer_tail or value.wide == .spacer_head) continue;
        var style = p.style(value);
        switch (value.content_tag) {
            .bg_color_palette => style.bg_color = .palette(value.content.color_palette.data),
            .bg_color_rgb => style.bg_color = .rgb(.{ .r = value.content.color_rgb.r, .g = value.content.color_rgb.g, .b = value.content.color_rgb.b }),
            else => {},
        }
        if (last == null or !std.meta.eql(last.?, style)) {
            try emptyCells(w, &empty);
            try w.print("{f}", .{style.formatterVt()});
            last = style;
        }
        // Empty cells must stay empty: with wrap disabled, a combining mark
        // is ignored over an erased cell but attaches to a printed space.
        // ECH/CUF runs preserve that distinction without one control per cell.
        if (!value.hasText()) {
            if (value.style_id != 0 or value.hyperlink or value.protected) {
                const blank: vt.Style = .{};
                var non_bg = style;
                non_bg.bg_color = blank.bg_color;
                const needs_attributes = !std.meta.eql(non_bg, blank) or value.hyperlink or value.protected;
                const reconstructible_edge = p.rowAndCell().row.wrap and x + 1 == p.cells(.all).len;
                // ECH preserves only background. An independently styled or
                // linked empty interior cell needs a nonprinting cell setter;
                // wrapped edges have the explicit construction below.
                if (needs_attributes and !reconstructible_edge) return error.Unrepresentable;
            }
            empty += 1;
            continue;
        }
        try emptyCells(w, &empty);
        const link_id: usize = if (value.hyperlink) p.node.page().lookupHyperlink(value).? else 0;
        if (link_id != last_link) {
            try cellLink(w, p, value);
            last_link = link_id;
        }
        if (protected == null or protected.? != value.protected) {
            try w.print("\x1b[{d}\"q", .{@as(u8, if (value.protected) 1 else 0)});
            protected = value.protected;
        }
        try text(w, p, value);
    }
    try emptyCells(w, &empty);
    try w.writeAll("\x1b]8;;\x1b\\");
    const values = p.cells(.all);
    const edge = &values[values.len - 1];
    if (!p.rowAndCell().row.wrap) return false;
    if (values.len < 2 and !edge.hasText()) return error.Unrepresentable;
    const next = p.down(1) orelse return error.Unrepresentable;
    const next_continues = next.rowAndCell().row.wrap_continuation;
    if (!edge.hasText() and (edge.wide == .narrow or edge.wide == .spacer_head)) {
        if (edge.wide == .spacer_head and next_continues and next.cells(.all)[0].wide != .wide) return error.Unrepresentable;
        // Construct a spacer head with its own attributes before painting
        // the next row: that row's first wide glyph may have a different style
        // or hyperlink. If the original head had narrowed, overwrite the
        // temporary wide glyph to narrow it without losing its attributes.
        // ECH would discard those empty-cell attributes. Leave the cursor at
        // the next row's start for its ordinary repaint.
        try w.print("\x1b[{d}G", .{values.len});
        try cellLink(w, p, edge);
        try w.print("\x1b[{d}\"q{f}", .{ @as(u8, if (edge.protected) 1 else 0), effectiveStyle(p, edge).formatterVt() });
        const next_base = &next.cells(.all)[0];
        if (edge.wide == .spacer_head and next_continues and next_base.wide == .wide and unicode.table.get(next_base.codepoint()).width == 1) {
            // Build the actual cluster across the head, rather than overwriting
            // a temporary wide glyph with its narrow base on the next row.
            try text(w, next, next_base);
            return true;
        }
        try codepoint(w, '界');
        try w.writeAll("\x1b[2D");
        if (edge.wide == .narrow) try w.writeAll(" \x1b[1D");
        try w.writeAll("\x1b]8;;\x1b\\");
        if (!next_continues) try w.writeAll("\x1b[M");
    } else {
        // Even an entirely erased next row needs a real wrap transition.
        // Its ECH/CUF controls cannot trigger the pending wrap themselves.
        // A temporary narrow space avoids clearing a previous wide head
        // when the next row starts with erased cells.
        try w.writeAll(" \x1b[1D");
        if (!next_continues) try w.writeAll("\x1b[M");
    }
    return false;
}

fn emptyCells(w: *Writer, count: *usize) SnapshotError!void {
    if (count.* == 0) return;
    try w.print("\x1b[{d}X\x1b[{d}C", .{ count.*, count.* });
    count.* = 0;
}

fn cursorLink(w: *Writer, link: ?*@import("terminal/hyperlink.zig").Hyperlink) SnapshotError!void {
    if (link) |l| {
        switch (l.id) {
            .explicit => |id| try w.print("\x1b]8;id={s};{s}\x1b\\", .{ id, l.uri }),
            .implicit => |id| try w.print("\x1b]8;id=infraternal-implicit-{d};{s}\x1b\\", .{ id, l.uri }),
        }
    } else try w.writeAll("\x1b]8;;\x1b\\");
}

fn cell(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) SnapshotError!void {
    try cellLink(w, p, value);
    try w.print("\x1b[{d}\"q", .{@as(u8, if (value.protected) 1 else 0)});
    try w.print("{f}", .{effectiveStyle(p, value).formatterVt()});
    try text(w, p, value);
}

fn cellLink(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) SnapshotError!void {
    const page = p.node.page();
    if (value.hyperlink) {
        const id = page.lookupHyperlink(value).?;
        const link = page.hyperlink_set.get(page.memory, id);
        const uri = link.uri.slice(page.memory);
        switch (link.id) {
            .explicit => |s| try w.print("\x1b]8;id={s};{s}\x1b\\", .{ s.slice(page.memory), uri }),
            // Stable IDs keep a multi-row implicit link one group. Reopening
            // without an ID would create a new link at every repaint row.
            .implicit => |implicit_id| try w.print("\x1b]8;id=infraternal-implicit-{d};{s}\x1b\\", .{ implicit_id, uri }),
        }
    } else try w.writeAll("\x1b]8;;\x1b\\");
}

fn text(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) SnapshotError!void {
    // Charset mapping can turn a wide source glyph into a stored space while
    // retaining width. Ordinary space painting narrows it; this construction
    // needs explicit wide-cell metadata restoration rather than silent loss.
    if (value.wide == .wide and value.codepoint() == ' ') return error.Unrepresentable;

    try codepoint(w, if (value.codepoint() == 0) ' ' else value.codepoint());
    if (p.grapheme(value)) |extra| {
        // A cell boundary must stay a boundary even when adjacent emoji would
        // form a cluster. Print the base with clustering off, and enable it
        // only while appending the cell's already-known grapheme codepoints.
        const widened = value.wide == .wide and unicode.table.get(value.codepoint()).width == 1;
        if (widened) {
            // A variation selector can widen a narrow base after SGR/link
            // changes. Its tail has independent attributes. The borrowed
            // cell belongs to this row; check the tail index before lookup.
            const values = p.cells(.all);
            const x = (@intFromPtr(value) - @intFromPtr(values.ptr)) / @sizeOf(vt.page.Cell);
            if (x + 1 >= values.len) return error.Unrepresentable;
            const tail = &values[x + 1];
            try cellLink(w, p, tail);
            try w.print("\x1b[{d}\"q{f}", .{ @as(u8, if (tail.protected) 1 else 0), effectiveStyle(p, tail).formatterVt() });
        }
        try w.writeAll("\x1b[?2027h");
        for (extra) |cp| try codepoint(w, cp);
        try w.writeAll("\x1b[?2027l");
        if (widened) {
            // Keep row()'s attribute caches consistent for the next cell.
            try cellLink(w, p, value);
            try w.print("\x1b[{d}\"q{f}", .{ @as(u8, if (value.protected) 1 else 0), effectiveStyle(p, value).formatterVt() });
        }
    }
}

fn codepoint(w: *Writer, cp: u21) SnapshotError!void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch return error.Unrepresentable;
    try w.writeAll(buf[0..n]);
}

// Read-only fixture oracle: compare visible state through actual Ghostty cells,
// not bytes from our serializer. Normalise empty cells to displayed spaces.
pub fn compare(a_handle: c.Terminal, b_handle: c.Terminal, strict: bool) callconv(lib.calling_conv) usize {
    const a = c.zigTerminal(a_handle) orelse return 9999999;
    const b = c.zigTerminal(b_handle) orelse return 9999999;
    if (a.rows != b.rows or a.cols != b.cols) return 1000000;
    inline for (.{ .primary, .alternate }) |key| {
        if (strict or key == a.screens.active_key) {
            const sa = a.screens.get(key);
            const sb = b.screens.get(key);
            if ((sa == null) != (sb == null)) return 6000004;
            if (sa != null and sb != null) {
                if (strict and key == .primary) {
                    const ha = sa.?.pages.total_rows - a.rows;
                    const hb = sb.?.pages.total_rows - b.rows;
                    if (hb > ha) return 6500000;
                    // Snapshot intentionally bounds/truncates history. Compare
                    // every retained destination row within the 256-row contract;
                    // older source rows are omitted, not certified equal.
                    const retained = @min(@min(ha, hb), 256);
                    for (0..retained) |y| {
                        const pa = sa.?.pages.pin(.{ .screen = .{ .x = 0, .y = @intCast(ha - retained + y) } }).?;
                        const pb = sb.?.pages.pin(.{ .screen = .{ .x = 0, .y = @intCast(hb - retained + y) } }).?;
                        for (pa.cells(.all), pb.cells(.all)) |*ca, *cb| {
                            if (!cellEqual(pa, pb, ca, cb, true)) return 6500001 + y;
                        }
                        const ra = pa.rowAndCell().row;
                        const rb = pb.rowAndCell().row;
                        if (ra.wrap != rb.wrap or ra.wrap_continuation != rb.wrap_continuation or ra.semantic_prompt != rb.semantic_prompt) return 6500001 + y;
                    }
                }
                for (0..a.rows) |y| {
                    const pa = sa.?.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
                    const pb = sb.?.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
                    const cells_a = pa.cells(.all);
                    const cells_b = pb.cells(.all);
                    for (cells_a, cells_b, 0..) |*ca, *cb, x| {
                        if (!cellEqual(pa, pb, ca, cb, strict)) return 1 + y * a.cols + x;
                    }
                    if (strict and pa.rowAndCell().row.semantic_prompt != pb.rowAndCell().row.semantic_prompt) return 6200000 + y;
                    if (pa.rowAndCell().row.wrap != pb.rowAndCell().row.wrap) return 2000000 + y;
                    if (strict and pa.rowAndCell().row.wrap_continuation != pb.rowAndCell().row.wrap_continuation) return 2100000 + y;
                }
                if (sa.?.cursor.x != sb.?.cursor.x or sa.?.cursor.y != sb.?.cursor.y) return 3000000;
                if (sa.?.cursor.pending_wrap != sb.?.cursor.pending_wrap) return 3000001;
                if (!std.meta.eql(sa.?.cursor.style, sb.?.cursor.style)) return 3000002;

                if (strict) {
                    // `seen` summarizes prompt history that may fall outside
                    // the bounded export tail; click behavior and live cursor
                    // semantics remain observable and must still compare.
                    if (!std.meta.eql(sa.?.semantic_prompt.click, sb.?.semantic_prompt.click) or sa.?.cursor.semantic_content != sb.?.cursor.semantic_content or sa.?.cursor.semantic_content_clear_eol != sb.?.cursor.semantic_content_clear_eol) return 6200001;
                    if (sa.?.protected_mode != sb.?.protected_mode or sa.?.cursor.protected != sb.?.cursor.protected) return 6300000;
                    if (!charsetEqual(sa.?.charset, sb.?.charset)) return 6400000;
                    if (!cursorLinkEqual(sa.?.cursor.hyperlink, sb.?.cursor.hyperlink)) return 6400001;
                    if (!std.meta.eql(sa.?.kitty_keyboard, sb.?.kitty_keyboard)) return 6400002;
                    if (!savedEqual(sa.?.saved_cursor, sb.?.saved_cursor)) return 6000002;
                    if (sa.?.cursor.cursor_style != sb.?.cursor.cursor_style) return 6000003;
                }
            }
        }
    }
    if (a.screens.active_key != b.screens.active_key) return 3000003;
    inline for (@typeInfo(vt.modes.Mode).@"enum".field_values) |value| {
        const mode: vt.modes.Mode = @enumFromInt(value);
        const tag = vt.modes.ModeTag.fromMode(mode);
        if (!(tag.value == 47 or tag.value == 1047 or tag.value == 1049 or tag.value == 1048 or tag.value == 2026)) {
            if (a.modes.get(mode) != b.modes.get(mode)) return 4000000 + @as(usize, tag.value);
        }
    }
    if (strict) {
        inline for (.{ "foreground", "background", "cursor" }) |name| {
            if (!std.meta.eql(@field(a.colors, name), @field(b.colors, name))) return 6400003;
        }
        if (!std.meta.eql(a.colors.palette.mask, b.colors.palette.mask)) return 6400004;
        if (a.flags.mouse_event != b.flags.mouse_event) return 6500000;
        if (a.flags.mouse_format != b.flags.mouse_format) return 6500001;
        if (a.flags.shell_redraws_prompt != b.flags.shell_redraws_prompt) return 6200002;
        if (!std.meta.eql(a.modes.saved, b.modes.saved)) return 6100000;
        if (a.previous_char != b.previous_char) return 6000000;
        for (0..a.cols) |x| {
            if (a.tabstops.get(@intCast(x)) != b.tabstops.get(@intCast(x))) return 6000001;
        }
    }
    if (!std.meta.eql(a.colors.palette.current, b.colors.palette.current)) return 5000000;
    if (!std.meta.eql(a.scrolling_region, b.scrolling_region)) return 5000001;
    if (a.screens.active.kitty_keyboard.current().int() != b.screens.active.kitty_keyboard.current().int()) return 5000002;
    return 0;
}
fn effectiveStyle(p: vt.PageList.Pin, value: *const vt.page.Cell) vt.Style {
    var s = p.style(value);
    switch (value.content_tag) {
        .bg_color_palette => s.bg_color = .palette(value.content.color_palette.data),
        .bg_color_rgb => s.bg_color = .rgb(.{ .r = value.content.color_rgb.r, .g = value.content.color_rgb.g, .b = value.content.color_rgb.b }),
        else => {},
    }
    return s;
}
fn cellUri(p: vt.PageList.Pin, value: *const vt.page.Cell) []const u8 {
    if (!value.hyperlink) return "";
    const page = p.node.page();
    const id = page.lookupHyperlink(value).?;
    return page.hyperlink_set.get(page.memory, id).uri.slice(page.memory);
}

// Explicit IDs are kept verbatim. Implicit IDs are represented by stable VT
// identifiers; comparing their group keys verifies row/cursor link continuity.
fn linkKey(p: vt.PageList.Pin, value: *const vt.page.Cell, buf: *[64]u8) []const u8 {
    if (!value.hyperlink) return "";
    const page = p.node.page();
    const id = page.lookupHyperlink(value).?;
    const link = page.hyperlink_set.get(page.memory, id);
    return switch (link.id) {
        .explicit => |v| v.slice(page.memory),
        .implicit => |v| std.fmt.bufPrint(buf, "infraternal-implicit-{d}", .{v}) catch unreachable,
    };
}

// UTF-8 and ASCII designations use the same printable mapping in Ghostty.
// Replay emits the standard ASCII designation, so compare behavior rather
// than the internal default tag when checking saved cursor state.
fn savedEqual(a: ?vt.Screen.SavedCursor, b: ?vt.Screen.SavedCursor) bool {
    var aa = a orelse return b == null;
    var bb = b orelse return false;
    inline for (.{ vt.CharsetSlot.G0, vt.CharsetSlot.G1, vt.CharsetSlot.G2, vt.CharsetSlot.G3 }) |slot| {
        if (aa.charset.charsets.get(slot) == .utf8) aa.charset.charsets.set(slot, .ascii);
        if (bb.charset.charsets.get(slot) == .utf8) bb.charset.charsets.set(slot, .ascii);
    }
    return std.meta.eql(aa, bb);
}

// Default UTF-8 and explicit ASCII share the same mapping in this pinned
// engine. Every other live/single-shift charset field remains significant.
fn charsetEqual(a: anytype, b: @TypeOf(a)) bool {
    var aa = a;
    var bb = b;
    inline for (.{ vt.CharsetSlot.G0, vt.CharsetSlot.G1, vt.CharsetSlot.G2, vt.CharsetSlot.G3 }) |slot| {
        if (aa.charsets.get(slot) == .utf8) aa.charsets.set(slot, .ascii);
        if (bb.charsets.get(slot) == .utf8) bb.charsets.set(slot, .ascii);
    }
    return std.meta.eql(aa, bb);
}

fn cursorLinkEqual(a: ?*@import("terminal/hyperlink.zig").Hyperlink, b: ?*@import("terminal/hyperlink.zig").Hyperlink) bool {
    const aa = a orelse return b == null;
    const bb = b orelse return false;
    if (!std.mem.eql(u8, aa.uri, bb.uri)) return false;
    var a_buf: [64]u8 = undefined;
    var b_buf: [64]u8 = undefined;
    const a_key = switch (aa.id) {
        .explicit => |v| v,
        .implicit => |v| std.fmt.bufPrint(&a_buf, "infraternal-implicit-{d}", .{v}) catch unreachable,
    };
    const b_key = switch (bb.id) {
        .explicit => |v| v,
        .implicit => |v| std.fmt.bufPrint(&b_buf, "infraternal-implicit-{d}", .{v}) catch unreachable,
    };
    return std.mem.eql(u8, a_key, b_key);
}

/// Best-effort visible repaint for negotiated approximate recovery. It omits
/// semantic/history/hidden state and may clip cells, but never emits half a VT
/// operation or half a UTF-8 scalar. The faithful serializer is unchanged.
pub fn approximate(handle: c.Terminal, buf: [*]u8, len: usize) callconv(lib.calling_conv) usize {
    const t = c.zigTerminal(handle) orelse return 0;
    if (len < 256) return 0;
    var w = Writer.fixed(buf[0 .. len - 128]);
    w.writeAll("\x1bc\x1b[?7l\x1b[?6l\x1b[?2027l\x1b(B\x0f") catch return 0;
    restoreColors(&w, t) catch return 0;
    if (t.screens.active_key == .alternate) w.writeAll("\x1b[?47h") catch return 0;
    const screen = t.screens.active;
    outer: for (0..t.rows) |y| {
        const p = screen.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
        for (p.cells(.all), 0..) |*value, x| {
            if (value.wide == .spacer_tail or value.wide == .spacer_head) continue;
            const style = effectiveStyle(p, value);
            if (!value.hasText() and style.bg_color.tag == .none) continue;
            const boundary = w.end;
            // Roll back a whole cell if its bounded operation cannot fit. No
            // borrowed engine data is modified by failure or clipping.
            approximateCell(&w, p, value, style, x, y) catch {
                w.end = boundary;
                break :outer;
            };
        }
    }
    // Reserve footer space independently of clipping, and leave a parser in
    // ground state at the visible cursor before subsequent raw output resumes.
    var footer = Writer.fixed(buf[w.end..len]);
    footer.print("\x1b[0m\x1b[?7h\x1b[?25{c}\x1b[{d};{d}H", .{ @as(u8, if (t.modes.get(.cursor_visible)) 'h' else 'l'), screen.cursor.y + 1, screen.cursor.x + 1 }) catch return 0;
    return w.end + footer.end;
}

fn approximateCell(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell, style: vt.Style, x: usize, y: usize) SnapshotError!void {
    try w.print("\x1b[{d};{d}H{f}", .{ y + 1, x + 1, style.formatterVt() });
    if (value.hasText()) {
        try codepoint(w, value.codepoint());
        if (p.grapheme(value)) |extra| {
            try w.writeAll("\x1b[?2027h");
            for (extra) |cp| try codepoint(w, cp);
            try w.writeAll("\x1b[?2027l");
        }
    } else try w.writeAll(" ");
}

// One field inventory serves active cells and the retained-history oracle, so
// adding a metadata check cannot accidentally leave archived cells unchecked.
fn cellEqual(pa: vt.PageList.Pin, pb: vt.PageList.Pin, ca: *const vt.page.Cell, cb: *const vt.page.Cell, strict: bool) bool {
    const cpa = if (ca.codepoint() == 0) ' ' else ca.codepoint();
    const cpb = if (cb.codepoint() == 0) ' ' else cb.codepoint();
    if ((strict and ca.semantic_content != cb.semantic_content) or ca.hasText() != cb.hasText() or cpa != cpb or ca.wide != cb.wide or ca.protected != cb.protected or !std.meta.eql(effectiveStyle(pa, ca), effectiveStyle(pb, cb))) return false;
    if (!std.mem.eql(u21, pa.grapheme(ca) orelse &.{}, pb.grapheme(cb) orelse &.{})) return false;
    if (!std.mem.eql(u8, cellUri(pa, ca), cellUri(pb, cb))) return false;
    var id_a: [64]u8 = undefined;
    var id_b: [64]u8 = undefined;
    return std.mem.eql(u8, linkKey(pa, ca, &id_a), linkKey(pb, cb, &id_b));
}

// RIS preserves palette/dynamic overrides. Clear the existing viewer first;
// emitting only source overrides would silently inherit stale viewer colors.
fn restoreColors(w: *Writer, t: *const vt.Terminal) SnapshotError!void {
    try w.writeAll("\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\");
    for (t.colors.palette.current, 0..) |rgb, i| {
        if (t.colors.palette.mask.isSet(i)) try w.print("\x1b]4;{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ i, rgb.r, rgb.g, rgb.b });
    }
    inline for (.{ .{ "foreground", 10 }, .{ "background", 11 }, .{ "cursor", 12 } }) |entry| {
        if (@field(t.colors, entry[0]).override) |rgb| try w.print("\x1b]{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ entry[1], rgb.r, rgb.g, rgb.b });
    }
}
