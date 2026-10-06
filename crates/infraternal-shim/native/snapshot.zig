//! Snapshot adapter over pinned libghostty-vt's Zig screen/cell API [13][94].
//! The C API does not yet expose inactive screens, saved cursors, tabs or
//! charsets. This read-only adapter accesses those fields without a mirror VT.
const std = @import("std");
const c = @import("terminal/c/terminal.zig");
const vt = @import("terminal/main.zig");
const lib = @import("terminal/lib.zig");
const Writer = std.Io.Writer;

pub fn snapshot(handle: c.Terminal, buf: [*]u8, len: usize, tail: usize) callconv(lib.calling_conv) usize {
    const t = c.zigTerminal(handle) orelse return 0;
    var w = Writer.fixed(buf[0..len]);
    serialize(t, &w, tail) catch return 0;
    return w.end;
}

fn serialize(t: *const vt.Terminal, w: *Writer, tail: usize) Writer.Error!void {
    try w.writeAll("\x1bc\x1b[?6l\x1b[r\x1b[?7h\x1b[?2027l");
    for (t.colors.palette.current, 0..) |rgb, i| {
        if (t.colors.palette.mask.isSet(i)) try w.print("\x1b]4;{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ i, rgb.r, rgb.g, rgb.b });
    }
    inline for (.{ .{ "foreground", 10 }, .{ "background", 11 }, .{ "cursor", 12 } }) |entry| {
        if (@field(t.colors, entry[0]).override) |rgb| try w.print("\x1b]{d};rgb:{x:0>2}/{x:0>2}/{x:0>2}\x1b\\", .{ entry[1], rgb.r, rgb.g, rgb.b });
    }
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
        // Each lookup resolves one row, never one cell through full history.
        for (history - count..history) |y| {
            const p = primary.pages.pin(.{ .screen = .{ .x = 0, .y = @intCast(y) } }).?;
            try row(w, p);
            if (!p.rowAndCell().row.wrap) try w.writeAll("\x1b[0m\r\n");
        }
        try w.print("\x1b[{d}S", .{t.rows});
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
    inline for (std.meta.fields(vt.modes.Mode)) |field| {
        const mode: vt.modes.Mode = @enumFromInt(field.value);
        const tag = vt.modes.ModeTag.fromMode(mode);
        if (!(tag.value == 47 or tag.value == 1047 or tag.value == 1049 or tag.value == 1048 or tag.value == 6 or tag.value == 7 or tag.value == 69 or tag.value == 2026)) {
            try w.print("\x1b[{s}{d}{c}", .{ if (tag.ansi) "" else "?", tag.value, @as(u8, if (t.modes.get(mode)) 'h' else 'l') });
        }
    }
    try w.writeAll("\x1b[3g");
    for (0..t.cols) |x| if (t.tabstops.get(@intCast(x))) {
        try w.print("\x1b[1;{d}H\x1bH", .{x + 1});
    };
    try regions(w, t);
    try w.print("\x1b[?7{c}", .{@as(u8, if (t.modes.get(.wraparound)) 'h' else 'l')});
    const screen = t.screens.active;
    try cursorShape(w, t, screen);
    try liveCursor(w, t, screen, t.modes.get(.origin));
}

fn paint(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen) Writer.Error!void {
    try w.writeAll("\x1b(B\x0f\x1b[?2027l\x1b[?7h\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[H\x1b[2J\x1b]8;;\x1b\\");
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
            try w.writeAll("\x1b(B\x0f\x1b[?2027l\x1b[?7h ");
        }
        try w.print("{f}\x1b[{d}\"q", .{ saved.style.formatterVt(), @as(u8, if (saved.protected) 1 else 0) });
        try charset(w, saved.charset);
        try w.writeAll("\x1b7");
    }
    // Discard temporary DECSC construction cells. Consume a saved single
    // shift before painting text, while retaining it in the saved record.
    try w.writeAll("\x1b(B\x0f\x1b[?2027l\x1b[?7h\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[H");
    if (screen.saved_cursor) |saved| {
        if (saved.charset.single_shift != null and t.previous_char != null) try w.writeAll(" \x1b[H");
    }
    try w.writeAll("\x1b[2J\x1b]8;;\x1b\\");
    var wrap = false;
    for (0..t.rows) |y| {
        if (!wrap) try w.print("\x1b[{d};1H", .{y + 1});
        const p = screen.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
        try row(w, p);
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
    try liveCursor(w, t, screen, false);
}

fn regions(w: *Writer, t: *const vt.Terminal) Writer.Error!void {
    try w.print("\x1b[?6l\x1b[?69{c}", .{@as(u8, if (t.modes.get(.enable_left_and_right_margin)) 'h' else 'l')});
    const r = t.scrolling_region;
    if (t.modes.get(.enable_left_and_right_margin)) try w.print("\x1b[{d};{d}s", .{ r.left + 1, r.right + 1 });
    try w.print("\x1b[{d};{d}r", .{ r.top + 1, r.bottom + 1 });
}

fn cursorShape(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen) Writer.Error!void {
    const shape: u8 = switch (screen.cursor.cursor_style) {
        .block => 1,
        .underline => 3,
        .bar => 5,
        .block_hollow => 1,
    };
    try w.print("\x1b[{d} q", .{shape + @as(u8, if (t.modes.get(.cursor_blinking)) 0 else 1)});
}

fn position(w: *Writer, t: *const vt.Terminal, x: u16, y: u16, origin: bool) Writer.Error!void {
    const r = t.scrolling_region;
    if (origin and (y < r.top or y > r.bottom or x < r.left or x > r.right)) {
        // DECRC can restore an absolute position outside later margins; CUP
        // in origin mode clamps it. The saved cursor is the existing absolute
        // anchor and relative movement retains its outside-region position.
        const saved = screenSaved: {
            const saved = t.screens.active.saved_cursor orelse return error.WriteFailed;
            if (!saved.origin) return error.WriteFailed;
            break :screenSaved saved;
        };
        try w.writeAll("\x1b8");
        if (y != saved.y) try w.print("\x1b[{d}{c}", .{ if (y > saved.y) y - saved.y else saved.y - y, @as(u8, if (y > saved.y) 'B' else 'A') });
        if (x != saved.x) try w.print("\x1b[{d}{c}", .{ if (x > saved.x) x - saved.x else saved.x - x, @as(u8, if (x > saved.x) 'C' else 'D') });
        return;
    }
    try w.print("\x1b[{d};{d}H", .{ @as(i32, y) + 1 - @as(i32, if (origin) r.top else 0), @as(i32, x) + 1 - @as(i32, if (origin and t.modes.get(.enable_left_and_right_margin)) r.left else 0) });
}

fn liveCursor(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen, origin: bool) Writer.Error!void {
    const cursor = screen.cursor;
    try w.print("\x1b[?6{c}", .{@as(u8, if (origin) 'h' else 'l')});
    try position(w, t, cursor.x, cursor.y, origin);
    if (cursor.pending_wrap) {
        try w.writeAll("\x1b[?7h");
        try recreateWrap(w, t, screen, cursor.x, cursor.y, origin);
        try w.print("\x1b[?7{c}", .{@as(u8, if (t.modes.get(.wraparound)) 'h' else 'l')});
    }
    try w.print("\x1b[?2027{c}", .{@as(u8, if (t.modes.get(.grapheme_cluster)) 'h' else 'l')});
    try w.print("{f}\x1b[{d}\"q", .{ cursor.style.formatterVt(), @as(u8, if (cursor.protected) 1 else 0) });
    try cursorLink(w, cursor.hyperlink);
    try charset(w, screen.charset);
}

fn recreateWrap(w: *Writer, t: *const vt.Terminal, screen: *const vt.Screen, x: u16, y: u16, origin: bool) Writer.Error!void {
    var p = screen.pages.pin(.{ .active = .{ .x = x, .y = y } }).?;
    if (p.rowAndCell().cell.wide == .spacer_tail and x > 0) p.x -= 1;
    try position(w, t, p.x, y, origin);
    try w.writeAll("\x1b(B\x0f\x1b[?2027l");
    try cell(w, p, p.rowAndCell().cell);
}

fn charset(w: *Writer, state: vt.Screen.CharsetState) Writer.Error!void {
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

fn row(w: *Writer, p: vt.PageList.Pin) Writer.Error!void {
    var last: ?vt.Style = null;
    var last_link: usize = 0;
    var protected: ?bool = null;
    var empty: usize = 0;
    for (p.cells(.all)) |*value| {
        if (value.wide == .spacer_tail or value.wide == .spacer_head) continue;
        var style = p.style(value);
        switch (value.content_tag) {
            .bg_color_palette => style.bg_color = .{ .palette = value.content.color_palette },
            .bg_color_rgb => style.bg_color = .{ .rgb = .{ .r = value.content.color_rgb.r, .g = value.content.color_rgb.g, .b = value.content.color_rgb.b } },
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
    if (!p.rowAndCell().row.wrap) return;
    const next = p.down(1) orelse return error.WriteFailed;
    const next_continues = next.rowAndCell().row.wrap_continuation;
    if (!edge.hasText() and (edge.wide == .narrow or edge.wide == .spacer_head)) {
        if (edge.wide == .spacer_head and next_continues and next.cells(.all)[0].wide != .wide) return error.WriteFailed;
        // Construct a spacer head with its own attributes before painting
        // the next row: that row's first wide glyph may have a different style
        // or hyperlink. If the original head had narrowed, overwrite the
        // temporary wide glyph to narrow it without losing its attributes.
        // ECH would discard those empty-cell attributes. Leave the cursor at
        // the next row's start for its ordinary repaint.
        try w.print("\x1b[{d}G", .{values.len});
        try cellLink(w, p, edge);
        try w.print("\x1b[{d}\"q{f}", .{ @as(u8, if (edge.protected) 1 else 0), effectiveStyle(p, edge).formatterVt() });
        try codepoint(w, '界');
        try w.writeAll("\x1b[2D");
        if (edge.wide == .narrow) try w.writeAll(" \x1b[1D");
        try w.writeAll("\x1b]8;;\x1b\\");
        if (!next_continues) try w.writeAll("\x1b[M");
    } else if (!next_continues) {
        // Region scrolling can retain this row's wrap/head while replacing
        // its following row. Remove the temporary following row before its
        // repaint so no wide-cell erase can clear the retained head.
        try codepoint(w, '界');
        try w.writeAll("\x1b[2D\x1b[M");
    }
}

fn emptyCells(w: *Writer, count: *usize) Writer.Error!void {
    if (count.* == 0) return;
    try w.print("\x1b[{d}X\x1b[{d}C", .{ count.*, count.* });
    count.* = 0;
}

fn cursorLink(w: *Writer, link: ?*@import("terminal/hyperlink.zig").Hyperlink) Writer.Error!void {
    if (link) |l| {
        switch (l.id) {
            .explicit => |id| try w.print("\x1b]8;id={s};{s}\x1b\\", .{ id, l.uri }),
            .implicit => |id| try w.print("\x1b]8;id=infraternal-implicit-{d};{s}\x1b\\", .{ id, l.uri }),
        }
    } else try w.writeAll("\x1b]8;;\x1b\\");
}

fn cell(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) Writer.Error!void {
    try cellLink(w, p, value);
    try w.print("\x1b[{d}\"q", .{@as(u8, if (value.protected) 1 else 0)});
    try w.print("{f}", .{effectiveStyle(p, value).formatterVt()});
    try text(w, p, value);
}

fn cellLink(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) Writer.Error!void {
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

fn text(w: *Writer, p: vt.PageList.Pin, value: *const vt.page.Cell) Writer.Error!void {
    try codepoint(w, if (value.codepoint() == 0) ' ' else value.codepoint());
    if (p.grapheme(value)) |extra| {
        // A cell boundary must stay a boundary even when adjacent emoji would
        // form a cluster. Print the base with clustering off, and enable it
        // only while appending the cell's already-known grapheme codepoints.
        try w.writeAll("\x1b[?2027h");
        for (extra) |cp| try codepoint(w, cp);
        try w.writeAll("\x1b[?2027l");
    }
}

fn codepoint(w: *Writer, cp: u21) Writer.Error!void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch return error.WriteFailed;
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
                for (0..a.rows) |y| {
                    const pa = sa.?.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
                    const pb = sb.?.pages.pin(.{ .active = .{ .x = 0, .y = @intCast(y) } }).?;
                    const cells_a = pa.cells(.all);
                    const cells_b = pb.cells(.all);
                    for (cells_a, cells_b, 0..) |*ca, *cb, x| {
                        const cpa = if (ca.codepoint() == 0) ' ' else ca.codepoint();
                        const cpb = if (cb.codepoint() == 0) ' ' else cb.codepoint();
                        if (ca.hasText() != cb.hasText() or cpa != cpb or ca.wide != cb.wide or ca.protected != cb.protected or !std.meta.eql(effectiveStyle(pa, ca), effectiveStyle(pb, cb))) {
                            return 1 + y * a.cols + x;
                        }
                        const ga = pa.grapheme(ca) orelse &.{};
                        const gb = pb.grapheme(cb) orelse &.{};
                        if (!std.mem.eql(u21, ga, gb)) return 1 + y * a.cols + x;
                        if (!std.mem.eql(u8, cellUri(pa, ca), cellUri(pb, cb))) return 1 + y * a.cols + x;
                        var id_a: [64]u8 = undefined;
                        var id_b: [64]u8 = undefined;
                        if (!std.mem.eql(u8, linkKey(pa, ca, &id_a), linkKey(pb, cb, &id_b))) return 1 + y * a.cols + x;
                    }
                    if (pa.rowAndCell().row.wrap != pb.rowAndCell().row.wrap) return 2000000 + y;
                    if (strict and pa.rowAndCell().row.wrap_continuation != pb.rowAndCell().row.wrap_continuation) return 2100000 + y;
                }
                if (sa.?.cursor.x != sb.?.cursor.x or sa.?.cursor.y != sb.?.cursor.y) return 3000000;
                if (sa.?.cursor.pending_wrap != sb.?.cursor.pending_wrap) return 3000001;
                if (!std.meta.eql(sa.?.cursor.style, sb.?.cursor.style)) return 3000002;

                if (strict) {
                    if (!savedEqual(sa.?.saved_cursor, sb.?.saved_cursor)) return 6000002;
                    if (sa.?.cursor.cursor_style != sb.?.cursor.cursor_style) return 6000003;
                }
            }
        }
    }
    if (a.screens.active_key != b.screens.active_key) return 3000003;
    inline for (std.meta.fields(vt.modes.Mode)) |field| {
        const mode: vt.modes.Mode = @enumFromInt(field.value);
        const tag = vt.modes.ModeTag.fromMode(mode);
        if (!(tag.value == 47 or tag.value == 1047 or tag.value == 1049 or tag.value == 1048 or tag.value == 2026)) {
            if (a.modes.get(mode) != b.modes.get(mode)) return 4000000 + @as(usize, tag.value);
        }
    }
    if (strict) {
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
        .bg_color_palette => s.bg_color = .{ .palette = value.content.color_palette },
        .bg_color_rgb => s.bg_color = .{ .rgb = .{ .r = value.content.color_rgb.r, .g = value.content.color_rgb.g, .b = value.content.color_rgb.b } },
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
