//! Browser-engine C API: the terminal handle, bulk viewport/scrollback reads and
//! the query-reply buffer that the ghostty-web TypeScript binding drives.
//!
//! This file is ours, not upstream's. It replaces the `ghostty_terminal_*` and
//! `ghostty_render_state_*` entry points that older ghostty-web patched into the core
//! (the core now has an official terminal C API with the same names and another
//! shape), so every export here is prefixed `ghostty_web_`. The browser build never
//! needs the official API: the TypeScript side makes ONE call per frame for the
//! whole viewport (`ghostty_web_render_state_get_viewport`) instead of one per cell.
//!
//! State changes come from the core's own terminal stream handler. Only the four
//! replies the page has always answered itself (DSR 5 and 6, DA1 and DA2) are produced
//! here and queued for `readResponse`; every other query stays unanswered, because the
//! server-side engine answers the rest and a second answer would reach the program
//! twice (D307).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const lib = @import("../lib.zig");
const Terminal = @import("../Terminal.zig");
const stream = @import("../stream.zig");
const Action = stream.Action;
const terminal_stream = @import("../stream_terminal.zig");
const render = @import("../render.zig");
const RenderState = render.RenderState;
const color = @import("../color.zig");
const modespkg = @import("../modes.zig");
const stylepkg = @import("../style.zig");
const Style = stylepkg.Style;

const log = std.log.scoped(.terminal_web);

/// Stream handler: the core's state-only handler, plus our four canned replies.
const ResponseHandler = struct {
    /// Applies every state change; its effects stay `.readonly`, so it never replies.
    inner: terminal_stream.Handler,
    alloc: Allocator,
    terminal: *Terminal,
    response_buffer: *std.ArrayList(u8),

    pub fn deinit(self: *ResponseHandler) void {
        self.inner.deinit();
    }

    /// Keeps the core's fast path for runs of printable ASCII.
    pub fn vtPrintAscii(self: *ResponseHandler, bytes: []const u8) void {
        self.inner.vtPrintAscii(bytes);
    }

    /// Stream entry point: answer the four queries we own, hand the rest to the core.
    pub fn vt(
        self: *ResponseHandler,
        comptime action: Action.Tag,
        value: Action.Value(action),
    ) void {
        switch (action) {
            .device_status => self.handleDeviceStatus(value.request),
            .device_attributes => self.handleDeviceAttributes(value),
            else => self.inner.vt(action, value),
        }
    }

    fn reply(self: *ResponseHandler, bytes: []const u8) void {
        self.response_buffer.appendSlice(self.alloc, bytes) catch |err| {
            log.warn("dropping a terminal reply err={}", .{err});
        };
    }

    fn handleDeviceStatus(self: *ResponseHandler, req: @import("../device_status.zig").Request) void {
        switch (req) {
            // DSR 5 - operating status: always "OK".
            .operating_status => self.reply("\x1B[0n"),
            // DSR 6 - cursor position report.
            .cursor_position => {
                const cursor = self.terminal.screens.active.cursor;
                const origin = self.terminal.modes.get(.origin);
                const x = if (origin) cursor.x -| self.terminal.scrolling_region.left else cursor.x;
                const y = if (origin) cursor.y -| self.terminal.scrolling_region.top else cursor.y;
                var buf: [32]u8 = undefined;
                const resp = std.fmt.bufPrint(&buf, "\x1B[{};{}R", .{ y + 1, x + 1 }) catch return;
                self.reply(resp);
            },
            else => {},
        }
    }

    fn handleDeviceAttributes(self: *ResponseHandler, req: @import("../device_attributes.zig").Req) void {
        switch (req) {
            // DA1: VT220 conformance with colour text.
            .primary => self.reply("\x1B[?62;22c"),
            // DA2: firmware 1.10.0.
            .secondary => self.reply("\x1B[>1;10;0c"),
            .tertiary => {},
        }
    }
};

/// The stream type that feeds our handler.
const ResponseStream = stream.Stream(ResponseHandler);

/// Owns the terminal, its stream, the render state and the reply queue. Heap-allocated
/// so the stream handler's pointers into it stay valid.
const TerminalWrapper = struct {
    alloc: Allocator,
    io: lib.TinyIo,
    terminal: Terminal,
    stream: ResponseStream,
    render_state: RenderState,
    /// Replies to DSR and DA queries, waiting for `readResponse`.
    response_buffer: std.ArrayList(u8),
    /// Tracks the alternate screen so a switch can force a full redraw.
    last_screen_is_alternate: bool = false,
};

/// C-compatible cell structure (16 bytes)
pub const GhosttyCell = extern struct {
    codepoint: u32,
    fg_r: u8,
    fg_g: u8,
    fg_b: u8,
    bg_r: u8,
    bg_g: u8,
    bg_b: u8,
    flags: u8,
    width: u8,
    hyperlink_id: u16,
    grapheme_len: u8 = 0, // Number of extra codepoints beyond first
    _pad: u8 = 0,
};

/// Dirty state
pub const GhosttyDirty = enum(u8) {
    none = 0,
    partial = 1,
    full = 2,
};

/// C-compatible terminal configuration
pub const GhosttyTerminalConfig = extern struct {
    scrollback_limit: u32,
    fg_color: u32,
    bg_color: u32,
    cursor_color: u32,
    palette: [16]u32,
};

// ============================================================================
// Lifecycle
// ============================================================================

pub fn new(cols: c_int, rows: c_int) callconv(.c) ?*anyopaque {
    return newWithConfig(cols, rows, null);
}

pub fn newWithConfig(
    cols: c_int,
    rows: c_int,
    config_: ?*const GhosttyTerminalConfig,
) callconv(.c) ?*anyopaque {
    if (cols <= 0 or rows <= 0) return null;
    const alloc = if (builtin.target.cpu.arch.isWasm())
        std.heap.wasm_allocator
    else
        std.heap.c_allocator;

    const wrapper = alloc.create(TerminalWrapper) catch return null;
    wrapper.* = .{
        .alloc = alloc,
        .io = .init,
        .terminal = undefined,
        .stream = undefined,
        .render_state = RenderState.empty,
        .response_buffer = .empty,
    };

    // Scrollback is a byte budget; zero in the config means unlimited.
    const scrollback_limit: ?usize = if (config_) |cfg|
        if (cfg.scrollback_limit == 0) null else cfg.scrollback_limit
    else
        10_000;

    // Setup terminal colors (0 = keep the default).
    var colors = Terminal.Colors.default;
    if (config_) |cfg| {
        if (cfg.fg_color != 0) colors.foreground = color.DynamicRGB.init(unpackRgb(cfg.fg_color));
        if (cfg.bg_color != 0) colors.background = color.DynamicRGB.init(unpackRgb(cfg.bg_color));
        if (cfg.cursor_color != 0) colors.cursor = color.DynamicRGB.init(unpackRgb(cfg.cursor_color));
    }

    wrapper.terminal = Terminal.init(wrapper.io.io(), alloc, .{
        .cols = @intCast(cols),
        .rows = @intCast(rows),
        .max_scrollback_bytes = scrollback_limit,
        .colors = colors,
    }) catch {
        alloc.destroy(wrapper);
        return null;
    };

    // The palette from the config is the terminal's DEFAULT palette, not a set of
    // program changes: a reset (RIS, DECSTR, OSC 104) must return to the page's theme,
    // never to the core's built-in colours. 0 means "keep the built-in entry".
    if (config_) |cfg| {
        var theme_palette: color.Palette = wrapper.terminal.colors.palette.original.*;
        for (cfg.palette, 0..) |palette_color, i| {
            if (palette_color != 0) theme_palette[i] = unpackRgb(palette_color);
        }
        wrapper.terminal.colors.palette.changeDefault(alloc, theme_palette) catch {
            wrapper.terminal.deinit(alloc);
            alloc.destroy(wrapper);
            return null;
        };
    }

    // The inner handler keeps the core's "readonly" effects: no query is answered by it.
    wrapper.stream = ResponseStream.init(.{
        .allocator = alloc,
        .handler = .{
            .inner = wrapper.terminal.vtHandler(),
            .alloc = alloc,
            .terminal = &wrapper.terminal,
            .response_buffer = &wrapper.response_buffer,
        },
    });

    // NOTE: linefeed mode must be FALSE to match native terminal behavior
    // When true, LF does automatic CR which breaks apps like nvim
    wrapper.terminal.modes.set(.linefeed, false);

    // Enable grapheme clustering (mode 2027) by default for proper Unicode support.
    wrapper.terminal.modes.set(.grapheme_cluster, true);

    return @ptrCast(wrapper);
}

/// Splits a packed 0xRRGGBB value.
fn unpackRgb(packed_rgb: u32) color.RGB {
    return .{
        .r = @truncate((packed_rgb >> 16) & 0xFF),
        .g = @truncate((packed_rgb >> 8) & 0xFF),
        .b = @truncate(packed_rgb & 0xFF),
    };
}

pub fn free(ptr: ?*anyopaque) callconv(.c) void {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return));
    const alloc = wrapper.alloc;
    wrapper.stream.deinit();
    wrapper.response_buffer.deinit(alloc);
    wrapper.render_state.deinit(alloc);
    wrapper.terminal.deinit(alloc);
    alloc.destroy(wrapper);
}

pub fn resize(ptr: ?*anyopaque, cols: c_int, rows: c_int) callconv(.c) void {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return));
    if (cols <= 0 or rows <= 0) return;
    wrapper.terminal.resize(wrapper.alloc, .{ .cols = @intCast(cols), .rows = @intCast(rows) }) catch return;
}

pub fn write(ptr: ?*anyopaque, data: [*]const u8, len: usize) callconv(.c) void {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return));
    wrapper.stream.nextSlice(data[0..len]);
}

/// Set a terminal theme color without writing VT data into the session.
/// Keys 0-15 set ANSI palette entries; 16, 17, and 18 set foreground,
/// background, and cursor colors. The color is packed as 0xRRGGBB.
///
/// The theme is the terminal's DEFAULT: it becomes the colour a reset (RIS, DECSTR,
/// OSC 104, OSC 110-112) returns to, and any change a program made to the same
/// entry is dropped so the new theme shows at once.
pub fn setThemeColor(ptr: ?*anyopaque, index: c_int, packed_rgb: u32) callconv(.c) void {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return));
    if (packed_rgb > 0x00ff_ffff) return;

    const rgb = unpackRgb(packed_rgb);
    const colors = &wrapper.terminal.colors;
    switch (index) {
        0...15 => {
            const i: u8 = @intCast(index);
            var theme_palette: color.Palette = colors.palette.original.*;
            theme_palette[i] = rgb;
            colors.palette.changeDefault(wrapper.alloc, theme_palette) catch return;
            colors.palette.reset(i);
            wrapper.terminal.flags.dirty.palette = true;
        },
        16 => colors.foreground = color.DynamicRGB.init(rgb),
        17 => colors.background = color.DynamicRGB.init(rgb),
        18 => colors.cursor = color.DynamicRGB.init(rgb),
        else => {},
    }
}

// ============================================================================
// RenderState API - High-performance rendering
// ============================================================================

/// The core only copies the default colours into the render state when BOTH are set,
/// leaving its own placeholders (white on black) otherwise. The page has always
/// shown a light grey (#CCCCCC) on black for whichever one is unset, so apply that
/// here, honouring reverse video.
fn applyDefaultColors(rs: *RenderState, t: *const Terminal) void {
    const bg = t.colors.background.get() orelse color.RGB{ .r = 0, .g = 0, .b = 0 };
    const fg = t.colors.foreground.get() orelse color.RGB{ .r = 204, .g = 204, .b = 204 };
    const reversed = t.modes.get(.reverse_colors);
    rs.colors.background = if (reversed) fg else bg;
    rs.colors.foreground = if (reversed) bg else fg;
}

/// Update render state from terminal. Call once per frame.
/// Returns dirty state: 0=none, 1=partial, 2=full
pub fn renderStateUpdate(ptr: ?*anyopaque) callconv(.c) GhosttyDirty {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return .full));
    
    // Detect screen buffer switch (normal <-> alternate)
    const current_is_alternate = wrapper.terminal.screens.active_key == .alternate;
    const screen_switched = current_is_alternate != wrapper.last_screen_is_alternate;
    wrapper.last_screen_is_alternate = current_is_alternate;
    
    // When screen switches, we must fully reset the render state to avoid
    // stale cached cell data from the previous screen buffer.
    if (screen_switched) {
        wrapper.render_state.deinit(wrapper.alloc);
        wrapper.render_state = RenderState.empty;
    }
    
    wrapper.render_state.update(wrapper.alloc, &wrapper.terminal) catch return .full;
    applyDefaultColors(&wrapper.render_state, &wrapper.terminal);
    
    // If screen switched, always return full dirty to force complete redraw
    if (screen_switched) {
        return .full;
    }
    
    return switch (wrapper.render_state.dirty) {
        .false => .none,
        .partial => .partial,
        .full => .full,
    };
}

/// Get dimensions from render state
pub fn renderStateGetCols(ptr: ?*anyopaque) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    return @intCast(wrapper.render_state.cols);
}

pub fn renderStateGetRows(ptr: ?*anyopaque) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    return @intCast(wrapper.render_state.rows);
}

/// Get cursor X position
pub fn renderStateGetCursorX(ptr: ?*anyopaque) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    return @intCast(wrapper.render_state.cursor.active.x);
}

/// Get cursor Y position  
pub fn renderStateGetCursorY(ptr: ?*anyopaque) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    return @intCast(wrapper.render_state.cursor.active.y);
}

/// Check if cursor is visible
pub fn renderStateGetCursorVisible(ptr: ?*anyopaque) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    return wrapper.render_state.cursor.visible;
}

/// Get default background color as 0xRRGGBB
pub fn renderStateGetBgColor(ptr: ?*anyopaque) callconv(.c) u32 {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    const bg = wrapper.render_state.colors.background;
    return (@as(u32, bg.r) << 16) | (@as(u32, bg.g) << 8) | bg.b;
}

/// Get default foreground color as 0xRRGGBB
pub fn renderStateGetFgColor(ptr: ?*anyopaque) callconv(.c) u32 {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0xCCCCCC));
    const fg = wrapper.render_state.colors.foreground;
    return (@as(u32, fg.r) << 16) | (@as(u32, fg.g) << 8) | fg.b;
}

/// Check if row is dirty
pub fn renderStateIsRowDirty(ptr: ?*anyopaque, y: c_int) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return true));
    if (wrapper.render_state.dirty == .full) return true;
    if (wrapper.render_state.dirty == .false) return false;
    const y_usize: usize = @intCast(y);
    if (y_usize >= wrapper.render_state.row_data.len) return false;
    return wrapper.render_state.row_data.items(.dirty)[y_usize];
}

/// Mark render state as clean after rendering
pub fn renderStateMarkClean(ptr: ?*anyopaque) callconv(.c) void {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return));
    wrapper.render_state.dirty = .false;
    @memset(wrapper.render_state.row_data.items(.dirty), false);
}

/// Get ALL viewport cells in one call - reads directly from terminal screen buffer.
/// This bypasses the RenderState cache to ensure fresh data for all rows.
/// Returns total cells written (rows * cols), or -1 on error.
pub fn renderStateGetViewport(
    ptr: ?*anyopaque,
    out: [*]GhosttyCell,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const rs = &wrapper.render_state;
    const t = &wrapper.terminal;
    const rows = rs.rows;
    const cols = rs.cols;
    const total: usize = @as(usize, rows) * cols;

    if (buf_size < total) return -1;

    // Read directly from terminal's active screen, bypassing RenderState cache.
    // This ensures we always get fresh data for ALL rows, not just dirty ones.
    const pages = &t.screens.active.pages;

    var idx: usize = 0;
    for (0..rows) |y| {
        // Get the row from the active viewport
        const pin = pages.pin(.{ .active = .{ .y = @intCast(y) } }) orelse {
            // Row doesn't exist, fill with defaults
            for (0..cols) |_| {
                out[idx] = .{
                    .codepoint = 0,
                    .fg_r = rs.colors.foreground.r,
                    .fg_g = rs.colors.foreground.g,
                    .fg_b = rs.colors.foreground.b,
                    .bg_r = rs.colors.background.r,
                    .bg_g = rs.colors.background.g,
                    .bg_b = rs.colors.background.b,
                    .flags = 0,
                    .width = 1,
                    .hyperlink_id = 0,
                };
                idx += 1;
            }
            continue;
        };

        const cells = pin.cells(.all);
        const page = pin.node.page();

        for (0..cols) |x| {
            if (x >= cells.len) {
                // Past end of row, fill with default
                out[idx] = .{
                    .codepoint = 0,
                    .fg_r = rs.colors.foreground.r,
                    .fg_g = rs.colors.foreground.g,
                    .fg_b = rs.colors.foreground.b,
                    .bg_r = rs.colors.background.r,
                    .bg_g = rs.colors.background.g,
                    .bg_b = rs.colors.background.b,
                    .flags = 0,
                    .width = 1,
                    .hyperlink_id = 0,
                };
                idx += 1;
                continue;
            }

            const cell = &cells[x];

            // Get style from page styles (cell has style_id)
            const sty: Style = if (cell.style_id != stylepkg.default_id)
                page.styles.get(page.memory, cell.style_id).*
            else
                .{};

            // Resolve colors
            const fg: color.RGB = switch (sty.fg_color.value()) {
                .none => rs.colors.foreground,
                .palette => |i| rs.colors.palette[i],
                .rgb => |rgb| rgb,
            };
            const bg: color.RGB = if (sty.bg(cell, &rs.colors.palette)) |rgb| rgb else rs.colors.background;

            // Build flags
            var flags: u8 = 0;
            if (sty.flags.bold) flags |= 1 << 0;
            if (sty.flags.italic) flags |= 1 << 1;
            if (sty.flags.underline != .none) flags |= 1 << 2;
            if (sty.flags.strikethrough) flags |= 1 << 3;
            if (sty.flags.inverse) flags |= 1 << 4;
            if (sty.flags.invisible) flags |= 1 << 5;
            if (sty.flags.blink) flags |= 1 << 6;
            if (sty.flags.faint) flags |= 1 << 7;

            // Get grapheme length if cell has grapheme data
            const grapheme_len: u8 = if (cell.hasGrapheme())
                if (page.lookupGrapheme(cell)) |cps| @min(@as(u8, @intCast(cps.len)), 255) else 0
            else
                0;

            out[idx] = .{
                .codepoint = cell.codepoint(),
                .fg_r = fg.r,
                .fg_g = fg.g,
                .fg_b = fg.b,
                .bg_r = bg.r,
                .bg_g = bg.g,
                .bg_b = bg.b,
                .flags = flags,
                .width = switch (cell.wide) {
                    .narrow => 1,
                    .wide => 2,
                    .spacer_tail, .spacer_head => 0,
                },
                .hyperlink_id = if (cell.hyperlink) 1 else 0,
                .grapheme_len = grapheme_len,
            };
            idx += 1;
        }
    }

    return @intCast(total);
}

/// Get grapheme codepoints for a cell at (row, col).
/// Returns all codepoints (including the first one) as u32 values.
/// Returns the number of codepoints written, or -1 on error.
pub fn renderStateGetGrapheme(
    ptr: ?*anyopaque,
    row: c_int,
    col: c_int,
    out: [*]u32,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const rs = &wrapper.render_state;
    const t = &wrapper.terminal;
    const cols: usize = @intCast(rs.cols);

    if (row < 0 or col < 0) return -1;
    if (@as(usize, @intCast(row)) >= rs.rows) return -1;
    if (@as(usize, @intCast(col)) >= cols) return -1;
    if (buf_size < 1) return -1;

    // Get the pin for this row from the terminal's active screen
    const pages = &t.screens.active.pages;
    const pin = pages.pin(.{ .active = .{ .y = @intCast(row) } }) orelse return -1;

    const cells = pin.cells(.all);
    const page = pin.node.page();
    const x: usize = @intCast(col);

    if (x >= cells.len) return -1;

    const cell = &cells[x];

    // First codepoint is always from the cell
    out[0] = cell.codepoint();
    var count: usize = 1;

    // Add extra codepoints from grapheme map if present
    if (cell.hasGrapheme()) {
        if (page.lookupGrapheme(cell)) |cps| {
            for (cps) |cp| {
                if (count >= buf_size) break;
                out[count] = cp;
                count += 1;
            }
        }
    }

    return @intCast(count);
}

// ============================================================================
// Terminal Modes (minimal set for compatibility)
// ============================================================================

pub fn isAlternateScreen(ptr: ?*anyopaque) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    return wrapper.terminal.screens.active_key == .alternate;
}

pub fn hasMouseTracking(ptr: ?*anyopaque) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    return wrapper.terminal.modes.get(.mouse_event_normal) or
           wrapper.terminal.modes.get(.mouse_event_button) or
           wrapper.terminal.modes.get(.mouse_event_any);
}

/// Query arbitrary terminal mode by number
/// Returns true if mode is set, false otherwise
pub fn getMode(ptr: ?*anyopaque, mode_num: c_int, is_ansi: bool) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    const mode = modespkg.modeFromInt(@intCast(mode_num), is_ansi) orelse return false;
    return wrapper.terminal.modes.get(mode);
}

// ============================================================================
// Scrollback API
// ============================================================================

/// Get the number of scrollback lines (history, not including active screen)
pub fn getScrollbackLength(ptr: ?*anyopaque) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return 0));
    const pages = &wrapper.terminal.screens.active.pages;
    // total_rows includes both scrollback and active area
    // We subtract rows (active area) to get just scrollback
    if (pages.total_rows <= pages.rows) return 0;
    return @intCast(pages.total_rows - pages.rows);
}

/// Get a line from the scrollback buffer
/// offset 0 = oldest line in scrollback, offset (length-1) = most recent scrollback line
/// Returns number of cells written, or -1 on error
pub fn getScrollbackLine(
    ptr: ?*anyopaque,
    offset: c_int,
    out: [*]GhosttyCell,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const rs = &wrapper.render_state;
    const cols = rs.cols;
    
    if (buf_size < cols) return -1;
    if (offset < 0) return -1;
    
    const scrollback_len = getScrollbackLength(ptr);
    if (offset >= scrollback_len) return -1;
    
    // Get the pin for this scrollback row
    // history point: y=0 is oldest, y=scrollback_len-1 is newest
    const pages = &wrapper.terminal.screens.active.pages;
    const pin = pages.pin(.{ .history = .{ .y = @intCast(offset) } }) orelse return -1;
    
    // Get cells for this row
    const cells = pin.cells(.all);
    const page = pin.node.page();
    
    // Fill output buffer
    for (0..cols) |x| {
        if (x >= cells.len) {
            // Fill with default
            out[x] = .{
                .codepoint = 0,
                .fg_r = rs.colors.foreground.r,
                .fg_g = rs.colors.foreground.g,
                .fg_b = rs.colors.foreground.b,
                .bg_r = rs.colors.background.r,
                .bg_g = rs.colors.background.g,
                .bg_b = rs.colors.background.b,
                .flags = 0,
                .width = 1,
                .hyperlink_id = 0,
            };
            continue;
        }
        
        const cell = &cells[x];
        
        // Get style from page styles (cell has style_id)
        const sty: Style = if (cell.style_id != stylepkg.default_id)
                page.styles.get(page.memory, cell.style_id).*
            else
                .{};
        
        // Resolve colors
        const fg: color.RGB = switch (sty.fg_color.value()) {
            .none => rs.colors.foreground,
            .palette => |i| rs.colors.palette[i],
            .rgb => |rgb| rgb,
        };
        const bg: color.RGB = if (sty.bg(cell, &rs.colors.palette)) |rgb| rgb else rs.colors.background;
        
        // Build flags
        var flags: u8 = 0;
        if (sty.flags.bold) flags |= 1 << 0;
        if (sty.flags.italic) flags |= 1 << 1;
        if (sty.flags.underline != .none) flags |= 1 << 2;
        if (sty.flags.strikethrough) flags |= 1 << 3;
        if (sty.flags.inverse) flags |= 1 << 4;
        if (sty.flags.invisible) flags |= 1 << 5;
        if (sty.flags.blink) flags |= 1 << 6;
        if (sty.flags.faint) flags |= 1 << 7;

        // Get grapheme length if cell has grapheme data
        const grapheme_len: u8 = if (cell.hasGrapheme())
            if (page.lookupGrapheme(cell)) |cps| @min(@as(u8, @intCast(cps.len)), 255) else 0
        else
            0;

        out[x] = .{
            .codepoint = cell.codepoint(),
            .fg_r = fg.r,
            .fg_g = fg.g,
            .fg_b = fg.b,
            .bg_r = bg.r,
            .bg_g = bg.g,
            .bg_b = bg.b,
            .flags = flags,
            .width = switch (cell.wide) {
                .narrow => 1,
                .wide => 2,
                .spacer_tail, .spacer_head => 0,
            },
            .hyperlink_id = if (cell.hyperlink) 1 else 0,
            .grapheme_len = grapheme_len,
        };
    }
    return @intCast(cols);
}

/// Get grapheme codepoints for a cell in the scrollback buffer.
/// Returns all codepoints (including the first one) as u32 values.
/// Returns the number of codepoints written, or -1 on error.
pub fn getScrollbackGrapheme(
    ptr: ?*anyopaque,
    offset: c_int,
    col: c_int,
    out: [*]u32,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const rs = &wrapper.render_state;
    const cols: usize = @intCast(rs.cols);

    if (offset < 0 or col < 0) return -1;
    if (@as(usize, @intCast(col)) >= cols) return -1;
    if (buf_size < 1) return -1;

    const scrollback_len = getScrollbackLength(ptr);
    if (offset >= scrollback_len) return -1;

    // Get the pin for this scrollback row
    const pages = &wrapper.terminal.screens.active.pages;
    const pin = pages.pin(.{ .history = .{ .y = @intCast(offset) } }) orelse return -1;

    const cells = pin.cells(.all);
    const page = pin.node.page();
    const x: usize = @intCast(col);

    if (x >= cells.len) return -1;

    const cell = &cells[x];

    // First codepoint is always from the cell
    out[0] = cell.codepoint();
    var count: usize = 1;

    // Add extra codepoints from grapheme map if present
    if (cell.hasGrapheme()) {
        if (page.lookupGrapheme(cell)) |cps| {
            for (cps) |cp| {
                if (count >= buf_size) break;
                out[count] = cp;
                count += 1;
            }
        }
    }

    return @intCast(count);
}

/// Check if a row is a continuation from the previous row (soft-wrapped)
/// This matches xterm.js semantics where isWrapped indicates the row continues
/// from the previous row, not that it wraps to the next row.
pub fn isRowWrapped(ptr: ?*anyopaque, y: c_int) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    const pages = &wrapper.terminal.screens.active.pages;
    
    // Get pin for this row in active area
    const pin = pages.pin(.{ .active = .{ .y = @intCast(y) } }) orelse return false;
    const rac = pin.rowAndCell();
    
    // wrap_continuation means this row continues from the previous row
    return rac.row.wrap_continuation;
}

// ============================================================================
// Hyperlink API
// ============================================================================

/// Get the hyperlink URI for a cell in the active viewport.
/// Returns number of bytes written, 0 if no hyperlink, -1 on error.
pub fn getHyperlinkUri(
    ptr: ?*anyopaque,
    row: c_int,
    col: c_int,
    out: [*]u8,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const t = &wrapper.terminal;

    if (row < 0 or col < 0) return -1;

    // Get the pin for this row from the terminal's active screen
    const pages = &t.screens.active.pages;
    const pin = pages.pin(.{ .active = .{ .y = @intCast(row) } }) orelse return -1;

    const cells = pin.cells(.all);
    const page = pin.node.page();
    const x: usize = @intCast(col);

    if (x >= cells.len) return -1;

    const cell = &cells[x];

    // Check if cell has a hyperlink
    if (!cell.hyperlink) return 0;

    // Look up the hyperlink ID from the page
    const hyperlink_id = page.lookupHyperlink(cell) orelse return 0;

    // Get the hyperlink entry from the set
    const hyperlink_entry = page.hyperlink_set.get(page.memory, hyperlink_id);

    // Get the URI bytes from the page memory
    const uri = hyperlink_entry.uri.slice(page.memory);

    if (uri.len == 0) return 0;
    if (buf_size < uri.len) return -1;

    @memcpy(out[0..uri.len], uri);
    return @intCast(uri.len);
}

/// Get the hyperlink URI for a cell in the scrollback buffer.
/// @param offset Scrollback line offset (0 = oldest, scrollback_len-1 = newest)
/// @param col Column index (0-based)
/// Returns number of bytes written, 0 if no hyperlink, -1 on error.
pub fn getScrollbackHyperlinkUri(
    ptr: ?*anyopaque,
    offset: c_int,
    col: c_int,
    out: [*]u8,
    buf_size: usize,
) callconv(.c) c_int {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));

    if (offset < 0 or col < 0) return -1;

    const scrollback_len = getScrollbackLength(ptr);
    if (offset >= scrollback_len) return -1;

    // Get the pin for this scrollback row
    const pages = &wrapper.terminal.screens.active.pages;
    const pin = pages.pin(.{ .history = .{ .y = @intCast(offset) } }) orelse return -1;

    const cells = pin.cells(.all);
    const page = pin.node.page();
    const x: usize = @intCast(col);

    if (x >= cells.len) return -1;

    const cell = &cells[x];

    // Check if cell has a hyperlink
    if (!cell.hyperlink) return 0;

    // Look up the hyperlink ID from the page
    const hyperlink_id = page.lookupHyperlink(cell) orelse return 0;

    // Get the hyperlink entry from the set
    const hyperlink_entry = page.hyperlink_set.get(page.memory, hyperlink_id);

    // Get the URI bytes from the page memory
    const uri = hyperlink_entry.uri.slice(page.memory);

    if (uri.len == 0) return 0;
    if (buf_size < uri.len) return -1;

    @memcpy(out[0..uri.len], uri);
    return @intCast(uri.len);
}

// ============================================================================
// Response API - for DSR and other terminal queries
// ============================================================================

/// Check if there are pending responses from the terminal
pub fn hasResponse(ptr: ?*anyopaque) callconv(.c) bool {
    const wrapper: *const TerminalWrapper = @ptrCast(@alignCast(ptr orelse return false));
    return wrapper.response_buffer.items.len > 0;
}

/// Read pending responses from the terminal.
/// Returns number of bytes written to buffer, or 0 if no responses pending.
/// Returns -1 on error (null pointer or buffer too small).
pub fn readResponse(ptr: ?*anyopaque, out: [*]u8, buf_size: usize) callconv(.c) c_int {
    const wrapper: *TerminalWrapper = @ptrCast(@alignCast(ptr orelse return -1));
    const len = @min(wrapper.response_buffer.items.len, buf_size);
    if (len == 0) return 0;
    
    @memcpy(out[0..len], wrapper.response_buffer.items[0..len]);
    
    // Remove consumed bytes from buffer
    if (len == wrapper.response_buffer.items.len) {
        wrapper.response_buffer.clearRetainingCapacity();
    } else {
        // Shift remaining bytes to front
        std.mem.copyForwards(
            u8,
            wrapper.response_buffer.items[0..],
            wrapper.response_buffer.items[len..],
        );
        wrapper.response_buffer.shrinkRetainingCapacity(wrapper.response_buffer.items.len - len);
    }
    
    return @intCast(len);
}

// ============================================================================
// WebAssembly exports
// ============================================================================

/// Allocation helpers the TypeScript binding uses for scratch buffers. The core's own
/// wasm allocator offers only raw byte blocks and opaque slots, so the typed
/// conveniences the binding relies on are rebuilt on top of them.
const wasm_alloc = @import("../../lib/allocator/wasm.zig");

fn allocU8Array(len: usize) callconv(.c) ?[*]u8 {
    return wasm_alloc.allocBytes(len);
}
fn freeU8Array(ptr: ?[*]u8, len: usize) callconv(.c) void {
    wasm_alloc.freeBytes(ptr, len);
}
fn allocU8() callconv(.c) ?*u8 {
    return @ptrCast(wasm_alloc.allocBytes(@sizeOf(u8)));
}
fn freeU8(ptr: ?*u8) callconv(.c) void {
    wasm_alloc.freeBytes(@ptrCast(ptr), @sizeOf(u8));
}
fn allocUsize() callconv(.c) ?*usize {
    return @ptrCast(@alignCast(wasm_alloc.allocBytes(@sizeOf(usize))));
}
fn freeUsize(ptr: ?*usize) callconv(.c) void {
    wasm_alloc.freeBytes(@ptrCast(ptr), @sizeOf(usize));
}

comptime {
    // Only the browser build exports these; a native build of the library keeps
    // the official terminal API and never references this file's entry points.
    if (builtin.target.cpu.arch.isWasm()) {
        const e = struct {
            fn put(comptime name: []const u8, comptime f: anytype) void {
                @export(f, .{ .name = "ghostty_web_" ++ name });
            }
        };
        // Terminal lifecycle
        e.put("terminal_new", &new);
        e.put("terminal_new_with_config", &newWithConfig);
        e.put("terminal_free", &free);
        e.put("terminal_resize", &resize);
        e.put("terminal_write", &write);
        e.put("terminal_set_theme_color", &setThemeColor);
        // Render state
        e.put("render_state_update", &renderStateUpdate);
        e.put("render_state_get_cols", &renderStateGetCols);
        e.put("render_state_get_rows", &renderStateGetRows);
        e.put("render_state_get_cursor_x", &renderStateGetCursorX);
        e.put("render_state_get_cursor_y", &renderStateGetCursorY);
        e.put("render_state_get_cursor_visible", &renderStateGetCursorVisible);
        e.put("render_state_get_bg_color", &renderStateGetBgColor);
        e.put("render_state_get_fg_color", &renderStateGetFgColor);
        e.put("render_state_is_row_dirty", &renderStateIsRowDirty);
        e.put("render_state_mark_clean", &renderStateMarkClean);
        e.put("render_state_get_viewport", &renderStateGetViewport);
        e.put("render_state_get_grapheme", &renderStateGetGrapheme);
        // Terminal modes
        e.put("terminal_is_alternate_screen", &isAlternateScreen);
        e.put("terminal_has_mouse_tracking", &hasMouseTracking);
        e.put("terminal_get_mode", &getMode);
        // Scrollback
        e.put("terminal_get_scrollback_length", &getScrollbackLength);
        e.put("terminal_get_scrollback_line", &getScrollbackLine);
        e.put("terminal_get_scrollback_grapheme", &getScrollbackGrapheme);
        e.put("terminal_is_row_wrapped", &isRowWrapped);
        // Hyperlinks
        e.put("terminal_get_hyperlink_uri", &getHyperlinkUri);
        e.put("terminal_get_scrollback_hyperlink_uri", &getScrollbackHyperlinkUri);
        // Query replies
        e.put("terminal_has_response", &hasResponse);
        e.put("terminal_read_response", &readResponse);
        // Typed scratch allocation
        @export(&allocU8Array, .{ .name = "ghostty_wasm_alloc_u8_array" });
        @export(&freeU8Array, .{ .name = "ghostty_wasm_free_u8_array" });
        @export(&allocU8, .{ .name = "ghostty_wasm_alloc_u8" });
        @export(&freeU8, .{ .name = "ghostty_wasm_free_u8" });
        @export(&allocUsize, .{ .name = "ghostty_wasm_alloc_usize" });
        @export(&freeUsize, .{ .name = "ghostty_wasm_free_usize" });
    }
}

// ============================================================================
// Tests
// ============================================================================

test "terminal lifecycle" {
    const term = new(80, 24);
    defer free(term);
    try std.testing.expect(term != null);

    _ = renderStateUpdate(term);
    try std.testing.expectEqual(@as(c_int, 80), renderStateGetCols(term));
    try std.testing.expectEqual(@as(c_int, 24), renderStateGetRows(term));
}

test "terminal write and read via render state" {
    const term = new(80, 24);
    defer free(term);

    write(term, "Hello", 5);
    _ = renderStateUpdate(term);

    var cells: [80 * 24]GhosttyCell = undefined;
    const count = renderStateGetViewport(term, &cells, 80 * 24);
    try std.testing.expectEqual(@as(c_int, 80 * 24), count);
    try std.testing.expectEqual(@as(u32, 'H'), cells[0].codepoint);
    try std.testing.expectEqual(@as(u32, 'o'), cells[4].codepoint);
}

test "queries the page owns are answered once and the rest stay silent" {
    const term = new(80, 24);
    defer free(term);

    const queries = "\x1b[6n\x1b[c\x1b[>c\x1b[5n\x1b[?1$p\x1b[>q";
    write(term, queries, queries.len);
    var buf: [128]u8 = undefined;
    const n = readResponse(term, &buf, buf.len);
    try std.testing.expectEqualStrings("\x1b[1;1R\x1b[?62;22c\x1b[>1;10;0c\x1b[0n", buf[0..@intCast(n)]);
}
