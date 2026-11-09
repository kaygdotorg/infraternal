//! Exact cold-page storage: UTF-8 row deltas, run-length attributes and opaque native metadata [D270].
//! Reversible row offsets and text deltas expose repetition to the existing
//! page codec. A bounded outer pass shares repeated block bytes. Decoding needs
//! no allocation and restores every raw cell bit, including nontext colors,
//! protection, hyperlinks, wide-cell markers and semantic flags.
const std = @import("std");
const lz4 = @import("terminal/compress/lz4.zig");
const native = @import("terminal/page.zig");
const c = @import("terminal/c/terminal.zig");
const lib = @import("terminal/lib.zig");
const header = 36;
// Bounded stack scratch makes restore allocation-free even at large geometry.
// Literal UTF-8 compresses repeated words/digits without a run header per cell.
const block_cells = 4096;
const outer_limit = 32 * 1024;
const cp_mask: u64 = ((@as(u64, 1) << 21) - 1) << 2;
comptime {
    std.debug.assert(@sizeOf(native.Cell) == 8);
    std.debug.assert(@bitOffsetOf(native.Cell, "content_tag") == 0);
    std.debug.assert(@bitOffsetOf(native.Cell, "content") == 2);
    std.debug.assert(@bitOffsetOf(native.Row, "cells") == 0);
    std.debug.assert(@bitSizeOf(@FieldType(native.Row, "cells")) == 32);
}
const EncodeError = lz4.CompressError || error{InvalidText};
const DecodeError = lz4.DecompressError || error{InvalidInput};

/// Compress eligible cold history pages through the internal PageList policy.
/// The stable C API keeps screens opaque and has no compact-history operation;
/// this optional experiment therefore needs this guarded internal driver.
pub fn compact(handle: c.Terminal, full: bool) callconv(lib.calling_conv) void {
    const terminal = c.zigTerminal(handle) orelse return;
    inline for (.{ .primary, .alternate }) |key| {
        if (terminal.screens.get(key)) |screen| {
            if (full) {
                _ = screen.pages.compress(.full);
            } else {
                _ = screen.pages.compress(.incremental);
            }
        }
    }
}

const Writer = struct {
    bytes: []u8,
    at: usize = header,
    fn put(self: *Writer, bytes: []const u8) EncodeError!void {
        if (bytes.len > self.bytes.len - self.at) return error.OutputTooSmall;
        @memcpy(self.bytes[self.at..][0..bytes.len], bytes);
        self.at += bytes.len;
    }
    fn integer(self: *Writer, comptime T: type, value: T) EncodeError!void {
        var bytes: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &bytes, value, .little);
        try self.put(&bytes);
    }
    fn run(self: *Writer, length: usize) EncodeError!void {
        var value: u32 = @intCast(length);
        while (value > 127) : (value >>= 7) try self.put(&.{@as(u8, @truncate(value)) | 128});
        try self.put(&.{@intCast(value)});
    }
};
const Reader = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Reader, count: usize) DecodeError![]const u8 {
        if (count > self.bytes.len - self.at) return error.InvalidInput;
        const result = self.bytes[self.at..][0..count];
        self.at += count;
        return result;
    }
    fn integer(self: *Reader, comptime T: type) DecodeError!T {
        const bytes = try self.take(@sizeOf(T));
        return std.mem.readInt(T, bytes[0..@sizeOf(T)], .little);
    }
    fn run(self: *Reader) DecodeError!u32 {
        var value: u32 = 0;
        for (0..5) |index| {
            const byte = (try self.take(1))[0];
            if (index == 4 and byte > 15) return error.InvalidInput;
            value |= @as(u32, byte & 127) << @intCast(index * 7);
            if (byte & 128 == 0) return value;
        }
        return error.InvalidInput;
    }
};
fn point(cell: u64) u21 {
    return if (cell & 3 <= 1) @intCast((cell & cp_mask) >> 2) else 0;
}
fn attributes(cell: u64) u64 {
    return if (cell & 3 <= 1) cell & ~cp_mask else cell;
}

/// Rows normally use consecutive cell offsets. XOR preserves arbitrary row
/// permutations too, while making the common offsets disappear before LZ4.
fn rowOffsets(bytes: []u8, page: *const native.Page) error{InvalidInput}!void {
    const layout = native.Page.layout(page.capacity);
    for (0..page.capacity.rows) |row| {
        const expected = std.math.cast(u32, layout.cells_start + row * page.capacity.cols * @sizeOf(native.Cell)) orelse return error.InvalidInput;
        const at = layout.rows_start + row * @sizeOf(native.Row);
        const value = std.mem.readInt(u32, bytes[at..][0..4], .little);
        std.mem.writeInt(u32, bytes[at..][0..4], value ^ expected, .little);
    }
}

pub fn encode(page: *const native.Page, output: []u8, table: *lz4.HashTable) EncodeError!usize {
    const plain = try encodePlain(page, output, table);
    // Repeated block headers and already encoded attribute/text patterns can
    // still share bytes. Use spare caller scratch, never another allocation.
    if (plain <= outer_limit) {
        const packed_len = lz4.compress(output[0..plain], output[plain..], table) catch return plain;
        if (packed_len + 8 < plain) {
            @memcpy(output[8..][0..packed_len], output[plain..][0..packed_len]);
            @memcpy(output[0..4], "IHC4");
            std.mem.writeInt(u16, output[4..6], @intCast(plain), .little);
            std.mem.writeInt(u16, output[6..8], @intCast(packed_len), .little);
            return packed_len + 8;
        }
    }
    return plain;
}

fn encodePlain(page: *const native.Page, output: []u8, table: *lz4.HashTable) EncodeError!usize {
    if (output.len < header) return error.OutputTooSmall;
    const layout = native.Page.layout(page.capacity);
    const first = layout.cells_start;
    const count = layout.cells_size / 8;
    const end = first + layout.cells_size;
    const cells = std.mem.bytesAsSlice(u64, page.memory[first..end]);
    var writer = Writer{ .bytes = output };
    var flags: u32 = 0;
    var prefix_storage: [4096]u8 = undefined;
    const prefix = if (first <= prefix_storage.len) transformed: {
        const bytes = prefix_storage[0..first];
        @memcpy(bytes, page.memory[0..first]);
        rowOffsets(bytes, page) catch return error.InvalidText;
        flags |= 1;
        break :transformed bytes;
    } else page.memory[0..first];
    if (page.capacity.cols == 0) return error.InvalidText;
    const cols = page.capacity.cols;
    const deltas = deltas: {
        for (cells, 0..) |cell, at| {
            const previous = if (at < cols) 0 else point(cells[at - cols]);
            _ = std.unicode.utf8CodepointSequenceLength(point(cell) ^ previous) catch break :deltas false;
        }
        break :deltas true;
    };
    if (deltas) flags |= 2;
    const prefix_len = try lz4.compress(prefix, output[writer.at..], table);
    writer.at += prefix_len;
    const suffix_len = try lz4.compress(page.memory[end..], output[writer.at..], table);
    writer.at += suffix_len;
    const blocks_first = writer.at;
    var index: usize = 0;
    while (index < count) {
        const limit = @min(index + block_cells, count);
        var text: [block_cells * 4]u8 = undefined;
        var text_at: usize = 0;
        for (cells[index..limit], index..) |cell, at| {
            var utf8: [4]u8 = undefined;
            const previous = if (!deltas or at < cols) 0 else point(cells[at - cols]);
            const len = std.unicode.utf8Encode(point(cell) ^ previous, &utf8) catch return error.InvalidText;
            @memcpy(text[text_at..][0..len], utf8[0..len]);
            text_at += len;
        }
        var attrs: [block_cells * 9]u8 = undefined;
        var attr_writer = Writer{ .bytes = &attrs, .at = 0 };
        while (index < limit) {
            const value = attributes(cells[index]);
            var next = index + 1;
            while (next < limit and attributes(cells[next]) == value) : (next += 1) {}
            try attr_writer.run(next - index);
            try attr_writer.integer(u64, value);
            index = next;
        }
        const block_header = writer.at;
        try writer.put(&.{ 0, 0, 0, 0, 0, 0, 0, 0 });
        const text_len = try lz4.compress(text[0..text_at], output[writer.at..], table);
        writer.at += text_len;
        const attrs_len = try lz4.compress(attrs[0..attr_writer.at], output[writer.at..], table);
        writer.at += attrs_len;
        for ([_]usize{ text_at, text_len, attr_writer.at, attrs_len }, 0..) |value, i| {
            std.mem.writeInt(u16, output[block_header + i * 2 ..][0..2], @intCast(value), .little);
        }
    }
    @memcpy(output[0..4], "IHC2");
    for ([_]usize{ first, count, prefix_len, suffix_len, writer.at - blocks_first, page.memory.len, block_cells, flags }, 0..) |value, i| {
        std.mem.writeInt(u32, output[4 + i * 4 ..][0..4], @intCast(value), .little);
    }
    return writer.at;
}

pub fn decode(encoded: []const u8, page: *const native.Page, memory: []u8) DecodeError!void {
    if (encoded.len >= 4 and std.mem.eql(u8, encoded[0..4], "IHC4")) {
        if (encoded.len < 8) return error.InvalidInput;
        const raw_len = std.mem.readInt(u16, encoded[4..6], .little);
        const packed_len = std.mem.readInt(u16, encoded[6..8], .little);
        if (raw_len < header or raw_len > outer_limit or encoded.len - 8 != packed_len) return error.InvalidInput;
        var scratch: [outer_limit]u8 = undefined;
        const plain = scratch[0..raw_len];
        _ = lz4.decompress(encoded[8..], plain) catch return error.InvalidInput;
        // Only the plain format is accepted here: nesting cannot consume
        // another stack buffer, including on malformed input.
        return decodePlain(plain, page, memory);
    }
    return decodePlain(encoded, page, memory);
}

fn decodePlain(encoded: []const u8, page: *const native.Page, memory: []u8) DecodeError!void {
    if (encoded.len < header or !std.mem.eql(u8, encoded[0..4], "IHC2")) return error.InvalidInput;
    var input = Reader{ .bytes = encoded, .at = 4 };
    const first = try input.integer(u32);
    const count = try input.integer(u32);
    const prefix_len = try input.integer(u32);
    const suffix_len = try input.integer(u32);
    const blocks_len = try input.integer(u32);
    const raw_len = try input.integer(u32);
    if (try input.integer(u32) != block_cells) return error.InvalidInput;
    const flags = try input.integer(u32);
    if (flags & ~@as(u32, 3) != 0 or page.capacity.cols == 0) return error.InvalidInput;
    const layout = native.Page.layout(page.capacity);
    if (first != layout.cells_start or count != layout.cells_size / 8 or raw_len != page.memory.len or memory.len != raw_len) return error.InvalidInput;
    const end = layout.cells_start + layout.cells_size;
    if (try lz4.decompress(try input.take(prefix_len), memory[0..first]) != first) return error.InvalidInput;
    if (flags & 1 != 0) try rowOffsets(memory[0..first], page);
    if (try lz4.decompress(try input.take(suffix_len), memory[end..]) != memory.len - end) return error.InvalidInput;
    var blocks = Reader{ .bytes = try input.take(blocks_len) };
    if (input.at != input.bytes.len) return error.InvalidInput;
    const cells = std.mem.bytesAsSlice(u64, memory[first..end]);
    var index: usize = 0;
    while (index < count) {
        const limit = @min(index + block_cells, count);
        const text_raw_len = try blocks.integer(u16);
        const text_len = try blocks.integer(u16);
        const attrs_raw_len = try blocks.integer(u16);
        const attrs_len = try blocks.integer(u16);
        if (text_raw_len < limit - index or text_raw_len > block_cells * 4 or attrs_raw_len == 0 or attrs_raw_len > block_cells * 9) return error.InvalidInput;
        var text_storage: [block_cells * 4]u8 = undefined;
        var attrs_storage: [block_cells * 9]u8 = undefined;
        const text_raw = text_storage[0..text_raw_len];
        const attrs_raw = attrs_storage[0..attrs_raw_len];
        _ = try lz4.decompress(try blocks.take(text_len), text_raw);
        _ = try lz4.decompress(try blocks.take(attrs_len), attrs_raw);
        var text = Reader{ .bytes = text_raw };
        var attrs = Reader{ .bytes = attrs_raw };
        var attr_left: usize = 0;
        var attr: u64 = 0;
        while (index < limit) : (index += 1) {
            const text_first = text.at;
            const byte = (try text.take(1))[0];
            const len = std.unicode.utf8ByteSequenceLength(byte) catch return error.InvalidInput;
            _ = try text.take(len - 1);
            const value = std.unicode.utf8Decode(text.bytes[text_first..text.at]) catch return error.InvalidInput;
            const previous = if (flags & 2 == 0 or index < page.capacity.cols) 0 else point(cells[index - page.capacity.cols]);
            const cp = value ^ previous;
            _ = std.unicode.utf8CodepointSequenceLength(cp) catch return error.InvalidInput;
            if (attr_left == 0) {
                attr_left = try attrs.run();
                attr = try attrs.integer(u64);
                if (attr_left == 0 or attr_left > limit - index or (attr & 3 <= 1 and attr & cp_mask != 0)) return error.InvalidInput;
            }
            if (attr & 3 > 1 and cp != 0) return error.InvalidInput;
            cells[index] = attr | (@as(u64, cp) << 2);
            attr_left -= 1;
        }
        if (attr_left != 0 or text.at != text.bytes.len or attrs.at != attrs.bytes.len) return error.InvalidInput;
    }
    if (blocks.at != blocks.bytes.len) return error.InvalidInput;
}

test "compact history preserves every raw cell bit and native metadata" {
    var page = try native.Page.init(.{ .cols = 80, .rows = 32, .styles = 128, .grapheme_bytes = 8192, .string_bytes = 4096 });
    defer page.deinit();
    const layout = native.Page.layout(page.capacity);
    const cells = std.mem.bytesAsSlice(u64, page.memory[layout.cells_start..][0..layout.cells_size]);
    var seed: u64 = 270_205;
    for (cells, 0..) |*cell, index| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        const cp: u21 = switch (index % 7) {
            0 => 0,
            1 => 'A',
            2 => 0x0301,
            3 => 0x754c,
            4 => 0x1f642,
            5 => 0x10ffff,
            else => ' ',
        };
        // Nontext content keeps all 64 bits; text clears only its codepoint
        // field. Styles, protection, wide markers and semantic bits vary.
        cell.* = if (seed & 3 > 1) seed else (seed & ~cp_mask) | (@as(u64, cp) << 2);
    }
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const restored = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len);
    defer std.heap.page_allocator.free(restored);
    var table: lz4.HashTable = undefined;
    const length = try encode(&page, encoded, &table);
    try decode(encoded[0..length], &page, restored);
    try std.testing.expectEqualSlices(u8, page.memory, restored);
}

test "compact history bounds numbered decimal page encoding" {
    var page = try native.Page.init(.{ .cols = 80, .rows = 32, .styles = 128, .grapheme_bytes = 8192, .string_bytes = 4096 });
    defer page.deinit();
    page.size = .{ .cols = 80, .rows = 32 };
    for (0..32) |row| {
        var line: [72]u8 = undefined;
        _ = try std.fmt.bufPrint(&line, "{d:0>6} ", .{row + 1});
        for (7..72) |col| line[col] = '0' + @as(u8, @intCast((col - 7) % 10));
        for (line, 0..) |cp, col| page.getRowAndCell(col, row).cell.* = .init(cp);
    }
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const restored = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len);
    defer std.heap.page_allocator.free(restored);
    var table: lz4.HashTable = undefined;
    const length = try encode(&page, encoded, &table);
    try std.testing.expect(length <= 1024);
    try decode(encoded[0..length], &page, restored);
    try std.testing.expectEqualSlices(u8, page.memory, restored);
}

test "compact history rejects malformed dimensions and every truncation" {
    var page = try native.Page.init(.{ .cols = 12, .rows = 9, .styles = 8, .grapheme_bytes = 128, .string_bytes = 128 });
    defer page.deinit();
    page.getRowAndCell(2, 3).cell.* = .init(0x754c);
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const restored = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len);
    defer std.heap.page_allocator.free(restored);
    var table: lz4.HashTable = undefined;
    const length = try encodePlain(&page, encoded, &table);
    for (0..length) |end| {
        if (decode(encoded[0..end], &page, restored)) |_| return error.TruncationAccepted else |_| {}
    }
    for ([_]usize{ 0, 4, 8, 24 }) |offset| {
        encoded[offset] ^= 1;
        try std.testing.expectError(error.InvalidInput, decode(encoded[0..length], &page, restored));
        encoded[offset] ^= 1;
    }
    encoded[length] = 0;
    try std.testing.expectError(error.InvalidInput, decode(encoded[0 .. length + 1], &page, restored));
}

test "compact history seeded malformed inputs cannot escape output bounds" {
    var page = try native.Page.init(.{ .cols = 12, .rows = 9, .styles = 8, .grapheme_bytes = 128, .string_bytes = 128 });
    defer page.deinit();
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const guarded = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len + 4096);
    defer std.heap.page_allocator.free(guarded);
    const restored = guarded[0..page.memory.len];
    const guard = guarded[page.memory.len..];
    @memset(guard, 0xa5);
    var table: lz4.HashTable = undefined;
    const length = try encode(&page, encoded, &table);
    const valid = try std.testing.allocator.dupe(u8, encoded[0..length]);
    defer std.testing.allocator.free(valid);
    var seed: u64 = 270_205;
    for (0..10_000) |_| {
        @memcpy(encoded[0..length], valid);
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        encoded[seed % length] ^= @as(u8, 1) << @intCast((seed >> 32) % 8);
        decode(encoded[0..length], &page, restored) catch {};
        for (guard) |byte| try std.testing.expectEqual(@as(u8, 0xa5), byte);
    }
}

test "compact history outer envelope rejects trailing bytes limits and nesting" {
    var page = try native.Page.init(.{ .cols = 12, .rows = 9, .styles = 8, .grapheme_bytes = 128, .string_bytes = 128 });
    defer page.deinit();
    const plain = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(plain);
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const restored = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len);
    defer std.heap.page_allocator.free(restored);
    var table: lz4.HashTable = undefined;
    const plain_len = try encodePlain(&page, plain, &table);
    const packed_len = try lz4.compress(plain[0..plain_len], encoded[8..], &table);
    @memcpy(encoded[0..4], "IHC4");
    std.mem.writeInt(u16, encoded[4..6], @intCast(plain_len), .little);
    std.mem.writeInt(u16, encoded[6..8], @intCast(packed_len), .little);
    const length = packed_len + 8;
    try decode(encoded[0..length], &page, restored);
    try std.testing.expectEqualSlices(u8, page.memory, restored);
    for (0..length) |end| {
        if (decode(encoded[0..end], &page, restored)) |_| return error.TruncationAccepted else |_| {}
    }
    encoded[length] = 0;
    try std.testing.expectError(error.InvalidInput, decode(encoded[0 .. length + 1], &page, restored));
    std.mem.writeInt(u16, encoded[4..6], outer_limit + 1, .little);
    try std.testing.expectError(error.InvalidInput, decode(encoded[0..length], &page, restored));
    @memcpy(plain[0..4], "IHC4");
    const nested_len = try lz4.compress(plain[0..plain_len], encoded[8..], &table);
    std.mem.writeInt(u16, encoded[4..6], @intCast(plain_len), .little);
    std.mem.writeInt(u16, encoded[6..8], @intCast(nested_len), .little);
    try std.testing.expectError(error.InvalidInput, decode(encoded[0 .. nested_len + 8], &page, restored));
}

const DecodeFuzz = struct {
    page: *const native.Page,
    memory: []u8,
    before: []const u8,
    after: []const u8,
    fn one(self: DecodeFuzz, input: []const u8) !void {
        decode(input, self.page, self.memory) catch {};
        try std.testing.expect(std.mem.allEqual(u8, self.before, 0xa5));
        try std.testing.expect(std.mem.allEqual(u8, self.after, 0xa5));
    }
};

test "compact history decoder fuzz" {
    var page = try native.Page.init(.{ .cols = 12, .rows = 9, .styles = 8, .grapheme_bytes = 128, .string_bytes = 128 });
    defer page.deinit();
    const rac = page.getRowAndCell(2, 3);
    rac.cell.* = .init(0x754c);
    rac.cell.protected = true;
    try page.appendGrapheme(rac.row, rac.cell, 0x0301);
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    var table: lz4.HashTable = undefined;
    const length = try encode(&page, encoded, &table);
    const guard_len = std.heap.page_size_min;
    const guarded = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(guard_len), page.memory.len + 2 * guard_len);
    defer std.heap.page_allocator.free(guarded);
    const before = guarded[0..guard_len];
    const after = guarded[guard_len + page.memory.len ..];
    @memset(before, 0xa5);
    @memset(after, 0xa5);
    // A valid page seed reaches the LZ4, UTF-8 and attribute decoders from
    // the first fuzz iteration; arbitrary/truncated data exercises rejection.
    try std.testing.fuzz(DecodeFuzz{
        .page = &page,
        .memory = guarded[guard_len..][0..page.memory.len],
        .before = before,
        .after = after,
    }, DecodeFuzz.one, .{ .corpus = &.{ encoded[0..length], "IHC1" } });
}
