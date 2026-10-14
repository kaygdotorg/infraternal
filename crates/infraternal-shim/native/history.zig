//! Exact cold-page storage: UTF-8 text runs, run-length cell attributes and opaque native metadata [D270].
//! The existing page codec compresses the two non-cell regions. Decoding needs
//! no allocation and restores every raw cell bit, including nontext colors,
//! protection, hyperlinks, wide-cell markers and semantic flags.
const std = @import("std");
const lz4 = @import("terminal/compress/lz4.zig");
const native = @import("terminal/page.zig");
const header = 28;
const cp_mask: u64 = ((@as(u64, 1) << 21) - 1) << 2;
comptime {
    std.debug.assert(@sizeOf(native.Cell) == 8);
    std.debug.assert(@bitOffsetOf(native.Cell, "content_tag") == 0);
    std.debug.assert(@bitOffsetOf(native.Cell, "content") == 2);
}
const EncodeError = lz4.CompressError || error{InvalidText};
const DecodeError = lz4.DecompressError || error{InvalidInput};

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

pub fn encode(page: *const native.Page, output: []u8, table: *lz4.HashTable) EncodeError!usize {
    if (output.len < header) return error.OutputTooSmall;
    const layout = native.Page.layout(page.capacity);
    const first = layout.cells_start;
    const count = layout.cells_size / 8;
    const end = first + layout.cells_size;
    const cells = std.mem.bytesAsSlice(u64, page.memory[first..end]);
    var writer = Writer{ .bytes = output };
    const prefix_len = try lz4.compress(page.memory[0..first], output[writer.at..], table);
    writer.at += prefix_len;
    const suffix_len = try lz4.compress(page.memory[end..], output[writer.at..], table);
    writer.at += suffix_len;
    const text_first = writer.at;
    var index: usize = 0;
    while (index < count) {
        const cp = point(cells[index]);
        var next = index + 1;
        while (next < count and point(cells[next]) == cp) : (next += 1) {}
        var utf8: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(cp, &utf8) catch return error.InvalidText;
        try writer.run(next - index);
        try writer.put(&.{len});
        try writer.put(utf8[0..len]);
        index = next;
    }
    const text_len = writer.at - text_first;
    index = 0;
    while (index < count) {
        const value = attributes(cells[index]);
        var next = index + 1;
        while (next < count and attributes(cells[next]) == value) : (next += 1) {}
        try writer.run(next - index);
        try writer.integer(u64, value);
        index = next;
    }
    @memcpy(output[0..4], "IHC1");
    for ([_]usize{ first, count, prefix_len, suffix_len, text_len, page.memory.len }, 0..) |value, i| {
        std.mem.writeInt(u32, output[4 + i * 4 ..][0..4], @intCast(value), .little);
    }
    return writer.at;
}

pub fn decode(encoded: []const u8, page: *const native.Page, memory: []u8) DecodeError!void {
    if (encoded.len < header or !std.mem.eql(u8, encoded[0..4], "IHC1")) return error.InvalidInput;
    var input = Reader{ .bytes = encoded, .at = 4 };
    const first = try input.integer(u32);
    const count = try input.integer(u32);
    const prefix_len = try input.integer(u32);
    const suffix_len = try input.integer(u32);
    const text_len = try input.integer(u32);
    const raw_len = try input.integer(u32);
    const layout = native.Page.layout(page.capacity);
    if (first != layout.cells_start or count != layout.cells_size / 8 or raw_len != page.memory.len or memory.len != raw_len) return error.InvalidInput;
    const end = layout.cells_start + layout.cells_size;
    if (try lz4.decompress(try input.take(prefix_len), memory[0..first]) != first) return error.InvalidInput;
    if (try lz4.decompress(try input.take(suffix_len), memory[end..]) != memory.len - end) return error.InvalidInput;
    var text = Reader{ .bytes = try input.take(text_len) };
    var attrs = Reader{ .bytes = input.bytes[input.at..] };
    const cells = std.mem.bytesAsSlice(u64, memory[first..end]);
    var text_left: usize = 0;
    var attr_left: usize = 0;
    var cp: u21 = 0;
    var attr: u64 = 0;
    for (cells, 0..) |*cell, index| {
        if (text_left == 0) {
            text_left = try text.run();
            const len = (try text.take(1))[0];
            if (len == 0 or len > 4 or text_left == 0 or text_left > count - index) return error.InvalidInput;
            cp = std.unicode.utf8Decode(try text.take(len)) catch return error.InvalidInput;
        }
        if (attr_left == 0) {
            attr_left = try attrs.run();
            attr = try attrs.integer(u64);
            if (attr_left == 0 or attr_left > count - index or (attr & 3 <= 1 and attr & cp_mask != 0)) return error.InvalidInput;
        }
        if (attr & 3 > 1 and cp != 0) return error.InvalidInput;
        cell.* = attr | (@as(u64, cp) << 2);
        text_left -= 1;
        attr_left -= 1;
    }
    if (text_left != 0 or attr_left != 0 or text.at != text.bytes.len or attrs.at != attrs.bytes.len) return error.InvalidInput;
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

test "compact history rejects malformed dimensions and every truncation" {
    var page = try native.Page.init(.{ .cols = 12, .rows = 9, .styles = 8, .grapheme_bytes = 128, .string_bytes = 128 });
    defer page.deinit();
    page.getRowAndCell(2, 3).cell.* = .init(0x754c);
    const encoded = try std.testing.allocator.alloc(u8, page.memory.len * 2);
    defer std.testing.allocator.free(encoded);
    const restored = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), page.memory.len);
    defer std.heap.page_allocator.free(restored);
    var table: lz4.HashTable = undefined;
    const length = try encode(&page, encoded, &table);
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
