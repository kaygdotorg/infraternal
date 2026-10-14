//! Routes native screen-pool allocations into the session's page budget [D270].
//! The default build does not import this adapter. Its caller supplies the C
//! allocator retained by terminal_new; the C ABI pointer remains stable until
//! terminal destruction. usize max cannot be a userspace return address, so it
//! tags pool requests separately from payload/style/image allocations.
const std = @import("std");
const C = @import("terminal/lib.zig").alloc.Allocator;
const marker = std.math.maxInt(usize);

pub fn pageAllocator(allocator: std.mem.Allocator) std.mem.Allocator {
    std.debug.assert(allocator.vtable == &C.zig_vtable);
    return .{ .ptr = allocator.ptr, .vtable = &vtable };
}
const vtable: std.mem.Allocator.VTable = .{
    .alloc = alloc,
    .resize = resize,
    .remap = remap,
    .free = free,
};
fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    return C.zig_vtable.alloc(ctx, len, alignment, marker);
}
fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, _: usize) bool {
    return C.zig_vtable.resize(ctx, memory, alignment, new_len, marker);
}
fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, _: usize) ?[*]u8 {
    return C.zig_vtable.remap(ctx, memory, alignment, new_len, marker);
}
fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, _: usize) void {
    C.zig_vtable.free(ctx, memory, alignment, marker);
}
