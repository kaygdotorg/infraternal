//! Routes native screen-pool allocations into the session's page budget [D270].
//! The default build does not import this adapter. Its caller supplies the C
//! allocator retained by terminal_new; the C ABI pointer remains stable until
//! terminal destruction. usize max cannot be a userspace return address, so it
//! tags pool requests separately from payload/style/image allocations.
const std = @import("std");
const C = @import("terminal/lib.zig").alloc.Allocator;
const marker = std.math.maxInt(usize);
const mem = @import("terminal/mem.zig");

pub fn pageAllocator(allocator: std.mem.Allocator) std.mem.Allocator {
    // The public C API permits a null allocator, which selects the native
    // default allocator. Keep that path unchanged; shared-host engines always
    // supply the retained C allocator and therefore take the tagged path.
    if (allocator.vtable != &C.zig_vtable) return std.heap.page_allocator;
    return .{ .ptr = allocator.ptr, .vtable = &vtable };
}

/// Encoded cold history has its own retention share. It cannot consume the
/// smaller parser/title/style budget merely because many pages are retained.
pub fn historyAllocator(allocator: std.mem.Allocator) std.mem.Allocator {
    if (allocator.vtable != &C.zig_vtable) return allocator;
    return .{ .ptr = allocator.ptr, .vtable = &history_vtable };
}
/// Page-list nodes: one per page, so their count follows the pages the
/// history share bounds, not the parser/title/style data the smaller
/// ordinary cap is for. With 80x32 standard pages a long history holds many
/// nodes; charging them as ordinary data refused a widening reflow.
pub fn structureAllocator(allocator: std.mem.Allocator) std.mem.Allocator {
    if (allocator.vtable != &C.zig_vtable) return allocator;
    return .{ .ptr = allocator.ptr, .vtable = &structure_vtable };
}
const structure_vtable: std.mem.Allocator.VTable = .{
    .alloc = structureAlloc,
    .resize = resize,
    .remap = remap,
    .free = structureFree,
};
fn structureAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    return C.zig_vtable.alloc(ctx, len, alignment, marker - 3);
}
fn structureFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, _: usize) void {
    C.zig_vtable.free(ctx, memory, alignment, marker - 3);
}
const history_vtable: std.mem.Allocator.VTable = .{
    .alloc = historyAlloc,
    .resize = resize,
    .remap = remap,
    .free = historyFree,
};
fn historyAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    return C.zig_vtable.alloc(ctx, len, alignment, marker - 1);
}
fn historyFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, _: usize) void {
    C.zig_vtable.free(ctx, memory, alignment, marker - 1);
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

/// Asks the session's allocator whether one more screen-pool item of `len`
/// bytes fits its reservation, without allocating and without counting a
/// refusal. Growth uses the answer to recycle its oldest history page
/// instead of requesting memory that would be refused: a refusal mid-write
/// would drop terminal state, while recycling keeps every visible cell exact.
/// The probe travels through the resize callback with its own tag because
/// the C allocator ABI has no query entry; an empty slice is never resized.
pub fn fits(page_alloc: std.mem.Allocator, len: usize) bool {
    if (page_alloc.vtable != &vtable) return true;
    var none: [0]u8 = .{};
    return C.zig_vtable.resize(page_alloc.ptr, &none, .fromByteUnits(std.heap.page_size_min), len, marker - 2);
}

/// Screen-pool storage for shared-host terminals [D270, #205].
///
/// Every item is its own page-aligned allocation and a released item beyond
/// a small reserve returns to the session allocator at once. Retained bytes
/// therefore follow the live page count: a geometry storm or erased history
/// gives its memory back, and growth asks for exactly one item at a time, so
/// the history share is reachable without a geometric chunk crossing the
/// reservation first. All items are tracked so reset and deinit release
/// them without walking terminal pages. Free items keep the upstream
/// invariant: zero apart from the leading free-list pointer.
pub fn PagePool(comptime Item: type, comptime alignment: std.mem.Alignment) type {
    return struct {
        const Pool = @This();
        pub const item_size = @sizeOf(Item);
        const ItemPtr = *align(alignment.toByteUnits()) Item;
        const Free = struct { next: ?*Free };
        // Reflow destroys an old page right before it creates the next one,
        // and compression borrows one scratch item; two cover both without
        // a mapping round trip per page.
        const reserve = 2;
        comptime {
            std.debug.assert(item_size >= @sizeOf(Free));
            std.debug.assert(alignment.toByteUnits() >= @alignOf(Free));
        }

        /// Page backing allocator, matching the public field used by the 1.0 pool.
        allocator: std.mem.Allocator,
        gen: std.mem.Allocator,
        items: std.ArrayList(ItemPtr) = .empty,
        free_list: ?*Free = null,
        free_count: usize = 0,

        /// Creates a tracked page pool with `preheat` zero-filled items.
        pub fn initCapacity(gen: std.mem.Allocator, page: std.mem.Allocator, preheat: usize) error{OutOfMemory}!Pool {
            var pool: Pool = .{
                .allocator = page,
                // Pointer bookkeeping grows with history pages, so it follows
                // the page share rather than the smaller parser allocation cap.
                .gen = structureAllocator(gen),
            };
            errdefer pool.deinit();
            for (0..preheat) |_| pool.push(try pool.allocNew());
            return pool;
        }

        /// Number of free buffers, exposed for the upstream pool tests.
        pub fn freeCount(pool: *const Pool) usize {
            return pool.free_count;
        }

        pub fn deinit(pool: *Pool) void {
            while (pool.items.items.len > 0) {
                pool.release(pool.items.items[pool.items.items.len - 1]);
            }
            pool.items.deinit(pool.gen);
            pool.* = undefined;
        }

        /// Free-list item or one new mapping; at most one allocation each.
        pub fn canCreate(pool: *const Pool) bool {
            return pool.free_list != null or fits(pool.allocator, item_size);
        }

        pub fn create(pool: *Pool) error{OutOfMemory}!ItemPtr {
            if (pool.free_list) |node| {
                pool.free_list = node.next;
                pool.free_count -= 1;
                return @ptrCast(@alignCast(node));
            }
            return pool.allocNew();
        }

        pub fn destroy(pool: *Pool, item: ItemPtr) void {
            if (pool.free_count < reserve) return pool.push(item);
            pool.release(item);
        }

        /// Immediately returns an item to its backing allocator and removes it
        /// from pool bookkeeping, as PageList teardown expects in 1.0.
        pub fn release(pool: *Pool, item: ItemPtr) void {
            var index = pool.items.items.len;
            while (index > 0) {
                index -= 1;
                if (pool.items.items[index] == item) break;
            } else unreachable;
            _ = pool.items.swapRemove(index);
            pool.allocator.rawFree(item, alignment, @returnAddress());
        }

        /// Invalidates every item. Retained items are zeroed for reuse,
        /// as the screen expects fresh pages to be.
        pub fn reset(pool: *Pool, mode: std.heap.ArenaAllocator.ResetMode) bool {
            const keep_bytes: usize = switch (mode) {
                .free_all => 0,
                .retain_capacity => std.math.maxInt(usize),
                .retain_with_limit => |limit| limit,
            };
            const keep = @min(keep_bytes / item_size, pool.items.items.len);
            while (pool.items.items.len > keep) {
                pool.release(pool.items.items[pool.items.items.len - 1]);
            }
            pool.free_list = null;
            pool.free_count = 0;
            for (pool.items.items) |item| {
                if (!mem.decommit(.zero, item, item.len)) @memset(item, 0);
                pool.push(item);
            }
            return true;
        }

        fn allocNew(pool: *Pool) error{OutOfMemory}!ItemPtr {
            try pool.items.ensureUnusedCapacity(pool.gen, 1);
            // Fresh anonymous mappings are zero-filled.
            const raw = pool.allocator.rawAlloc(item_size, alignment, @returnAddress()) orelse
                return error.OutOfMemory;
            const item: ItemPtr = @ptrCast(@alignCast(raw));
            pool.items.appendAssumeCapacity(item);
            return item;
        }

        fn push(pool: *Pool, item: ItemPtr) void {
            const node: *Free = @ptrCast(@alignCast(item));
            node.* = .{ .next = pool.free_list };
            pool.free_list = node;
            pool.free_count += 1;
        }

    };
}

/// Pages one `cols` x `rows` screen occupies at the shared-host page shape,
/// laid out as PageList.init lays out its active area; `page_len` receives
/// each page's payload bytes (a pool item, or one exact wider page). The
/// host keeps that many bytes per screen out of its shared pool [#205].
pub fn screenPages(cols: u16, rows: u16, page_len: *usize) callconv(.c) usize {
    const page = @import("terminal/page.zig");
    const pool_len = page.Page.layout(page.std_capacity).total_size;
    const cap = page.std_capacity.adjust(.{ .cols = @max(cols, 1) }) catch wide: {
        var cap = page.std_capacity;
        cap.cols = @max(cols, 1);
        break :wide cap;
    };
    const len = page.Page.layout(cap).total_size;
    page_len.* = if (len <= pool_len) pool_len else len;
    return std.math.divCeil(usize, @max(rows, 1), cap.rows) catch unreachable;
}
