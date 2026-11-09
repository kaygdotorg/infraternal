#!/usr/bin/env python3
"""Apply the small D270 adapter patches required by libghostty-vt 1.0 [#419].

The public C ABI owns ordinary terminal operations. These patches are limited
to our bounded snapshot adapter, final-link section garbage collection,
callback-free private session logging, shared-host page accounting, and the
optional in-process cold-history experiment. Every upstream edit is guarded so
release source drift fails the build instead of silently changing behavior.
"""

from pathlib import Path
import sys


def replace_once(source: str, before: str, after: str, purpose: str) -> str:
    """Apply one reviewed source edit and reject an unexpected upstream shape."""
    count = source.count(before)
    if count != 1:
        raise SystemExit(f"expected one {purpose} boundary, found {count}")
    return source.replace(before, after, 1)


def patch_static_section_gc(source_root: Path) -> None:
    """Emit per-function/data sections so static consumers can discard unused exports."""
    path = source_root / "src/build/GhosttyLibVt.zig"
    source = path.read_text()
    source = replace_once(
        source,
        "        lib.bundle_compiler_rt = true;\n",
        "        lib.bundle_compiler_rt = true;\n"
        "        lib.link_function_sections = true;\n"
        "        lib.link_data_sections = true;\n",
        "static VT section garbage collection",
    )
    path.write_text(source)


def patch_session_image_logging(source_root: Path) -> None:
    """Drop logging callbacks only from private session images that never register one."""
    path = source_root / "src/lib_vt.zig"
    source = path.read_text()
    source = replace_once(
        source,
        '        @export(&c.sys_log_stderr, .{ .name = "ghostty_sys_log_stderr" });\n',
        "",
        "private session stderr logger export",
    )
    source = replace_once(
        source,
        '        @export(&c.sys_set, .{ .name = "ghostty_sys_set" });\n',
        "",
        "private session system callback setter export",
    )
    source = replace_once(
        source,
        '@import("terminal/c/sys.zig").logFn',
        '@import("infraternal_session_log.zig").logFn',
        "private session callback-free logger",
    )
    path.write_text(source)


def patch_shared_host(source_root: Path) -> None:
    """Route Linux page memory through the session allocator and cap resize work."""
    path = source_root / "src/terminal/PageList.zig"
    source = path.read_text()

    # The library's default pool uses demand-paged mappings. Shared-host
    # sessions instead need every page in the same hard per-user budget as
    # parser and style allocations, with exact ownership at teardown.
    start = source.index("const PagePool = if (wasm_page_pool)")
    end = source.index("\n\n/// List of pins", start)
    pool = '''const PagePool = @import("../infraternal_memory.zig").PagePool(
    [std_size]u8,
    .fromByteUnits(std.heap.page_size_min),
);'''
    source = source[:start] + pool + source[end:]
    source = replace_once(
        source,
        "if (!builtin.target.os.tag.isDarwin()) return std.heap.page_allocator;",
        'if (!builtin.target.os.tag.isDarwin()) return @import("../infraternal_memory.zig").pageAllocator(alloc);',
        "shared-host page allocator",
    )
    source = replace_once(
        source,
        "const page_preheat = 4;",
        "const page_preheat = 1;",
        "shared-host page preheat",
    )
    source = replace_once(
        source,
        "var node_pool = try NodePool.initCapacity(gen_alloc, gen_alloc, node_preheat);",
        "var node_pool = try NodePool.initCapacity(gen_alloc, @import(\"../infraternal_memory.zig\").structureAllocator(gen_alloc), node_preheat);",
        "shared-host page-list node allocator",
    )

    # PageList's own byte limit cannot see the host-wide cap. Check the
    # session allocator before a growth write; when a pooled page would not
    # fit, the existing oldest-page reuse path keeps the visible screen exact.
    source = replace_once(
        source,
        "const new_size = if (pooled) PagePool.item_size else layout.total_size;",
        "const new_size = if (pooled) PagePool.item_size else layout.total_size;\n"
        "    const allocation_fits = if (pooled)\n"
        "        self.pool.pages.canCreate()\n"
        "    else\n"
        '        @import("../infraternal_memory.zig").fits(self.pool.pages.allocator, new_size);',
        "shared-host growth fit check",
    )
    source = replace_once(
        source,
        "self.page_size + new_size > self.limits.max(.bytes))",
        "(self.page_size + new_size > self.limits.max(.bytes) or\n"
        "            !allocation_fits))",
        "shared-host oldest-page reuse condition",
    )

    # Wide pages and compression scratch bypass the standard pool. Probe the
    # allocation before mutating the page list so expected budget pressure is
    # handled by the existing rollback or optional-compression path.
    source = replace_once(
        source,
        "            break :buf try page_alloc.alignedAlloc(\n"
        "                u8,\n"
        "                .fromByteUnits(std.heap.page_size_min),\n"
        "                layout.total_size,\n"
        "            );",
        '            if (!@import("../infraternal_memory.zig").fits(page_alloc, layout.total_size)) return error.OutOfMemory;\n'
        "            break :buf try page_alloc.alignedAlloc(\n"
        "                u8,\n"
        "                .fromByteUnits(std.heap.page_size_min),\n"
        "                layout.total_size,\n"
        "            );",
        "shared-host initial wide page allocation",
    )
    source = replace_once(
        source,
        "    } else try page_alloc.alignedAlloc(\n"
        "        u8,\n"
        "        .fromByteUnits(std.heap.page_size_min),\n"
        "        layout.total_size,\n"
        "    );",
        '    } else block: {\n'
        '        if (!@import("../infraternal_memory.zig").fits(page_alloc, layout.total_size)) return error.OutOfMemory;\n'
        "        break :block try page_alloc.alignedAlloc(\n"
        "            u8,\n"
        "            .fromByteUnits(std.heap.page_size_min),\n"
        "            layout.total_size,\n"
        "        );\n"
        "    };",
        "shared-host wide page allocation",
    )
    source = replace_once(
        source,
        "        if (required <= std_size) {\n"
        "            const memory = try pool.pages.create();",
        "        if (required <= std_size) {\n"
        "            if (!pool.pages.canCreate()) return error.OutOfMemory;\n"
        "            const memory = try pool.pages.create();",
        "shared-host compression scratch allocation",
    )
    source = replace_once(
        source,
        "        const page_alloc = pool.pages.allocator;\n"
        "        return .{ .allocated = try page_alloc.alignedAlloc(\n"
        "            u8,\n"
        "            .fromByteUnits(std.heap.page_size_min),\n"
        "            raw_len,\n"
        "        ) };",
        '        const page_alloc = pool.pages.allocator;\n'
        '        if (!@import("../infraternal_memory.zig").fits(page_alloc, raw_len)) return error.OutOfMemory;\n'
        "        return .{ .allocated = try page_alloc.alignedAlloc(\n"
        "            u8,\n"
        "            .fromByteUnits(std.heap.page_size_min),\n"
        "            raw_len,\n"
        "        ) };",
        "shared-host oversized compression scratch",
    )

    # A wider reflow may allocate its full destination before PageList can
    # prune. Discard only oldest complete history pages that the requested
    # geometry cannot keep within the configured history share.
    resize_before = (
        "    self.page_compression.reset();\n"
        "    self.page_compression.markActivity();\n\n"
        "    if (comptime std.debug.runtime_safety) {\n"
    )
    resize_after = (
        "    self.page_compression.reset();\n"
        "    self.page_compression.markActivity();\n"
        "    if (opts.cols) |cols| self.trimHistoryForCols(cols, opts.rows orelse self.rows, opts.reflow);\n\n"
        "    if (comptime std.debug.runtime_safety) {\n"
    )
    source = replace_once(source, resize_before, resize_after, "shared-host resize pretrim")
    trim_anchor = "fn resizeCols("
    if source.count(trim_anchor) != 1:
        raise SystemExit("expected one shared-host resize helper insertion point")
    trim = '''/// Shared-host history bound for a wider geometry [D270, #205]. Whole
/// pages from the oldest end only, never a page with active rows, so
/// tracked pins and the cursor keep their rows.
fn trimHistoryForCols(self: *PageList, cols: size.CellCountInt, new_rows: size.CellCountInt, reflow: bool) void {
    if (cols <= self.cols) return;
    const max = @max(self.limits.bytes.explicit, Limits.minMaxSize(cols, new_rows));
    var bound: usize = 0;
    var it = self.pages.first;
    while (it) |node| : (it = node.next) bound +|= widenedNodeBytes(node, cols);
    if (bound <= max) return;
    const history = self.total_rows - self.rows;
    const keep_history = if (new_rows > self.rows) new_rows - self.rows else 0;
    const droppable_history = history -| keep_history;
    var erase: usize = 0;
    if (!reflow) {
        it = self.pages.first;
        while (it) |node| : (it = node.next) {
            if (bound <= max or erase + node.rows() > droppable_history) break;
            erase += node.rows();
            bound -|= widenedNodeBytes(node, cols);
        }
    } else {
        const shape = widenedShape(self.pages.first.?.capacity(), cols);
        var line: usize = 0;
        var rows: usize = 0;
        it = self.pages.first;
        while (it) |node| : (it = node.next) rows += reflowedRows(node, cols, &line);
        rows += lineRows(line, cols);
        line = 0;
        it = self.pages.first;
        while (it) |node| : (it = node.next) {
            const bytes = (std.math.divCeil(usize, rows, shape.rows) catch unreachable) * shape.bytes;
            if (bytes <= max or erase + node.rows() > droppable_history) break;
            erase += node.rows();
            rows -|= reflowedRows(node, cols, &line);
        }
    }
    if (erase == 0) return;
    if (self.pin(.{ .history = .{ .y = @intCast(erase - 1) } })) |last| {
        var boundary = last;
        var next = boundary.down(1);
        while (next) |p| {
            if (!p.rowAndCell().row.wrap_continuation) break;
            if (erase >= droppable_history) {
                var line_start = boundary;
                var line_rows: usize = 1;
                while (line_start.rowAndCell().row.wrap_continuation) {
                    const previous = line_start.up(1) orelse break;
                    line_start = previous;
                    line_rows += 1;
                }
                erase -|= line_rows;
                break;
            }
            erase += 1;
            boundary = p;
            next = p.down(1);
        }
    }
    if (erase == 0) return;
    self.eraseHistory(.{ .history = .{ .y = @intCast(erase - 1) } });
}

const WidenedShape = struct { rows: usize, bytes: usize };

/// Rows per page and bytes per page after widening the page capacity.
fn widenedShape(capacity: Capacity, cols: size.CellCountInt) WidenedShape {
    const cap = capacity.adjust(.{ .cols = cols }) catch wide: {
        var cap = capacity;
        cap.cols = cols;
        cap.rows = @max(1, @min(capacity.rows, std_capacity.rows));
        break :wide cap;
    };
    const total = Page.layout(cap).total_size;
    return .{ .rows = cap.rows, .bytes = if (total <= std_size) PagePool.item_size else total };
}

fn widenedNodeBytes(node: *const List.Node, cols: size.CellCountInt) usize {
    const capacity = node.capacity();
    if (capacity.cols >= cols) return switch (node.owned) {
        .pool => PagePool.item_size,
        .heap => node.metadata().memory.len,
    };
    const shape = widenedShape(capacity, cols);
    return (std.math.divCeil(usize, node.rows(), shape.rows) catch unreachable) * shape.bytes;
}

/// Rows one logical line of `cells` takes at the requested width.
fn lineRows(cells: usize, cols: size.CellCountInt) usize {
    return @max(1, std.math.divCeil(usize, cells, cols) catch unreachable);
}

/// Rows the lines ending in `node` take after reflow to `cols`.
fn reflowedRows(node: *List.Node, cols: size.CellCountInt, line: *usize) usize {
    const page = node.page();
    var rows: usize = 0;
    for (page.rows.ptr(page.memory)[0..page.size.rows]) |*row| {
        if (!row.wrap_continuation and line.* > 0) {
            rows += lineRows(line.*, cols);
            line.* = 0;
        }
        var used: usize = page.size.cols;
        if (!row.wrap) {
            const cells = page.getCells(row);
            while (used > 0 and cells[used - 1].isEmpty()) used -= 1;
        }
        if (used == 0 and !row.wrap_continuation and line.* == 0) {
            rows += 1;
            continue;
        }
        line.* += used;
    }
    return rows;
}

'''
    source = source.replace(trim_anchor, trim + trim_anchor, 1)

    path.write_text(source)

    # The smaller shared-host page shape limits the per-session screen floor;
    # cell state and the upstream page/reflow algorithms are unchanged.
    page_path = source_root / "src/terminal/page.zig"
    page = page_path.read_text()
    page = replace_once(
        page,
        "pub const std_capacity: Capacity = .{\n    .cols = 215,\n    .rows = 215,",
        "pub const std_capacity: Capacity = .{\n    .cols = 80,\n    .rows = 32,",
        "shared-host standard page capacity",
    )
    page_path.write_text(page)


def patch_lz4_safety(source_root: Path) -> None:
    """Keep LZ4 bounds checks enabled when release code restores compressed pages."""
    path = source_root / "src/terminal/compress/lz4.zig"
    source = path.read_text()
    heads = (
        "pub fn decompress(input: []const u8, output: []u8) DecompressError!usize {\n",
        "fn copyMatch(output: []u8, op_: usize, offset: usize, match_len: usize) void {\n",
    )
    for head in heads:
        source = replace_once(source, head, head + "    @setRuntimeSafety(true);\n", "release LZ4 bounds check")
    for name in ("readIntAt", "writeIntAt", "copyIntAt"):
        start = source.find(f"inline fn {name}(")
        if start < 0:
            raise SystemExit(f"missing release LZ4 helper: {name}")
        body = source.find("{\n", start)
        # `body` points at the opening brace, so include it in the boundary check.
        if body < 0 or source[start : body + 1].count("{") != 1:
            raise SystemExit(f"invalid release LZ4 helper boundary: {name}")
        source = source[: body + 2] + "    @setRuntimeSafety(true);\n" + source[body + 2 :]
    path.write_text(source)


def patch_compact_history(source_root: Path) -> None:
    """Use the private reversible text codec only when its Cargo feature is set."""
    path = source_root / "src/terminal/compress/Page.zig"
    source = path.read_text()
    source = replace_once(
        source,
        "encoded: []u8,",
        "encoded: []u8,\ntext_runs: bool = false,",
        "compact-history state field",
    )
    start = source.find("    const encoded_len = lz4.compress(")
    if start < 0:
        raise SystemExit("missing compact-history codec boundary")
    end = source.find("\n    // requiredScratch already", start)
    if end < 0:
        raise SystemExit("missing compact-history codec tail")
    fallback = source[start:end].replace("    const encoded_len = ", "        break :fallback ", 1)
    replacement = (
        "    var text_runs = true;\n"
        "    const encoded_len = @import(\"../../infraternal_history.zig\").encode(source, scratch[0..required], table) catch fallback: {\n"
        "        text_runs = false;\n"
        f"{fallback}\n"
        "    };\n"
        '    const encoded_allocator = @import("../../infraternal_memory.zig").historyAllocator(alloc);\n'
    )
    source = source[:start] + replacement + source[end:]
    source = replace_once(
        source,
        ".encoded = try alloc.dupe(u8, scratch[0..encoded_len]),",
        ".encoded = try encoded_allocator.dupe(u8, scratch[0..encoded_len]),\n"
        "        .text_runs = text_runs,",
        "compact-history encoded storage",
    )
    source = replace_once(
        source,
        ".alloc = alloc,",
        ".alloc = encoded_allocator,",
        "compact-history allocator ownership",
    )
    before = "    _ = try lz4.decompress(self.encoded, result.memory);"
    if source.count(before) != 2:
        raise SystemExit("expected two compact-history restore boundaries")
    after = '''    if (self.text_runs) {
        @import("../../infraternal_history.zig").decode(self.encoded, &self.page, result.memory) catch return error.InvalidOffset;
    } else {
        _ = try lz4.decompress(self.encoded, result.memory);
    }'''
    source = source.replace(before, after)
    path.write_text(source)


def main() -> None:
    """Patch the verified extraction according to the Cargo feature set."""
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: patch-libghostty-vt.py SOURCE_DIR SHARED_HOST COMPACT_HISTORY SESSION_IMAGE"
        )
    source_root = Path(sys.argv[1])
    shared_host = bool(sys.argv[2])
    compact_history = bool(sys.argv[3])
    session_image = bool(sys.argv[4])
    patch_static_section_gc(source_root)
    if session_image:
        patch_session_image_logging(source_root)
    if shared_host:
        # Shared-host restore runs release decompression under its bounded
        # allocator; ordinary builds keep upstream's hot LZ4 path unchanged.
        patch_lz4_safety(source_root)
    if shared_host:
        patch_shared_host(source_root)
    if compact_history:
        patch_compact_history(source_root)


if __name__ == "__main__":
    main()
