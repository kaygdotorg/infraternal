//! Callback-free logger for private session images that never install a C log callback.
const std = @import("std");

/// Discards engine log messages so unused formatting code is removed from the session image.
pub fn logFn(
    comptime _: std.log.Level,
    comptime _: @TypeOf(.EnumLiteral),
    comptime _: []const u8,
    _: anytype,
) void {}
