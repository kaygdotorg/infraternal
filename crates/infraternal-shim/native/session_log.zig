//! Private session images have no logging callbacks; omit their unused formatters (D243).
//! Parser checks and returned initialization/resize errors remain with the pinned engine.
const std = @import("std");

pub fn logFn(
    comptime _: std.log.Level,
    comptime _: @TypeOf(.EnumLiteral),
    comptime _: []const u8,
    _: anytype,
) void {}
