const std = @import("std");

pub fn Queue(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        items: std.ArrayList(T),
        read_index: usize = 0,

        pub fn init(allocator: std.mem.Allocator) @This() {
            return .{
                .allocator = allocator,
                .items = .{},
            };
        }

        pub fn deinit(self: *@This()) void {
            self.items.deinit(self.allocator);
        }

        pub fn write(self: *@This(), item: T) !void {
            try self.items.append(self.allocator, item);
        }

        pub fn read(self: *@This()) !?T {
            if (self.read_index >= self.items.items.len) return null;
            const item = self.items.items[self.read_index];
            self.read_index += 1;
            return item;
        }
    };
}
