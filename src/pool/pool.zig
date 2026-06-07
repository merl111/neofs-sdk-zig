const std = @import("std");
const clock = @import("../util/clock.zig");
const client_mod = @import("../client/client.zig");
const object_stream = @import("../client/object_stream.zig");
const session_mod = @import("../session/token.zig");
const session_v2 = @import("../session/v2/token.zig");
const sampler_mod = @import("sampler.zig");
const sliding_window = @import("sliding_window.zig");
const session_cache = @import("session_cache.zig");
const user = @import("../user/id.zig");
const accounting = @import("../accounting/decimal.zig");
const container = @import("../container/container.zig");

pub const Node = struct {
    endpoint: []const u8,
    priority: i32 = 0,
    weight: f64 = 1.0,
};

pub const InitParams = struct {
    session_duration_epochs: u64 = 100,
    session_v2_duration_secs: u64 = 3600,
    error_threshold: i64 = 100,
    error_window_ns: i64 = 15 * std.time.ns_per_s,
    rebalance_interval_ns: i64 = 25 * std.time.ns_per_s,
    healthcheck_timeout_ms: u64 = 4000,
    use_v2_sessions: bool = false,
    disable_session_v2_delegation: bool = false,
};

pub const Pool = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    params: InitParams,
    nodes: std.ArrayList(Node),
    inner_pools: std.ArrayList(InnerPool),
    cache: session_cache.SessionCache,
    node_session_cache: std.StringHashMap(session_mod.Token),
    active_client: client_mod.Client,
    active_endpoint: ?[]const u8 = null,
    rebalance_thread: ?std.Thread = null,
    stop_flag: std.atomic.Value(bool) = .init(false),

    const InnerPool = struct {
        priority: i32,
        clients: std.ArrayList(NodeClient),
        sampler: ?sampler_mod.Sampler = null,

        fn deinit(self: *InnerPool, allocator: std.mem.Allocator) void {
            for (self.clients.items) |*nc| nc.deinit();
            self.clients.deinit(allocator);
            if (self.sampler) |*s| s.deinit(allocator);
        }
    };

    const NodeClient = struct {
        endpoint: []const u8,
        client: client_mod.Client,
        healthy: bool = true,
        weight: f64,
        monitor: sliding_window.SlidingWindow,

        fn init(allocator: std.mem.Allocator, endpoint: []const u8, weight: f64, threshold: i64, window_ns: i64) NodeClient {
            return .{
                .endpoint = endpoint,
                .client = client_mod.Client.init(allocator),
                .weight = weight,
                .monitor = sliding_window.SlidingWindow.init(window_ns, threshold),
            };
        }

        fn deinit(self: *NodeClient) void {
            self.client.deinit();
        }

        fn markError(self: *NodeClient) void {
            if (!self.monitor.allow()) self.healthy = false;
        }

        fn probeHealth(self: *NodeClient, io: std.Io, timeout_ms: u64) bool {
            const tls = std.mem.startsWith(u8, self.endpoint, "grpcs://");
            self.client.close();
            self.client.dial(io, self.endpoint, tls, timeout_ms) catch {
                self.healthy = false;
                return false;
            };
            _ = self.client.endpointInfo() catch {
                self.healthy = false;
                return false;
            };
            self.healthy = true;
            return true;
        }
    };

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Pool {
        return initWithParams(allocator, io, .{});
    }

    pub fn initWithParams(allocator: std.mem.Allocator, io: std.Io, params: InitParams) Pool {
        return .{
            .allocator = allocator,
            .io = io,
            .params = params,
            .nodes = .empty,
            .inner_pools = .empty,
            .cache = session_cache.SessionCache.init(allocator, 700),
            .node_session_cache = std.StringHashMap(session_mod.Token).init(allocator),
            .active_client = client_mod.Client.init(allocator),
        };
    }

    pub fn deinit(self: *Pool) void {
        self.stop_flag.store(true, .release);
        if (self.rebalance_thread) |t| {
            t.join();
            self.rebalance_thread = null;
        }
        if (self.active_endpoint) |ep| self.allocator.free(ep);
        self.active_client.deinit();
        for (self.inner_pools.items) |*ip| ip.deinit(self.allocator);
        self.inner_pools.deinit(self.allocator);
        for (self.nodes.items) |node| self.allocator.free(node.endpoint);
        self.nodes.deinit(self.allocator);
        self.cache.deinit();
        var it = self.node_session_cache.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.node_session_cache.deinit();
    }

    pub fn addNode(self: *Pool, node: Node) !void {
        try self.nodes.append(self.allocator, .{
            .endpoint = try self.allocator.dupe(u8, node.endpoint),
            .priority = node.priority,
            .weight = node.weight,
        });
    }

    pub fn dial(self: *Pool) !void {
        if (self.nodes.items.len == 0) return error.EmptyPool;
        try self.buildInnerPools();
        const nc = try self.selectNodeClient();
        if (self.active_endpoint) |ep| self.allocator.free(ep);
        self.active_client.close();
        self.active_client = client_mod.Client.init(self.allocator);
        const tls = std.mem.startsWith(u8, nc.endpoint, "grpcs://");
        try self.active_client.dial(self.io, nc.endpoint, tls, 10_000);
        self.active_endpoint = try self.allocator.dupe(u8, nc.endpoint);
        if (self.rebalance_thread == null and self.nodes.items.len > 1) {
            self.rebalance_thread = try std.Thread.spawn(.{}, rebalanceLoop, .{self});
        }
    }

    pub fn close(self: *Pool) void {
        self.stop_flag.store(true, .release);
        self.active_client.deinit();
        self.active_client = client_mod.Client.init(self.allocator);
    }

    pub fn withinContainerSession(
        self: *Pool,
        endpoint: []const u8,
        container_id: [32]u8,
        verb: session_mod.Verb,
        signer_key: []const u8,
    ) !session_mod.Token {
        if (self.params.use_v2_sessions) {
            return self.withinContainerSessionV2(endpoint, container_id, signer_key);
        }
        return self.withinContainerSessionV1(endpoint, container_id, verb, signer_key);
    }

    pub fn withinContainerSessionV1(
        self: *Pool,
        endpoint: []const u8,
        container_id: [32]u8,
        verb: session_mod.Verb,
        signer_key: []const u8,
    ) !session_mod.Token {
        const cache_key = try std.fmt.allocPrint(self.allocator, "{s}{s}{d}{d}", .{
            endpoint,
            signer_key,
            @intFromEnum(verb),
            std.mem.readInt(u64, container_id[0..8], .little),
        });

        if (self.cache.getV1(cache_key)) |cached| {
            self.allocator.free(cache_key);
            return cached;
        }

        const base_key = try std.fmt.allocPrint(self.allocator, "{s}:{s}", .{ endpoint, signer_key });
        defer self.allocator.free(base_key);

        const base = blk: {
            if (self.node_session_cache.get(base_key)) |tok| break :blk tok;
            const epoch = self.active_client.networkInfo() catch 0;
            const exp = epoch + self.params.session_duration_epochs;
            break :blk session_mod.new(.put, epoch, exp);
        };

        var bound = base;
        bound.verb = verb;
        try self.cache.putV1(cache_key, bound);
        return bound;
    }

    pub fn withinContainerSessionV2(
        self: *Pool,
        endpoint: []const u8,
        container_id: [32]u8,
        signer_key: []const u8,
    ) !session_mod.Token {
        const cache_key = try std.fmt.allocPrint(self.allocator, "{s}{s}{x}", .{
            endpoint,
            signer_key,
            std.mem.readInt(u64, container_id[0..8], .little),
        });

        if (self.cache.getV2(cache_key)) |_| {
            self.allocator.free(cache_key);
            return session_mod.Token{
                .id = undefined,
                .verb = .put,
                .nbf_epoch = 0,
                .exp_epoch = 0,
            };
        }

        const tok = session_v2.Token{
            .verb = .object_put,
            .issuer = endpoint,
            .target = "",
            .iat = @intCast(clock.timestamp()),
            .nbf = @intCast(clock.timestamp()),
            .exp = @intCast(clock.timestamp() + @as(i64, @intCast(self.params.session_v2_duration_secs))),
        };
        try self.cache.putV2(cache_key, tok);
        return session_mod.Token{
            .id = undefined,
            .verb = .put,
            .nbf_epoch = 0,
            .exp_epoch = @intCast(tok.exp),
        };
    }

    pub fn objectPutInit(self: *Pool, container_id: [32]u8, signer_key: []const u8) !struct { session_mod.Token, object_stream.ObjectWriter } {
        const ep = self.active_endpoint orelse return error.NotConnected;
        const tok = try self.withinContainerSession(ep, container_id, .put, signer_key);
        const writer = try self.active_client.objectPutInit(null);
        return .{ tok, writer };
    }

    pub fn objectGetInit(
        self: *Pool,
        container_id: [32]u8,
        object_id: [32]u8,
        signer_key: []const u8,
    ) !struct { session_mod.Token, @import("../proto/gen/object/types.pb.zig").GetResponse, object_stream.PayloadReader } {
        const ep = self.active_endpoint orelse return error.NotConnected;
        const tok = try self.withinContainerSession(ep, container_id, .get, signer_key);
        const result = try self.active_client.objectGetInit(container_id, object_id);
        return .{ tok, result.header, result.reader };
    }

    pub fn reportNodeError(self: *Pool, endpoint: []const u8) !void {
        for (self.inner_pools.items) |*ip| {
            for (ip.clients.items) |*nc| {
                if (std.mem.eql(u8, nc.endpoint, endpoint)) {
                    nc.markError();
                    self.cache.deleteByPrefix(endpoint);
                    return;
                }
            }
        }
    }

    pub fn checkSessionTokenErr(self: *Pool, err: anyerror, endpoint: []const u8) void {
        _ = err;
        self.cache.deleteByPrefix(endpoint);
        var it = self.node_session_cache.keyIterator();
        while (it.next()) |key| {
            if (std.mem.startsWith(u8, key.*, endpoint)) {
                _ = self.node_session_cache.remove(key.*);
            }
        }
    }

    pub fn containerPut(self: *Pool, cont: container.Container) ![32]u8 {
        return self.active_client.containerPut(cont);
    }

    pub fn containerGet(self: *Pool, id: [32]u8) !container.Container {
        return self.active_client.containerGet(id);
    }

    pub fn containerList(self: *Pool, owner: user.ID) ![][32]u8 {
        return self.active_client.containerList(owner);
    }

    pub fn containerDelete(self: *Pool, id: [32]u8) !void {
        return self.active_client.containerDelete(id);
    }

    pub fn containerEaclGet(self: *Pool, id: [32]u8) ![]const u8 {
        return self.active_client.containerEaclGet(id);
    }

    pub fn containerEaclSet(self: *Pool, id: [32]u8, eacl_bin: []const u8) !void {
        return self.active_client.containerEaclSet(id, eacl_bin);
    }

    pub fn balanceGet(self: *Pool, owner: user.ID) !accounting.Decimal {
        return self.active_client.balanceGet(&owner.bytes);
    }

    pub fn networkInfo(self: *Pool) !u64 {
        return self.active_client.networkInfo();
    }

    pub fn netMapSnapshot(self: *Pool) ![]const u8 {
        return self.active_client.netMapSnapshot();
    }

    fn buildInnerPools(self: *Pool) !void {
        for (self.inner_pools.items) |*ip| ip.deinit(self.allocator);
        self.inner_pools.clearRetainingCapacity();

        var groups: std.AutoHashMap(i32, std.ArrayList(usize)) = .init(self.allocator);
        defer {
            var git = groups.iterator();
            while (git.next()) |entry| {
                entry.value_ptr.deinit(self.allocator);
            }
            groups.deinit();
        }

        for (self.nodes.items, 0..) |node, idx| {
            const gop = try groups.getOrPut(node.priority);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(self.allocator, idx);
        }

        var priorities: std.ArrayList(i32) = .empty;
        defer priorities.deinit(self.allocator);
        var git = groups.iterator();
        while (git.next()) |entry| try priorities.append(self.allocator, entry.key_ptr.*);
        std.mem.sort(i32, priorities.items, {}, std.sort.asc(i32));

        for (priorities.items) |priority| {
            const indices = groups.get(priority).?;
            var clients: std.ArrayList(NodeClient) = .empty;
            var weights: std.ArrayList(f64) = .empty;
            defer weights.deinit(self.allocator);
            for (indices.items) |idx| {
                const node = self.nodes.items[idx];
                const nc = NodeClient.init(
                    self.allocator,
                    node.endpoint,
                    node.weight,
                    if (self.nodes.items.len == 1) std.math.maxInt(i64) else self.params.error_threshold,
                    self.params.error_window_ns,
                );
                try clients.append(self.allocator, nc);
                try weights.append(self.allocator, node.weight);
            }
            const ip = InnerPool{
                .priority = priority,
                .clients = clients,
                .sampler = try sampler_mod.Sampler.init(self.allocator, weights.items),
            };
            try self.inner_pools.append(self.allocator, ip);
        }
    }

    fn selectNodeClient(self: *Pool) !*NodeClient {
        for (self.inner_pools.items) |*ip| {
            if (ip.clients.items.len == 1) {
                if (ip.clients.items[0].healthy) return &ip.clients.items[0];
                continue;
            }
            const attempts = ip.clients.items.len * 3;
            var i: usize = 0;
            while (i < attempts) : (i += 1) {
                const idx = ip.sampler.?.next();
                if (ip.clients.items[idx].healthy) return &ip.clients.items[idx];
            }
        }
        return error.NoHealthyNodes;
    }

    fn rebalanceLoop(pool: *Pool) void {
        while (!pool.stop_flag.load(.acquire)) {
            std.Io.sleep(
                pool.io,
                std.Io.Duration.fromNanoseconds(@intCast(pool.params.rebalance_interval_ns)),
                .awake,
            ) catch {};
            if (pool.stop_flag.load(.acquire)) break;
            for (pool.inner_pools.items) |*ip| {
                var weights: std.ArrayList(f64) = .empty;
                defer weights.deinit(pool.allocator);
                for (ip.clients.items) |*nc| {
                    _ = nc.probeHealth(pool.io, pool.params.healthcheck_timeout_ms);
                    if (!nc.healthy) nc.weight = 0;
                    weights.append(pool.allocator, nc.weight) catch continue;
                }
                if (ip.sampler) |*s| s.deinit(pool.allocator);
                ip.sampler = sampler_mod.Sampler.init(pool.allocator, weights.items) catch null;
            }
            pool.cache.purge();
        }
    }
};

test "pool selects healthy node" {
    var p = Pool.init(std.testing.allocator, std.testing.io);
    defer p.deinit();
    try p.addNode(.{ .endpoint = "mem://n1:8080" });
    try p.addNode(.{ .endpoint = "mem://n2:8080", .weight = 2.0 });
    try p.dial();
    const ep = try p.active_client.endpointInfo();
    try std.testing.expect(ep.len > 0);
}

test "pool caches container session" {
    var p = Pool.init(std.testing.allocator, std.testing.io);
    defer p.deinit();
    try p.addNode(.{ .endpoint = "mem://n1:8080" });
    try p.dial();
    var cid: [32]u8 = undefined;
    @memset(&cid, 0xAB);
    const t1 = try p.withinContainerSession("mem://n1:8080", cid, .put, "signer");
    const t2 = try p.withinContainerSession("mem://n1:8080", cid, .put, "signer");
    try std.testing.expectEqual(@intFromEnum(t1.verb), @intFromEnum(t2.verb));
}

test "pool v2 session mode" {
    var p = Pool.initWithParams(std.testing.allocator, std.testing.io, .{ .use_v2_sessions = true });
    defer p.deinit();
    try p.addNode(.{ .endpoint = "mem://n1:8080" });
    try p.dial();
    var cid: [32]u8 = undefined;
    @memset(&cid, 0xCD);
    const tok = try p.withinContainerSession("mem://n1:8080", cid, .put, "signer");
    try std.testing.expectEqual(@intFromEnum(session_mod.Verb.put), @intFromEnum(tok.verb));
}

test "pool container wrappers use active client" {
    var p = Pool.init(std.testing.allocator, std.testing.io);
    defer p.deinit();

    try p.addNode(.{ .endpoint = "mem://n1:8080" });
    try p.dial();

    var cont = try container.Container.init(std.testing.allocator, "owner", "nonce");
    defer cont.deinit();
    const id = try p.containerPut(cont);
    var got = try p.containerGet(id);
    defer got.deinit();

    try p.containerDelete(id);
    try std.testing.expectError(error.ContainerNotFound, p.containerGet(id));
}
