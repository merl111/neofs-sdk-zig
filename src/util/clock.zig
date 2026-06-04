const std = @import("std");

fn realtimeTimespec() std.c.timespec {
    var ts: std.c.timespec = undefined;
    if (@TypeOf(std.c.clock_gettime) != void) {
        _ = std.c.clock_gettime(.REALTIME, &ts);
        return ts;
    }
    var tv: std.c.timeval = undefined;
    _ = std.c.gettimeofday(&tv, null);
    return .{
        .sec = tv.sec,
        .nsec = @intCast(tv.usec * std.time.ns_per_us),
    };
}

pub fn timestamp() i64 {
    return realtimeTimespec().sec;
}

pub fn milliTimestamp() i64 {
    const ts = realtimeTimespec();
    return ts.sec * std.time.ms_per_s + @divTrunc(ts.nsec, std.time.ns_per_ms);
}

pub fn nanoTimestamp() i128 {
    const ts = realtimeTimespec();
    return @as(i128, ts.sec) * std.time.ns_per_s + ts.nsec;
}
