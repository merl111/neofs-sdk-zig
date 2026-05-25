const codes = @import("../../proto/status/codes.zig");

pub const Error = error{
    IncompleteSuccess,
    InternalServerError,
    WrongMagicNumber,
    SignatureVerificationFailed,
    NodeUnderMaintenance,
    BadRequest,
    Busy,
    ObjectNotFound,
    ObjectAccessDenied,
    ObjectLocked,
    LockIrregularObject,
    ObjectAlreadyRemoved,
    ObjectOutOfRange,
    QuotaExceeded,
    ContainerNotFound,
    EaclNotFound,
    ContainerLocked,
    ContainerAwaitTimeout,
    SessionTokenNotFound,
    SessionTokenExpired,
    UnknownStatus,
};

pub fn fromCode(code: i32) Error {
    return switch (code) {
        @intFromEnum(codes.Code.incomplete_success) => error.IncompleteSuccess,
        @intFromEnum(codes.Code.internal_server_error) => error.InternalServerError,
        @intFromEnum(codes.Code.wrong_magic_number) => error.WrongMagicNumber,
        @intFromEnum(codes.Code.signature_verification_failed) => error.SignatureVerificationFailed,
        @intFromEnum(codes.Code.node_under_maintenance) => error.NodeUnderMaintenance,
        @intFromEnum(codes.Code.bad_request) => error.BadRequest,
        @intFromEnum(codes.Code.busy) => error.Busy,
        @intFromEnum(codes.Code.object_access_denied) => error.ObjectAccessDenied,
        @intFromEnum(codes.Code.object_not_found) => error.ObjectNotFound,
        @intFromEnum(codes.Code.object_locked) => error.ObjectLocked,
        @intFromEnum(codes.Code.lock_irregular_object) => error.LockIrregularObject,
        @intFromEnum(codes.Code.object_already_removed) => error.ObjectAlreadyRemoved,
        @intFromEnum(codes.Code.out_of_range) => error.ObjectOutOfRange,
        @intFromEnum(codes.Code.quota_exceeded) => error.QuotaExceeded,
        @intFromEnum(codes.Code.container_not_found) => error.ContainerNotFound,
        @intFromEnum(codes.Code.eacl_not_found) => error.EaclNotFound,
        @intFromEnum(codes.Code.container_locked) => error.ContainerLocked,
        @intFromEnum(codes.Code.container_await_timeout) => error.ContainerAwaitTimeout,
        @intFromEnum(codes.Code.session_token_not_found) => error.SessionTokenNotFound,
        @intFromEnum(codes.Code.session_token_expired) => error.SessionTokenExpired,
        else => error.UnknownStatus,
    };
}

pub fn toCode(err: Error) i32 {
    return switch (err) {
        error.IncompleteSuccess => @intFromEnum(codes.Code.incomplete_success),
        error.InternalServerError => @intFromEnum(codes.Code.internal_server_error),
        error.WrongMagicNumber => @intFromEnum(codes.Code.wrong_magic_number),
        error.SignatureVerificationFailed => @intFromEnum(codes.Code.signature_verification_failed),
        error.NodeUnderMaintenance => @intFromEnum(codes.Code.node_under_maintenance),
        error.BadRequest => @intFromEnum(codes.Code.bad_request),
        error.Busy => @intFromEnum(codes.Code.busy),
        error.ObjectAccessDenied => @intFromEnum(codes.Code.object_access_denied),
        error.ObjectNotFound => @intFromEnum(codes.Code.object_not_found),
        error.ObjectLocked => @intFromEnum(codes.Code.object_locked),
        error.LockIrregularObject => @intFromEnum(codes.Code.lock_irregular_object),
        error.ObjectAlreadyRemoved => @intFromEnum(codes.Code.object_already_removed),
        error.ObjectOutOfRange => @intFromEnum(codes.Code.out_of_range),
        error.QuotaExceeded => @intFromEnum(codes.Code.quota_exceeded),
        error.ContainerNotFound => @intFromEnum(codes.Code.container_not_found),
        error.EaclNotFound => @intFromEnum(codes.Code.eacl_not_found),
        error.ContainerLocked => @intFromEnum(codes.Code.container_locked),
        error.ContainerAwaitTimeout => @intFromEnum(codes.Code.container_await_timeout),
        error.SessionTokenNotFound => @intFromEnum(codes.Code.session_token_not_found),
        error.SessionTokenExpired => @intFromEnum(codes.Code.session_token_expired),
        error.UnknownStatus => -1,
    };
}

test "status code roundtrip for known values" {
    const t = @import("std").testing;
    try expectRoundTrip(t, error.IncompleteSuccess);
    try expectRoundTrip(t, error.InternalServerError);
    try expectRoundTrip(t, error.WrongMagicNumber);
    try expectRoundTrip(t, error.SignatureVerificationFailed);
    try expectRoundTrip(t, error.NodeUnderMaintenance);
    try expectRoundTrip(t, error.BadRequest);
    try expectRoundTrip(t, error.Busy);
    try expectRoundTrip(t, error.ObjectNotFound);
    try expectRoundTrip(t, error.ObjectAccessDenied);
    try expectRoundTrip(t, error.ObjectLocked);
    try expectRoundTrip(t, error.LockIrregularObject);
    try expectRoundTrip(t, error.ObjectAlreadyRemoved);
    try expectRoundTrip(t, error.ObjectOutOfRange);
    try expectRoundTrip(t, error.QuotaExceeded);
    try expectRoundTrip(t, error.ContainerNotFound);
    try expectRoundTrip(t, error.EaclNotFound);
    try expectRoundTrip(t, error.ContainerLocked);
    try expectRoundTrip(t, error.ContainerAwaitTimeout);
    try expectRoundTrip(t, error.SessionTokenNotFound);
    try expectRoundTrip(t, error.SessionTokenExpired);
}

fn expectRoundTrip(t: @TypeOf(@import("std").testing), err: Error) !void {
    try t.expectEqual(err, fromCode(toCode(err)));
}

test "fromCode maps known proto status codes" {
    const t = @import("std").testing;
    try t.expectEqual(error.BadRequest, fromCode(@intFromEnum(codes.Code.bad_request)));
    try t.expectEqual(error.ObjectNotFound, fromCode(@intFromEnum(codes.Code.object_not_found)));
    try t.expectEqual(error.ContainerNotFound, fromCode(@intFromEnum(codes.Code.container_not_found)));
    try t.expectEqual(error.SessionTokenExpired, fromCode(@intFromEnum(codes.Code.session_token_expired)));
    try t.expectEqual(error.UnknownStatus, fromCode(99999));
}
