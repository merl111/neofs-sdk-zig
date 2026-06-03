const std = @import("std");

const c = @cImport({
    @cInclude("openssl/ssl.h");
    @cInclude("openssl/err.h");
});

pub const Connection = struct {
    ssl: *c.SSL,
    ctx: *c.SSL_CTX,

    pub fn init(host: [:0]const u8, stream: std.Io.net.Stream) !Connection {
        _ = c.OPENSSL_init_ssl(c.OPENSSL_INIT_LOAD_SSL_STRINGS | c.OPENSSL_INIT_LOAD_CRYPTO_STRINGS, null);

        const ctx = c.SSL_CTX_new(c.TLS_client_method()) orelse return error.TlsInitializationFailed;
        errdefer _ = c.SSL_CTX_free(ctx);

        if (c.SSL_CTX_set_default_verify_paths(ctx) != 1) return error.TlsInitializationFailed;
        c.SSL_CTX_set_verify(ctx, c.SSL_VERIFY_PEER, null);

        const alpn_h2 = [_]u8{ 2, 'h', '2' };
        if (c.SSL_CTX_set_alpn_protos(ctx, &alpn_h2, @intCast(alpn_h2.len)) != 0) {
            return error.TlsInitializationFailed;
        }

        const ssl = c.SSL_new(ctx) orelse return error.TlsInitializationFailed;
        errdefer _ = c.SSL_free(ssl);

        if (c.SSL_set_fd(ssl, @intCast(stream.socket.handle)) != 1) return error.TlsInitializationFailed;
        if (host.len > 0 and c.SSL_set_tlsext_host_name(ssl, host.ptr) != 1) {
            return error.TlsInitializationFailed;
        }

        if (c.SSL_connect(ssl) != 1) return error.TlsInitializationFailed;

        var alpn: [*c]const u8 = undefined;
        var alpn_len: c_uint = 0;
        c.SSL_get0_alpn_selected(ssl, &alpn, &alpn_len);
        if (alpn_len != 2 or alpn[0] != 'h' or alpn[1] != '2') return error.TlsInitializationFailed;

        return .{ .ssl = ssl, .ctx = ctx };
    }

    pub fn deinit(self: *Connection) void {
        _ = c.SSL_shutdown(self.ssl);
        _ = c.SSL_free(self.ssl);
        _ = c.SSL_CTX_free(self.ctx);
        self.* = undefined;
    }

    pub fn read(self: *Connection, buf: []u8) !usize {
        const n = c.SSL_read(self.ssl, buf.ptr, @intCast(buf.len));
        if (n <= 0) {
            const err = c.SSL_get_error(self.ssl, @intCast(n));
            if (err == c.SSL_ERROR_ZERO_RETURN) return 0;
            return error.EndOfStream;
        }
        return @intCast(n);
    }

    pub fn readAll(self: *Connection, buf: []u8) !void {
        var off: usize = 0;
        while (off < buf.len) {
            const n = try self.read(buf[off..]);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }

    pub fn writeAll(self: *Connection, data: []const u8) !void {
        var off: usize = 0;
        while (off < data.len) {
            const n = c.SSL_write(self.ssl, data.ptr + off, @intCast(data.len - off));
            if (n <= 0) {
                const err = c.SSL_get_error(self.ssl, n);
                std.log.err(
                    "tls: SSL_write failed off={d} remaining={d} ssl_err={d}",
                    .{ off, data.len - off, err },
                );
                return error.WriteFailed;
            }
            off += @intCast(n);
        }
    }
};
