using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Wol.Server.Network;

public enum ProtocolKind { PlainTelnet, TlsTelnet, WebSocket, WebSocketSecure }

public static class ProtocolDetector
{
    private static readonly byte[] HttpGetPrefix = "GET "u8.ToArray();

    /// <summary>
    /// Peeks at the stream with up to <paramref name="timeout"/> to determine protocol.
    /// Returns the detected kind and a stream ready for that protocol to use.
    /// For TLS kinds the returned stream is an authenticated SslStream.
    /// </summary>
    public static async Task<(ProtocolKind Kind, Stream Stream)> DetectAsync(
        Stream stream,
        X509Certificate2? tlsCert,
        TimeSpan timeout,
        CancellationToken ct = default)
    {
        byte first = await PeekByteAsync(stream, timeout, ct);

        if (first == 0x16 && tlsCert != null)
        {
            // TLS ClientHello — wrap with SslStream
            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    ServerCertificate = tlsCert,
                    ClientCertificateRequired = false,
                },
                ct);

            byte afterTls = await PeekByteAsync(ssl, timeout, ct);
            return IsHttpGet(afterTls)
                ? (ProtocolKind.WebSocketSecure, ssl)
                : (ProtocolKind.TlsTelnet, ssl);
        }

        return IsHttpGet(first)
            ? (ProtocolKind.WebSocket, stream)
            : (ProtocolKind.PlainTelnet, stream);
    }

    private static bool IsHttpGet(byte b) => b == HttpGetPrefix[0]; // 'G'

    private static async Task<byte> PeekByteAsync(Stream stream, TimeSpan timeout, CancellationToken ct)
    {
        // For NetworkStream / SslStream we must read into a buffer; there is no MSG_PEEK.
        // We use a 1-byte PeekBuffer stored on a wrapper. However, since Stream doesn't
        // support peek natively, we read one byte with a timeout and store it for
        // the connection to prepend to subsequent reads.
        //
        // The caller is responsible for wrapping the stream in a PeekableStream first.
        // This method is only called on a PeekableStream.
        if (stream is PeekableStream ps)
            return await ps.PeekAsync(timeout, ct);

        throw new InvalidOperationException("DetectAsync requires a PeekableStream.");
    }
}

/// <summary>
/// Wraps a Stream to support a single-byte peek with timeout, then replays that byte
/// transparently on subsequent reads.
/// </summary>
public sealed class PeekableStream : Stream
{
    private readonly Stream _inner;
    private byte[]? _peeked; // null = not yet peeked, empty = peeked EOF

    public PeekableStream(Stream inner) => _inner = inner;

    public async Task<byte> PeekAsync(TimeSpan timeout, CancellationToken ct)
    {
        if (_peeked != null)
            return _peeked.Length > 0 ? _peeked[0] : (byte)0;

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout);

        var buf = new byte[1];
        try
        {
            int n = await _inner.ReadAsync(buf, cts.Token);
            _peeked = n > 0 ? new[] { buf[0] } : Array.Empty<byte>();
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Timeout — treat as plain telnet (no first byte)
            _peeked = Array.Empty<byte>();
        }

        return _peeked.Length > 0 ? _peeked[0] : (byte)0;
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        if (_peeked is { Length: > 0 })
        {
            buffer.Span[0] = _peeked[0];
            _peeked = Array.Empty<byte>();
            return 1;
        }
        return await _inner.ReadAsync(buffer, ct);
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
    {
        if (_peeked is { Length: > 0 })
        {
            buffer[offset] = _peeked[0];
            _peeked = Array.Empty<byte>();
            return 1;
        }
        return await _inner.ReadAsync(buffer.AsMemory(offset, count), ct);
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => _inner.WriteAsync(buffer, offset, count, ct);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        => _inner.WriteAsync(buffer, ct);

    public override Task FlushAsync(CancellationToken ct) => _inner.FlushAsync(ct);

    // Synchronous overrides (required by abstract Stream)
    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() => _inner.Flush();
    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("Use async reads.");
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => _inner.Write(buffer, offset, count);

    protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
}
