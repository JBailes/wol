using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Wol.Server.Auth;

namespace Wol.Server.Network;

/// <summary>
/// Manages a WebSocket connection (ws:// or wss://).
/// Performs the HTTP upgrade handshake, then drives <see cref="LoginStateMachine"/>
/// via JSON messages.
/// </summary>
public sealed class WebSocketConnection : IGameConnection, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly string _remoteAddress;
    private readonly AccountStore _accounts;
    private readonly CancellationTokenSource _cts = new();

    public ConnectionType ConnectionType => ConnectionType.WebSocket;
    public string RemoteAddress => _remoteAddress;

    private bool _closed;

    public WebSocketConnection(Stream stream, string remoteAddress, AccountStore accounts)
    {
        _stream = stream;
        _remoteAddress = remoteAddress;
        _accounts = accounts;
    }

    public async Task RunAsync()
    {
        // 1. Read HTTP upgrade request and complete handshake
        if (!await DoHandshakeAsync())
            return;

        // 2. Drive login via JSON messages
        var stateMachine = new LoginStateMachine(this, _accounts);

        try
        {
            while (!_cts.IsCancellationRequested)
            {
                string? message = await ReadTextFrameAsync();
                if (message == null) break;

                await stateMachine.HandleJsonAsync(message);
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        finally
        {
            await CloseAsync();
        }
    }

    // -------------------------------------------------------------------------
    // IGameConnection
    // -------------------------------------------------------------------------

    public async Task SendAsync(string text, CancellationToken ct = default)
    {
        byte[] payload = Encoding.UTF8.GetBytes(text);
        await WriteFrameAsync(0x81 /* FIN + text opcode */, payload, ct);
    }

    public async Task SendRawAsync(byte[] data, CancellationToken ct = default)
    {
        await WriteFrameAsync(0x82 /* FIN + binary opcode */, data, ct);
    }

    public async Task CloseAsync(CancellationToken ct = default)
    {
        if (_closed) return;
        _closed = true;
        _cts.Cancel();
        try
        {
            // Send close frame (opcode 0x08)
            await WriteFrameAsync(0x88, new byte[] { 0x03, 0xE8 }, ct); // 1000 Normal Closure
        }
        catch { }
        _stream.Close();
    }

    // -------------------------------------------------------------------------
    // HTTP Upgrade Handshake
    // -------------------------------------------------------------------------

    private async Task<bool> DoHandshakeAsync()
    {
        var headers = await ReadHttpHeadersAsync();
        if (headers == null) return false;

        if (!headers.TryGetValue("Sec-WebSocket-Key", out string? key) || string.IsNullOrEmpty(key))
            return false;

        string accept = ComputeAcceptKey(key);

        string response =
            "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            $"Sec-WebSocket-Accept: {accept}\r\n" +
            "\r\n";

        byte[] responseBytes = Encoding.ASCII.GetBytes(response);
        await _stream.WriteAsync(responseBytes, _cts.Token);
        await _stream.FlushAsync(_cts.Token);
        return true;
    }

    private async Task<Dictionary<string, string>?> ReadHttpHeadersAsync()
    {
        var headerBytes = new List<byte>();
        var buf = new byte[1];

        // Read until \r\n\r\n
        while (true)
        {
            int n = await _stream.ReadAsync(buf, _cts.Token);
            if (n == 0) return null;
            headerBytes.Add(buf[0]);

            if (headerBytes.Count >= 4)
            {
                int e = headerBytes.Count;
                if (headerBytes[e - 4] == '\r' && headerBytes[e - 3] == '\n' &&
                    headerBytes[e - 2] == '\r' && headerBytes[e - 1] == '\n')
                    break;
            }

            if (headerBytes.Count > 8192) return null; // too large
        }

        string raw = Encoding.ASCII.GetString(headerBytes.ToArray());
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (string line in raw.Split("\r\n"))
        {
            int colon = line.IndexOf(':');
            if (colon > 0)
            {
                string name = line[..colon].Trim();
                string value = line[(colon + 1)..].Trim();
                result[name] = value;
            }
        }
        return result;
    }

    private static string ComputeAcceptKey(string clientKey)
    {
        const string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        byte[] combined = Encoding.ASCII.GetBytes(clientKey + guid);
        byte[] hash = SHA1.HashData(combined);
        return Convert.ToBase64String(hash);
    }

    // -------------------------------------------------------------------------
    // WS Frame Reading
    // -------------------------------------------------------------------------

    private async Task<string?> ReadTextFrameAsync()
    {
        while (true)
        {
            // Read 2-byte frame header
            byte[] header = new byte[2];
            if (!await ReadExactAsync(header)) return null;

            bool fin = (header[0] & 0x80) != 0;
            int opcode = header[0] & 0x0F;
            bool masked = (header[1] & 0x80) != 0;
            long payloadLen = header[1] & 0x7F;

            if (payloadLen == 126)
            {
                byte[] ext = new byte[2];
                if (!await ReadExactAsync(ext)) return null;
                payloadLen = (ext[0] << 8) | ext[1];
            }
            else if (payloadLen == 127)
            {
                byte[] ext = new byte[8];
                if (!await ReadExactAsync(ext)) return null;
                payloadLen = 0;
                for (int i = 0; i < 8; i++)
                    payloadLen = (payloadLen << 8) | ext[i];
            }

            if (payloadLen > 1024 * 1024) return null; // 1MB limit

            byte[]? mask = null;
            if (masked)
            {
                mask = new byte[4];
                if (!await ReadExactAsync(mask)) return null;
            }

            byte[] payload = new byte[payloadLen];
            if (!await ReadExactAsync(payload)) return null;

            if (masked && mask != null)
                for (int i = 0; i < payload.Length; i++)
                    payload[i] ^= mask[i % 4];

            switch (opcode)
            {
                case 0x1: // text frame
                    if (!fin) return null; // fragmentation not supported yet
                    return Encoding.UTF8.GetString(payload);

                case 0x8: // close
                    return null;

                case 0x9: // ping
                    await WriteFrameAsync(0x8A, payload, _cts.Token); // pong
                    continue;

                case 0xA: // pong
                    continue;

                default:
                    continue;
            }
        }
    }

    // -------------------------------------------------------------------------
    // WS Frame Writing
    // -------------------------------------------------------------------------

    private async Task WriteFrameAsync(byte firstByte, byte[] payload, CancellationToken ct)
    {
        long len = payload.Length;
        int headerLen = 2 + (len < 126 ? 0 : len < 65536 ? 2 : 8);
        byte[] frame = new byte[headerLen + len];

        frame[0] = firstByte;
        if (len < 126)
        {
            frame[1] = (byte)len;
        }
        else if (len < 65536)
        {
            frame[1] = 126;
            frame[2] = (byte)(len >> 8);
            frame[3] = (byte)len;
        }
        else
        {
            frame[1] = 127;
            for (int i = 0; i < 8; i++)
                frame[2 + i] = (byte)(len >> (56 - i * 8));
        }

        payload.CopyTo(frame, headerLen);
        await _stream.WriteAsync(frame, ct);
        await _stream.FlushAsync(ct);
    }

    private async Task<bool> ReadExactAsync(byte[] buf)
    {
        int total = 0;
        while (total < buf.Length)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(total), _cts.Token);
            if (n == 0) return false;
            total += n;
        }
        return true;
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _cts.Dispose();
        _stream.Dispose();
        return ValueTask.CompletedTask;
    }
}
