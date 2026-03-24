# Socket Implementation Design: Unified Multi-Protocol Listener

## Overview

This document proposes a C# .NET Core socket implementation that accepts **telnet**, **telnet-TLS**, **WebSocket (ws)**, and **WebSocket Secure (wss)** connections on a **single listening port**. Protocol detection occurs by inspecting the first bytes of each inbound connection, eliminating the need for per-protocol ports as required by the ACK!TNG reference implementation.

## Background: ACK!TNG Reference

ACK!TNG (C, OpenSSL) uses **six separate listening ports**:

| Port | Purpose |
|------|---------|
| `global_port` | Plain telnet |
| `global_ws_port` | WebSocket (via nginx loopback) |
| `global_tls_port` | Telnet over TLS |
| `global_sniff_port` | Auto-detect telnet vs TLS |
| `global_http_port` | REST API (GSGP/who) |
| `global_wss_port` | WebSocket over TLS |

Its `sniff_is_tls()` function already proves that peeking at the first byte (`0x16` = TLS ClientHello) can distinguish protocols. This design extends that principle to cover all four protocols on one socket.

## Protocol Detection Strategy

When a new TCP connection arrives, the first bytes reveal the protocol:

```
Byte 0x16 (22)         -> TLS ClientHello
  After TLS handshake:
    "GET " prefix       -> WebSocket Secure (wss://)
    Anything else       -> Telnet-TLS

Byte 0x47 ("G")        -> Likely HTTP "GET" -> WebSocket (ws://)
  Validate full HTTP Upgrade request

Anything else           -> Plain Telnet
  (Typically 0xFF = IAC, or printable ASCII)
```

### Detection Flow

```
  New TCP Connection
        |
        v
  Peek first byte (MSG_PEEK / PipeReader)
        |
        +-- 0x16 ---------> TLS Handshake (SslStream)
        |                         |
        |                    Peek decrypted byte
        |                         |
        |                    +-- "GET " --> WS Upgrade --> WSS session
        |                    |
        |                    +-- else ----> Telnet-TLS session
        |
        +-- "G" ----------> Read HTTP headers
        |                         |
        |                    Has Upgrade: websocket?
        |                         |
        |                    +-- yes --> WS Upgrade --> WS session
        |                    |
        |                    +-- no ---> Close (not supported)
        |
        +-- else ----------> Plain Telnet session
```

### Detection Timeout

A 2-second timeout is applied during protocol detection. If no data arrives (e.g. port scanner), the connection defaults to plain telnet and sends the greeting. This matches MUD convention where telnet clients may connect silently and wait for the server prompt.

## Architecture

### Project Structure

```
WoL.Server/
├── WoL.Server.csproj
├── Program.cs                          # Host builder, DI, startup
├── Configuration/
│   └── ServerOptions.cs                # Port, cert path, timeouts
├── Network/
│   ├── ConnectionListener.cs           # Single-port TCP listener
│   ├── ProtocolDetector.cs             # Byte-peeking protocol sniffer
│   ├── ConnectionManager.cs            # Tracks all active sessions
│   └── Protocols/
│       ├── IProtocolTransport.cs        # Read/write abstraction
│       ├── TelnetTransport.cs           # Raw TCP + IAC handling
│       ├── TelnetTlsTransport.cs        # SslStream + IAC handling
│       ├── WebSocketTransport.cs        # WS framing over TCP
│       └── WebSocketSecureTransport.cs  # WS framing over SslStream
├── Telnet/
│   ├── TelnetOption.cs                 # Option codes (ECHO, NAWS, etc.)
│   ├── TelnetNegotiator.cs             # IAC state machine
│   └── TelnetOptionHandlers/
│       ├── EchoHandler.cs
│       ├── NawsHandler.cs              # Window size
│       ├── MsspHandler.cs              # MUD Server Status Protocol
│       ├── MsdpHandler.cs              # MUD Server Data Protocol
│       ├── GmcpHandler.cs              # Generic MUD Comm Protocol
│       └── Mccp2Handler.cs             # Compression (zlib stream)
├── WebSocket/
│   ├── WsHandshake.cs                  # HTTP Upgrade + Sec-WebSocket-Accept
│   ├── WsFrameReader.cs               # Unmask + reassemble frames
│   └── WsFrameWriter.cs               # Construct outbound frames
└── Session/
    ├── ClientSession.cs                # Per-connection state machine
    ├── SessionState.cs                 # Enum: Detecting, Negotiating, Active, Closed
    └── InputProcessor.cs              # Line buffering, command queue
```

### Key Interfaces

```csharp
/// Abstraction over the wire protocol. All session logic talks to this
/// interface regardless of whether the underlying transport is raw TCP,
/// SslStream, or WebSocket.
public interface IProtocolTransport : IAsyncDisposable
{
    /// The protocol family for this transport.
    ProtocolType Protocol { get; }

    /// Send a line of text (server -> client).
    /// Implementations handle framing (IAC escaping, WS text frames, etc.)
    ValueTask SendAsync(ReadOnlyMemory<byte> data,
                        CancellationToken ct = default);

    /// Receive the next complete line/command from the client.
    /// Implementations handle deframing (IAC stripping, WS unmasking, etc.)
    ValueTask<ReadResult> ReceiveAsync(CancellationToken ct = default);

    /// Flush any buffered output (e.g., MCCP compressed block).
    ValueTask FlushAsync(CancellationToken ct = default);

    /// Negotiate protocol capabilities after detection.
    /// For telnet: sends WILL/DO sequences.
    /// For WS: already complete after handshake (no-op).
    ValueTask NegotiateAsync(CancellationToken ct = default);

    /// Remote endpoint info for logging / bans.
    EndPointInfo RemoteEndPoint { get; }

    /// Whether the transport is still connected.
    bool IsConnected { get; }
}

public enum ProtocolType
{
    Telnet,
    TelnetTls,
    WebSocket,
    WebSocketSecure
}

public readonly record struct ReadResult(
    bool Success,
    string? Line,
    bool IsGmcpMessage = false,
    string? GmcpPackage = null,
    string? GmcpData = null
);
```

### Connection Listener

```csharp
public class ConnectionListener : BackgroundService
{
    private readonly ServerOptions _options;
    private readonly ConnectionManager _connections;
    private readonly ProtocolDetector _detector;
    private readonly ILogger<ConnectionListener> _logger;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        using var listener = new TcpListener(
            IPAddress.Any, _options.Port);     // e.g. 6969
        listener.Start(backlog: 32);

        _logger.LogInformation("Listening on port {Port}", _options.Port);

        while (!ct.IsCancellationRequested)
        {
            var tcp = await listener.AcceptTcpClientAsync(ct);
            // Fire-and-forget per connection; tracked by ConnectionManager
            _ = HandleConnectionAsync(tcp, ct);
        }
    }

    private async Task HandleConnectionAsync(TcpClient tcp,
                                              CancellationToken ct)
    {
        IProtocolTransport? transport = null;
        try
        {
            transport = await _detector.DetectAndWrapAsync(tcp, ct);
            var session = new ClientSession(transport, _connections);
            _connections.Add(session);
            await session.RunAsync(ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Connection error from {Remote}",
                tcp.Client.RemoteEndPoint);
        }
        finally
        {
            if (transport != null)
                await transport.DisposeAsync();
            tcp.Dispose();
        }
    }
}
```

### Protocol Detector

```csharp
public class ProtocolDetector
{
    private readonly ServerOptions _options;
    private readonly X509Certificate2? _cert;

    private const byte TLS_HANDSHAKE = 0x16;
    private const byte HTTP_G        = 0x47;  // 'G'

    public async Task<IProtocolTransport> DetectAndWrapAsync(
        TcpClient tcp, CancellationToken ct)
    {
        var stream = tcp.GetStream();
        stream.ReadTimeout = (int)_options.DetectionTimeout
                                         .TotalMilliseconds;

        // Peek at first byte with a short timeout.
        var buf = new byte[1];
        int read;
        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(ct);
        cts.CancelAfter(_options.DetectionTimeout);  // default 2s

        try
        {
            read = await stream.ReadAsync(buf.AsMemory(0, 1), cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Timeout: assume plain telnet (silent connect)
            return new TelnetTransport(stream, tcp);
        }

        if (read == 0)
            throw new IOException("Connection closed during detection");

        byte first = buf[0];

        // --- TLS path ---
        if (first == TLS_HANDSHAKE && _cert != null)
        {
            // We consumed 1 byte; prepend it for the TLS handshake.
            var prefixed = new PrefixedStream(buf.AsMemory(0, 1), stream);
            var ssl = new SslStream(prefixed, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
            {
                ServerCertificate = _cert,
                ClientCertificateRequired = false,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            }, ct);

            // Now peek decrypted first bytes to distinguish TLS-telnet vs WSS.
            var decBuf = new byte[4];
            int decRead = await ssl.ReadAsync(decBuf.AsMemory(0, 4), ct);
            if (decRead >= 3 && decBuf[0] == 'G' &&
                                decBuf[1] == 'E' &&
                                decBuf[2] == 'T')
            {
                return new WebSocketSecureTransport(ssl, tcp, decBuf[..decRead]);
            }
            return new TelnetTlsTransport(ssl, tcp, decBuf[..decRead]);
        }

        // --- WebSocket path ---
        if (first == HTTP_G)
        {
            return new WebSocketTransport(stream, tcp, buf.AsMemory(0, 1));
        }

        // --- Plain telnet ---
        return new TelnetTransport(stream, tcp, buf.AsMemory(0, 1));
    }
}
```

Note: `PrefixedStream` is a thin `Stream` wrapper that yields the already-consumed byte(s) before delegating to the inner stream, so the `SslStream` sees the complete TLS ClientHello.

## Telnet Negotiation

### IAC State Machine

The telnet transport parses IAC sequences inline as data arrives:

```
State: Normal
  byte == IAC (0xFF) -> State: IAC
  byte == anything   -> append to input line

State: IAC
  byte == IAC        -> literal 0xFF to input, State: Normal
  byte == WILL       -> State: WILL
  byte == WONT       -> State: WONT
  byte == DO         -> State: DO
  byte == DONT       -> State: DONT
  byte == SB         -> State: Subneg, clear subneg buffer
  byte == GA/EOR     -> State: Normal (prompt marker)

State: WILL/WONT/DO/DONT
  byte == option     -> dispatch to option handler, State: Normal

State: Subneg
  byte == IAC        -> State: SubnegIAC
  byte == anything   -> append to subneg buffer

State: SubnegIAC
  byte == SE         -> dispatch subneg buffer, State: Normal
  byte == IAC        -> literal 0xFF to subneg buffer, State: Subneg
```

### Supported Options

| Option | Code | Direction | Purpose |
|--------|------|-----------|---------|
| ECHO | 1 | WILL | Server controls echo (password masking) |
| SGA | 3 | WILL | Suppress Go-Ahead |
| NAWS | 31 | DO | Client reports window size |
| MSSP | 70 | WILL | Server advertises game metadata |
| MSDP | 69 | WILL | Structured variable exchange |
| GMCP | 201 | WILL | JSON-based out-of-band messaging |
| MCCP2 | 86 | WILL | zlib compression (server -> client) |

### Greeting Sequence (Telnet only)

On connection, the server immediately sends:
```
IAC WILL ECHO
IAC WILL SGA
IAC WILL MSSP
IAC WILL MSDP
IAC WILL GMCP
IAC WILL MCCP2
IAC DO NAWS
<login banner>
```

WebSocket connections skip IAC negotiation entirely; GMCP-equivalent data is sent as JSON text frames.

## WebSocket Handshake

For both WS and WSS, after detecting an HTTP GET request:

1. Read the full HTTP request headers (up to `\r\n\r\n`)
2. Validate required headers:
   - `Upgrade: websocket`
   - `Connection: Upgrade`
   - `Sec-WebSocket-Version: 13`
   - `Sec-WebSocket-Key: <base64>`
3. Compute accept key: `Base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`
4. Send response:
   ```
   HTTP/1.1 101 Switching Protocols\r\n
   Upgrade: websocket\r\n
   Connection: Upgrade\r\n
   Sec-WebSocket-Accept: <computed>\r\n
   \r\n
   ```

After the handshake, the transport switches to WebSocket frame encoding. .NET's built-in `System.Net.WebSockets.WebSocket.CreateFromStream()` can handle frame-level I/O after we manually complete the HTTP upgrade on our raw stream.

### Frame Handling

**Inbound:** All client frames are masked per RFC 6455. The transport unmaskes payloads and reassembles fragmented messages. Only text (opcode 0x1) and close (0x8) frames are expected. Ping (0x9) frames get automatic pong (0xA) replies.

**Outbound:** Server frames are unmasked text frames. The transport strips any embedded IAC sequences from outbound text (sanitization inherited from ACK!TNG's `sanitize_websocket_text_payload()`).

## Session Lifecycle

```
  TCP Accept
      |
      v
  [Detecting] --- ProtocolDetector.DetectAndWrapAsync()
      |
      v
  [Negotiating] --- transport.NegotiateAsync()
      |              (telnet: IAC exchange; WS: handshake already done)
      v
  [Connected] --- CON_GET_NAME equivalent
      |            Send login greeting / prompt for name
      v
  [Playing] --- Main command loop
      |          ReceiveAsync() -> parse -> execute -> SendAsync()
      |          Idle timeout: 180s during login, configurable during play
      v
  [Closed] --- Graceful or timeout
               Flush output, save state, dispose transport
```

### Connection Manager

```csharp
public class ConnectionManager
{
    private readonly ConcurrentDictionary<Guid, ClientSession> _sessions = new();

    public void Add(ClientSession session) =>
        _sessions.TryAdd(session.Id, session);

    public void Remove(Guid id) =>
        _sessions.TryRemove(id, out _);

    public IEnumerable<ClientSession> ActiveSessions =>
        _sessions.Values.Where(s => s.State == SessionState.Playing);

    /// Broadcast to all active sessions (e.g., global channels).
    public async Task BroadcastAsync(ReadOnlyMemory<byte> data,
        Func<ClientSession, bool>? filter = null)
    {
        var targets = filter != null
            ? ActiveSessions.Where(filter)
            : ActiveSessions;
        await Parallel.ForEachAsync(targets, async (s, ct) =>
            await s.Transport.SendAsync(data, ct));
    }
}
```

## Configuration

```json
{
  "Server": {
    "Port": 6969,
    "TlsCertPath": "/etc/letsencrypt/live/example.com/fullchain.pem",
    "TlsKeyPath": "/etc/letsencrypt/live/example.com/privkey.pem",
    "DetectionTimeoutMs": 2000,
    "LoginTimeoutSeconds": 180,
    "IdleTimeoutSeconds": 3600,
    "MaxConnections": 256,
    "BindAddress": "0.0.0.0"
  }
}
```

```csharp
public class ServerOptions
{
    public int Port { get; set; } = 6969;
    public string? TlsCertPath { get; set; }
    public string? TlsKeyPath { get; set; }
    public TimeSpan DetectionTimeout { get; set; } = TimeSpan.FromSeconds(2);
    public TimeSpan LoginTimeout { get; set; } = TimeSpan.FromSeconds(180);
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromHours(1);
    public int MaxConnections { get; set; } = 256;
    public string BindAddress { get; set; } = "0.0.0.0";
}
```

When no TLS certificate is configured, TLS/WSS connections are rejected at detection time (the `0x16` path returns an error and closes the socket). This allows running in dev mode without certificates.

## .NET Implementation Notes

### Why Not Kestrel?

Kestrel is optimized for HTTP and would add unnecessary overhead for raw telnet. By using `TcpListener` directly, we get:
- Full control over the byte stream from the first byte
- No HTTP parsing overhead for telnet connections
- Simpler protocol detection (no middleware pipeline to work around)
- Lower memory footprint per connection

However, we can optionally integrate a Kestrel endpoint on a separate port for HTTP REST APIs (GSGP/who) if needed later. The core game socket remains a raw TCP listener.

### System.IO.Pipelines

For high-throughput I/O, the telnet transports should use `System.IO.Pipelines` (`PipeReader`/`PipeWriter`) rather than raw `Stream.ReadAsync`. This provides:
- Zero-copy buffer management
- Backpressure when a client isn't reading fast enough
- Efficient partial-read handling (important for IAC parsing)

```csharp
// In TelnetTransport constructor
var pipe = new Pipe();
_reader = PipeReader.Create(_stream);
_writer = PipeWriter.Create(_stream);
```

### MCCP2 Compression

MCCP2 wraps the output stream in a zlib deflate stream after sending `IAC SB MCCP2 IAC SE`. In .NET:

```csharp
// When client confirms DO MCCP2:
await SendRawAsync(new byte[] { IAC, SB, MCCP2, IAC, SE });
_outputStream = new DeflateStream(_outputStream,
    CompressionLevel.Fastest, leaveOpen: true);
```

The compressed stream stays active for the remainder of the session. Input is never compressed (MCCP2 is server-to-client only).

### Thread Safety

- Each `ClientSession` runs on its own async task; no shared mutable state between sessions except through `ConnectionManager`
- `ConnectionManager` uses `ConcurrentDictionary`
- Broadcast operations are fire-and-forget with per-session error isolation
- The game loop (tick processing, combat, etc.) will eventually need a single-threaded dispatcher, but that is outside the scope of this socket layer design

## Comparison with ACK!TNG

| Aspect | ACK!TNG | This Design |
|--------|---------|-------------|
| Language | C + OpenSSL | C# .NET Core |
| Ports required | 6 | 1 (+ optional HTTP) |
| Protocol detection | Only TLS sniffing on sniff port | Full auto-detect on single port |
| WebSocket | nginx loopback required | Native, in-process |
| TLS library | OpenSSL (manual) | SslStream (managed) |
| I/O model | select() loop, single-threaded | async/await, thread pool |
| Telnet options | ECHO, MSSP, MSDP, GMCP, MCCP2/3 | Same set (MCCP3 deferred) |
| Hot reboot | FD inheritance via exec() | Planned: connection draining |
| Compression | MCCP2 + MCCP3 | MCCP2 initially |

## Future Considerations

- **MCCP3**: Can be added as an additional telnet option handler later
- **PROXY protocol (HAProxy)**: If running behind a load balancer, detect PROXY protocol header before the TLS/telnet sniff
- **HTTP REST API**: Can share the same port by detecting `GET /api/` or `POST /` patterns during the HTTP-path detection, or run Kestrel on a separate port
- **Hot Reboot**: Unlike ACK!TNG's FD inheritance via `exec()`, .NET would need a connection-draining strategy or Unix domain socket handoff
- **Rate Limiting**: Add per-IP connection rate limiting in `ConnectionListener` before protocol detection
- **Ban List**: Check IP against ban table immediately on accept, before spending resources on detection
