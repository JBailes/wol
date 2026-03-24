# Socket Implementation Design: Unified Multi-Protocol Listener

## Overview

This document proposes a C# .NET Core socket implementation that accepts **telnet**, **telnet-TLS**, **WebSocket (ws)**, and **WebSocket Secure (wss)** connections on a **single listening port**. Protocol detection occurs by inspecting the first bytes of each inbound connection, eliminating the need for per-protocol ports as required by the ACK!TNG reference implementation.

The socket layer is responsible for:
- Accepting TCP connections and detecting the protocol
- TLS termination when applicable
- Telnet option negotiation (ECHO, SGA, NAWS, MSSP, MSDP, GMCP, MCCP2, MCCP3)
- WebSocket upgrade handshake and frame encoding
- Character encoding translation (Latin-1 for telnet, UTF-8 for WebSocket)
- Authentication flow (account login / registration)
- Feeding commands into the game loop and delivering output back to clients
- Connection lifecycle management (idle timeouts, dead socket detection, session takeover)

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

Its `sniff_is_tls()` function peeks at the first byte (`0x16` = TLS ClientHello) to distinguish protocols. This design extends that principle to cover all four protocols on one socket.

### ACK!TNG Telnet Options Supported

| Option | Code | Notes |
|--------|------|-------|
| ECHO | 1 | Server-controlled echo for password masking |
| SGA | 3 | Suppress Go-Ahead |
| NAWS | 31 | Client reports terminal width/height |
| MSSP | 70 | MUD Server Status Protocol — game metadata for crawlers |
| MSDP | 69 | MUD Server Data Protocol — structured variable exchange |
| GMCP | 201 | Generic MUD Communication Protocol — JSON out-of-band |
| MCCP2 | 86 | MUD Client Compression Protocol v2 — zlib server-to-client |
| MCCP3 | 87 | MUD Client Compression Protocol v3 — zlib with per-message negotiation |

All of these must be supported in this implementation.

## Protocol Detection Strategy

When a new TCP connection arrives, we use `Socket.Receive` with `SocketFlags.Peek` (`MSG_PEEK`) to inspect the first bytes **without consuming them**. This is critical: it means the underlying stream remains untouched for handoff to `SslStream` or the telnet parser, avoiding the need for a fragile `PrefixedStream` wrapper.

### Detection Algorithm

```
  New TCP Connection
        |
        v
  Check IP against ban list (reject immediately if banned)
  Check connection count (reject if at MaxConnections)
        |
        v
  MSG_PEEK first 4 bytes (1 second timeout)
        |
        +-- Timeout (no data) -----> Plain Telnet (silent connect)
        |
        +-- Byte[0] == 0x16 -------> TLS Handshake (SslStream)
        |                                  |
        |                             MSG_PEEK decrypted first 4 bytes
        |                                  |
        |                             +-- "GET " --> WSS handshake --> WSS session
        |                             |
        |                             +-- else ----> Telnet-TLS session
        |
        +-- "GET " (4 bytes) -------> Read HTTP headers
        |                                  |
        |                             Has "Upgrade: websocket"?
        |                                  |
        |                             +-- yes --> WS handshake --> WS session
        |                             +-- no ---> HTTP request (GSGP/who) or close
        |
        +-- Byte[0] == 'G' but
        |   not "GET " -------------> Plain Telnet (prepend buffered bytes)
        |
        +-- Anything else ----------> Plain Telnet
```

### Why 4 bytes, not 1

The original design peeked only at the first byte (`0x47` = `'G'`). This creates a false positive: if a telnet client with auto-login sends a username starting with "G" before waiting for a prompt, we'd misroute it to the WebSocket path and drop the connection. By peeking 4 bytes and requiring the full `"GET "` prefix, we eliminate this class of false positives. The only remaining ambiguity is a telnet client that auto-sends exactly `"GET "` — which is not a realistic scenario.

### Detection Timeout

A 1-second timeout is applied during the initial peek. If no data arrives (port scanner, or a standard telnet client waiting for the server greeting), the connection defaults to plain telnet. This matches MUD convention where telnet clients connect silently and wait for the server prompt.

### MSG_PEEK Approach

```csharp
// Peek without consuming — SslStream sees the full ClientHello intact.
var peekBuf = new byte[4];
int peeked = socket.Receive(peekBuf, 0, 4, SocketFlags.Peek);
```

This avoids the `PrefixedStream` hack from the original design. `SslStream` wraps the raw `NetworkStream` directly, seeing every byte from the start. After protocol detection, the peeked bytes are either:
- Consumed naturally by `SslStream.AuthenticateAsServerAsync()` (TLS path)
- Consumed naturally by the HTTP header read (WebSocket path)
- Consumed naturally by the telnet IAC parser (telnet path)

## Architecture

### Project Structure

```
WoL.Server/
├── WoL.Server.csproj
├── Program.cs                              # Host builder, DI, startup
├── Configuration/
│   └── ServerOptions.cs                    # Port, cert path, timeouts
├── Network/
│   ├── ConnectionListener.cs               # Single-port TCP listener
│   ├── ProtocolDetector.cs                 # MSG_PEEK protocol sniffer
│   ├── ConnectionManager.cs                # Tracks all active sessions
│   ├── BanList.cs                          # IP-based connection bans
│   ├── RateLimiter.cs                      # Per-IP connection rate limiting
│   └── Protocols/
│       ├── IProtocolTransport.cs            # Read/write abstraction
│       ├── TelnetTransport.cs               # Raw TCP + IAC handling
│       ├── TelnetTlsTransport.cs            # SslStream + IAC handling
│       ├── WebSocketTransport.cs            # WS framing over TCP
│       └── WebSocketSecureTransport.cs      # WS framing over SslStream
├── Telnet/
│   ├── TelnetConstants.cs                  # IAC, WILL, WONT, DO, DONT, SB, SE, option codes
│   ├── TelnetNegotiator.cs                 # IAC state machine
│   ├── TelnetEncoding.cs                   # Latin-1 <-> UTF-16 translation
│   └── OptionHandlers/
│       ├── ITelnetOptionHandler.cs          # Interface for option negotiation
│       ├── EchoHandler.cs                   # Server echo control (password masking)
│       ├── SgaHandler.cs                    # Suppress Go-Ahead
│       ├── NawsHandler.cs                   # Window size reporting
│       ├── MsspHandler.cs                   # MUD Server Status Protocol
│       ├── MsdpHandler.cs                   # MUD Server Data Protocol
│       ├── GmcpHandler.cs                   # Generic MUD Communication Protocol
│       ├── Mccp2Handler.cs                  # Compression v2 (zlib)
│       └── Mccp3Handler.cs                  # Compression v3 (zlib per-message)
├── WebSocket/
│   ├── WsHandshake.cs                      # HTTP Upgrade + Sec-WebSocket-Accept
│   ├── WsFrameReader.cs                    # Unmask + reassemble frames
│   ├── WsFrameWriter.cs                    # Construct outbound frames
│   └── WsSubprotocol.cs                    # Subprotocol negotiation (e.g. "gmcp")
├── Auth/
│   ├── AuthFlow.cs                         # Orchestrates login/registration per protocol
│   ├── TelnetAuthFlow.cs                   # Line-by-line prompts for telnet
│   └── WebSocketAuthFlow.cs                # JSON message-based auth for WS
└── Session/
    ├── ClientSession.cs                    # Per-connection state machine
    ├── SessionState.cs                     # Enum: Detecting, Authenticating, Playing, Closed
    ├── InputBuffer.cs                      # Line buffering, command queue
    ├── OutputBuffer.cs                     # Batched output with prompt appending
    └── SnoopLink.cs                        # Admin session-watching support
```

### Key Interfaces

```csharp
/// Abstraction over the wire protocol. All session logic talks to this
/// interface regardless of whether the underlying transport is raw TCP,
/// SslStream, or WebSocket.
public interface IProtocolTransport : IAsyncDisposable
{
    ProtocolType Protocol { get; }

    /// Send output to the client. Implementations handle framing
    /// (IAC escaping, WS text frames, MCCP compression, etc.)
    ValueTask SendAsync(ReadOnlyMemory<byte> data,
                        CancellationToken ct = default);

    /// Receive the next complete line/command from the client.
    /// Implementations handle deframing (IAC stripping, WS unmasking, etc.)
    ValueTask<ReadResult> ReceiveAsync(CancellationToken ct = default);

    /// Flush any buffered output (MCCP compressed block, Nagle, etc.)
    ValueTask FlushAsync(CancellationToken ct = default);

    /// Negotiate protocol capabilities after detection.
    /// Telnet: sends WILL/DO sequences. WS: no-op (handshake already done).
    ValueTask NegotiateAsync(CancellationToken ct = default);

    /// Remote endpoint info for logging, bans, rate limiting.
    EndPointInfo RemoteEndPoint { get; }

    bool IsConnected { get; }

    /// Telnet-specific: currently negotiated option state.
    /// Null for WebSocket transports.
    TelnetOptionState? TelnetOptions { get; }
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
    bool IsOobMessage = false,       // Out-of-band (GMCP/MSDP) message
    string? OobPackage = null,       // e.g. "Core.Hello" for GMCP
    string? OobData = null           // JSON payload
);

public readonly record struct EndPointInfo(
    IPAddress Address,
    int Port,
    string HostName                  // Reverse DNS, resolved async post-connect
);
```

### Transport Hierarchy

`TelnetTransport` and `TelnetTlsTransport` share almost all logic (IAC parsing, option handling, encoding). The only difference is the underlying stream. Rather than duplicating code:

```csharp
// Both telnet variants compose a shared TelnetCodec over their stream.
public class TelnetTransport : IProtocolTransport
{
    private readonly TelnetCodec _codec;

    public TelnetTransport(NetworkStream stream, TcpClient tcp)
    {
        _codec = new TelnetCodec(stream, tcp.Client.RemoteEndPoint);
    }
}

public class TelnetTlsTransport : IProtocolTransport
{
    private readonly TelnetCodec _codec;

    public TelnetTlsTransport(SslStream stream, TcpClient tcp)
    {
        _codec = new TelnetCodec(stream, tcp.Client.RemoteEndPoint);
    }
}

// TelnetCodec takes any Stream and handles IAC, encoding, MCCP, etc.
internal class TelnetCodec { ... }
```

Similarly, `WebSocketTransport` and `WebSocketSecureTransport` share a `WsCodec` over either a `NetworkStream` or `SslStream`.

## Connection Listener

```csharp
public class ConnectionListener : BackgroundService
{
    private readonly ServerOptions _options;
    private readonly ConnectionManager _connections;
    private readonly ProtocolDetector _detector;
    private readonly BanList _bans;
    private readonly RateLimiter _rateLimiter;
    private readonly ILogger<ConnectionListener> _logger;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // Dual-stack: IPv6Any with DualMode accepts both IPv4 and IPv6.
        var listener = new TcpListener(IPAddress.IPv6Any, _options.Port);
        listener.Server.DualMode = true;
        listener.Start(backlog: 32);

        _logger.LogInformation("Listening on port {Port} (dual-stack)",
            _options.Port);

        while (!ct.IsCancellationRequested)
        {
            var tcp = await listener.AcceptTcpClientAsync(ct);
            var remoteEp = (IPEndPoint)tcp.Client.RemoteEndPoint!;

            // --- Pre-detection rejection (cheap checks first) ---
            if (_bans.IsBanned(remoteEp.Address))
            {
                _logger.LogDebug("Rejected banned IP {Ip}", remoteEp.Address);
                tcp.Dispose();
                continue;
            }
            if (_connections.Count >= _options.MaxConnections)
            {
                _logger.LogWarning("Max connections ({Max}) reached, rejecting {Ip}",
                    _options.MaxConnections, remoteEp.Address);
                tcp.Dispose();
                continue;
            }
            if (!_rateLimiter.Allow(remoteEp.Address))
            {
                _logger.LogDebug("Rate limited {Ip}", remoteEp.Address);
                tcp.Dispose();
                continue;
            }

            // Enable TCP keepalive to detect dead sockets.
            tcp.Client.SetSocketOption(SocketOptionLevel.Socket,
                SocketOptionName.KeepAlive, true);
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp,
                SocketOptionName.TcpKeepAliveTime, 60);       // first probe at 60s
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp,
                SocketOptionName.TcpKeepAliveInterval, 10);    // then every 10s
            tcp.Client.SetSocketOption(SocketOptionLevel.Tcp,
                SocketOptionName.TcpKeepAliveRetryCount, 3);   // give up after 3

            _ = HandleConnectionAsync(tcp, ct);
        }
    }

    private async Task HandleConnectionAsync(TcpClient tcp,
                                              CancellationToken ct)
    {
        ClientSession? session = null;
        try
        {
            var transport = await _detector.DetectAndWrapAsync(tcp, ct);
            session = new ClientSession(transport, _connections);
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
            // Always clean up: remove from manager, dispose transport, close TCP.
            if (session != null)
                _connections.Remove(session.Id);
            tcp.Dispose();
        }
    }
}
```

### Key differences from original design:
- **Dual-stack IPv6** via `IPAddress.IPv6Any` + `DualMode = true`
- **Ban check** before any protocol detection work
- **MaxConnections enforced** at accept time, not just configured
- **Rate limiting** per IP before spawning a task
- **TCP keepalive** configured to detect dead sockets within ~90 seconds
- **Session removal** in `finally` block — fixes the leaked session bug

## Protocol Detector

```csharp
public class ProtocolDetector
{
    private readonly ServerOptions _options;
    private readonly CertificateProvider _certProvider;

    private static readonly byte[] GET_PREFIX = "GET "u8.ToArray();
    private const byte TLS_HANDSHAKE = 0x16;

    public async Task<IProtocolTransport> DetectAndWrapAsync(
        TcpClient tcp, CancellationToken ct)
    {
        var socket = tcp.Client;
        var stream = tcp.GetStream();

        // --- Peek 4 bytes without consuming (MSG_PEEK) ---
        var peekBuf = new byte[4];
        int peeked = 0;

        using var cts = CancellationTokenSource
            .CreateLinkedTokenSource(ct);
        cts.CancelAfter(_options.DetectionTimeout);  // 1s

        try
        {
            // SocketFlags.Peek leaves data in the kernel buffer.
            peeked = await socket.ReceiveAsync(
                peekBuf.AsMemory(), SocketFlags.Peek, cts.Token);
        }
        catch (OperationCanceledException)
        {
            // Timeout: no data sent. Assume plain telnet (silent connect).
            return new TelnetTransport(stream, tcp);
        }

        if (peeked == 0)
            throw new IOException("Connection closed during detection");

        // --- TLS path: first byte is 0x16 (TLS ClientHello record) ---
        if (peekBuf[0] == TLS_HANDSHAKE)
        {
            var cert = _certProvider.GetCurrent();
            if (cert == null)
                throw new InvalidOperationException(
                    "TLS connection received but no certificate configured");

            var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsServerAsync(
                new SslServerAuthenticationOptions
                {
                    // Use callback for hot-reload support.
                    ServerCertificateSelectionCallback =
                        (_, _) => _certProvider.GetCurrent(),
                    ClientCertificateRequired = false,
                    EnabledSslProtocols =
                        SslProtocols.Tls12 | SslProtocols.Tls13,
                }, ct);

            // Now peek the *decrypted* stream to distinguish
            // telnet-TLS vs WSS.
            var decBuf = new byte[4];
            int decRead = await ssl.ReadAsync(decBuf.AsMemory(), ct);

            if (decRead >= 4 && decBuf.AsSpan(0, 4).SequenceEqual(GET_PREFIX))
            {
                // WSS: hand off with the already-read "GET " bytes.
                return new WebSocketSecureTransport(ssl, tcp, decBuf[..decRead]);
            }

            // Telnet-TLS: hand off with any already-read bytes.
            return new TelnetTlsTransport(ssl, tcp, decBuf[..decRead]);
        }

        // --- WebSocket path: first 4 bytes are "GET " ---
        if (peeked >= 4 && peekBuf.AsSpan(0, 4).SequenceEqual(GET_PREFIX))
        {
            return new WebSocketTransport(stream, tcp);
        }

        // --- Plain telnet: IAC (0xFF), printable ASCII, or anything else ---
        // Includes the case where first byte is 'G' but not "GET ".
        return new TelnetTransport(stream, tcp);
    }
}
```

### CertificateProvider (TLS Hot-Reload)

Let's Encrypt certificates expire every 90 days. The detector uses a `CertificateProvider` that watches the cert files and reloads them on change, rather than loading once at startup:

```csharp
public class CertificateProvider : IDisposable
{
    private volatile X509Certificate2? _current;
    private readonly FileSystemWatcher? _watcher;

    public CertificateProvider(ServerOptions options)
    {
        if (options.TlsCertPath != null && options.TlsKeyPath != null)
        {
            LoadCert(options.TlsCertPath, options.TlsKeyPath);

            _watcher = new FileSystemWatcher(
                Path.GetDirectoryName(options.TlsCertPath)!);
            _watcher.Changed += (_, _) =>
                LoadCert(options.TlsCertPath, options.TlsKeyPath);
            _watcher.EnableRaisingEvents = true;
        }
    }

    public X509Certificate2? GetCurrent() => _current;

    private void LoadCert(string certPath, string keyPath)
    {
        _current = X509Certificate2.CreateFromPemFile(certPath, keyPath);
    }

    public void Dispose() => _watcher?.Dispose();
}
```

The `ServerCertificateSelectionCallback` in `SslServerAuthenticationOptions` is called **per-connection**, so new connections automatically pick up renewed certificates without a server restart.

## Telnet Negotiation

### IAC State Machine

The `TelnetCodec` parses IAC sequences inline as bytes arrive from the network. The state machine runs byte-by-byte over the input buffer:

```
State: Normal
  byte == IAC (0xFF) -> State: IAC
  byte == '\r'       -> set CR-pending flag (handle \r\n vs \r\0)
  byte == '\n'       -> complete line, enqueue to input buffer
  byte == anything   -> append to current line

State: IAC
  byte == IAC        -> literal 0xFF to input, State: Normal
  byte == WILL       -> State: WILL
  byte == WONT       -> State: WONT
  byte == DO         -> State: DO
  byte == DONT       -> State: DONT
  byte == SB         -> State: Subneg, clear subneg buffer
  byte == GA (249)   -> State: Normal (prompt marker / Go Ahead)
  byte == EOR (239)  -> State: Normal (End of Record prompt marker)
  byte == NOP (241)  -> State: Normal (keepalive, ignore)
  byte == IP (244)   -> interrupt process, State: Normal
  byte == AYT (246)  -> respond with "[Yes]\r\n", State: Normal

State: WILL/WONT/DO/DONT
  byte == option     -> dispatch to ITelnetOptionHandler, State: Normal

State: Subneg
  byte == IAC        -> State: SubnegIAC
  byte == anything   -> append to subneg buffer

State: SubnegIAC
  byte == SE         -> dispatch subneg payload to handler, State: Normal
  byte == IAC        -> literal 0xFF to subneg buffer, State: Subneg
```

### Supported Telnet Options

All options from ACK!TNG are supported:

| Option | Code | Server Sends | Client Sends | Purpose |
|--------|------|-------------|-------------|---------|
| ECHO | 1 | WILL | DO | Server controls local echo. Toggled during password entry to suppress display. |
| SGA | 3 | WILL | DO | Suppress Go-Ahead. Enables character-at-a-time mode. |
| NAWS | 31 | DO | WILL + SB | Client reports terminal size (width, height) as a 4-byte subnegotiation. Used for paging, formatting. |
| MSSP | 70 | WILL | DO + SB | Server advertises game metadata (name, players online, uptime, etc.) for MUD crawlers. |
| MSDP | 69 | WILL | DO | Structured variable exchange. Client can REPORT, LIST, SET variables. Subnegotiation uses MSDP_VAR/MSDP_VAL framing. |
| GMCP | 201 | WILL | DO | JSON-based out-of-band messaging. Subneg payload is `"Package.Name <json>"`. Used for room info, char vitals, map data. |
| MCCP2 | 86 | WILL | DO | After client confirms DO, server sends `IAC SB MCCP2 IAC SE` and then all subsequent server output is zlib-compressed. Remains active for the session. |
| MCCP3 | 87 | WILL | DO | Per-message compression. Server wraps individual output blocks in zlib frames rather than compressing the entire stream. Client can switch between MCCP2 and MCCP3. |

### Greeting Sequence

On connection, the telnet transport immediately sends the negotiation sequence:

```
IAC WILL ECHO
IAC WILL SGA
IAC DO   NAWS
IAC WILL MSSP
IAC WILL MSDP
IAC WILL GMCP
IAC WILL MCCP2
IAC WILL MCCP3
```

The server then waits briefly (non-blocking) for client responses before sending the login banner. Clients that don't respond to an option within the negotiation window are assumed to not support it.

WebSocket connections skip all IAC negotiation. GMCP-equivalent data is sent as structured JSON text frames instead.

### MCCP2 Implementation

MCCP2 uses **RFC 1950 zlib** framing (not raw deflate). This is a critical distinction — using .NET's `DeflateStream` would produce a corrupt stream. Use `ZLibStream` (.NET 6+):

```csharp
// When client confirms DO MCCP2:
await SendRawAsync(new byte[] { IAC, SB, MCCP2, IAC, SE });
// Everything after this marker is compressed.
_compressedOutput = new ZLibStream(
    _outputStream, CompressionLevel.Fastest, leaveOpen: true);
_activeOutputStream = _compressedOutput;
```

The compressed stream stays active for the remainder of the session. MCCP2 is server-to-client only — input is never compressed.

### MCCP3 Implementation

MCCP3 differs from MCCP2 in that compression is per-message rather than per-session. The server wraps individual output blocks:

```csharp
// MCCP3: each output "message" is independently compressed.
// The client sees: IAC SB MCCP3 <compressed-data> IAC SE
private async ValueTask SendMccp3Async(ReadOnlyMemory<byte> data,
                                        CancellationToken ct)
{
    await SendRawAsync(new byte[] { IAC, SB, MCCP3 }, ct);

    using var ms = new MemoryStream();
    using (var zlib = new ZLibStream(ms, CompressionLevel.Fastest,
                                      leaveOpen: true))
    {
        await zlib.WriteAsync(data, ct);
    }
    await SendRawAsync(ms.ToArray(), ct);
    await SendRawAsync(new byte[] { IAC, SE }, ct);
}
```

If a client negotiates both MCCP2 and MCCP3, MCCP3 takes precedence. The transport tracks which compression mode is active via `TelnetOptionState`.

### MSDP Implementation

MSDP uses its own sub-protocol within telnet subnegotiations. The payload uses these framing bytes:

| Byte | Name | Purpose |
|------|------|---------|
| 1 | MSDP_VAR | Introduces a variable name |
| 2 | MSDP_VAL | Introduces a variable value |
| 3 | MSDP_TABLE_OPEN | Start of a table/object |
| 4 | MSDP_TABLE_CLOSE | End of a table/object |
| 5 | MSDP_ARRAY_OPEN | Start of an array |
| 6 | MSDP_ARRAY_CLOSE | End of an array |

Example: Server reporting character health:
```
IAC SB MSDP MSDP_VAR "HEALTH" MSDP_VAL "87" IAC SE
```

The `MsdpHandler` maintains a set of variables the client has subscribed to via `REPORT`, and pushes updates when those values change.

### GMCP Implementation

GMCP subnegotiation payload is a UTF-8 string: `"Package.Name <optional-json>"`.

```
IAC SB GMCP "Char.Vitals {\"hp\":87,\"maxhp\":100,\"mana\":45}" IAC SE
```

Common packages to support:
- `Core.Hello` — client identification
- `Core.Supports.Set` — client declares supported packages
- `Char.Vitals` — hp, mana, movement, etc.
- `Char.Status` — level, class, race, etc.
- `Room.Info` — current room vnum, name, exits
- `Comm.Channel` — structured channel messages

For WebSocket clients, GMCP data is sent as JSON text frames with a wrapper:
```json
{"gmcp": "Char.Vitals", "data": {"hp": 87, "maxhp": 100, "mana": 45}}
```

### MSSP Implementation

MSSP responds to crawler queries with game metadata. When a client sends `DO MSSP`, the server replies with:

```
IAC SB MSSP
  MSSP_VAR "NAME"       MSSP_VAL "Wheel of Lore"
  MSSP_VAR "PLAYERS"    MSSP_VAL "42"
  MSSP_VAR "UPTIME"     MSSP_VAL "1711234567"
  MSSP_VAR "CODEBASE"   MSSP_VAL "WoL Custom"
  MSSP_VAR "WEBSITE"    MSSP_VAL "https://example.com"
  MSSP_VAR "LANGUAGE"   MSSP_VAL "English"
  MSSP_VAR "FAMILY"     MSSP_VAL "Custom"
  MSSP_VAR "PORT"       MSSP_VAL "6969"
  MSSP_VAR "SSL"        MSSP_VAL "6969"
IAC SE
```

MSSP_VAR is 1, MSSP_VAL is 2 (same byte values as MSDP but different context since they're inside an MSSP subnegotiation).

## WebSocket Handshake

For both WS and WSS, after detecting an HTTP GET request:

1. Read the full HTTP request headers (up to `\r\n\r\n`, max 8KB)
2. Validate required headers:
   - `Upgrade: websocket` (case-insensitive token match)
   - `Connection: Upgrade`
   - `Sec-WebSocket-Version: 13`
   - `Sec-WebSocket-Key: <base64-encoded 16 bytes>`
3. Check for optional `Sec-WebSocket-Protocol` header. If the client requests `gmcp`, echo it back to enable structured out-of-band messaging.
4. Compute accept key: `Base64(SHA1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`
5. Send response:
   ```
   HTTP/1.1 101 Switching Protocols\r\n
   Upgrade: websocket\r\n
   Connection: Upgrade\r\n
   Sec-WebSocket-Accept: <computed>\r\n
   Sec-WebSocket-Protocol: gmcp\r\n        (only if requested)
   \r\n
   ```

If the HTTP request is a GET but **not** a WebSocket upgrade (no `Upgrade` header), treat it as an HTTP request instead — serve GSGP JSON (`GET /gsgp`), a who list (`GET /who`), or a 404, then close. This lets the single port double as a lightweight status endpoint.

### Frame Handling

After the handshake completes, we use .NET's `WebSocket.CreateFromStream()` to handle frame-level I/O, avoiding manual frame parsing:

```csharp
// After completing the HTTP 101 handshake on our raw stream:
var ws = WebSocket.CreateFromStream(
    stream, new WebSocketCreationOptions
    {
        IsServer = true,
        KeepAliveInterval = TimeSpan.FromSeconds(30),  // auto ping/pong
    });
```

This gives us:
- Automatic ping/pong keepalive (every 30s)
- Proper close handshake (opcode 0x8)
- Unmasking of client frames
- Fragment reassembly
- Binary and text frame support

**Outbound sanitization:** Before sending text to WebSocket clients, the transport strips any embedded IAC sequences and ANSI color codes that may have leaked from the shared output path. WebSocket clients receive clean text or structured JSON.

### WebSocket Message Protocol

WebSocket clients communicate using JSON text frames:

```json
// Client -> Server: regular command
{"type": "command", "data": "look"}

// Client -> Server: GMCP message
{"type": "gmcp", "package": "Core.Hello", "data": {"client": "WoL Web", "version": "1.0"}}

// Server -> Client: regular output
{"type": "output", "data": "You are standing in a dark forest.\r\n"}

// Server -> Client: GMCP message
{"type": "gmcp", "package": "Char.Vitals", "data": {"hp": 87, "maxhp": 100}}

// Server -> Client: prompt
{"type": "prompt", "data": "<87hp 45mn 120mv> "}
```

This structured format makes it straightforward for web clients to separate game output from out-of-band data, and to render prompts distinctly from narrative text.

## Authentication Flow

Authentication is protocol-aware: telnet uses sequential line-by-line prompts; WebSocket uses structured JSON messages so the web client can present a proper login/registration form.

### Telnet Authentication

The telnet flow is a line-mode conversation driven by `TelnetAuthFlow`:

```
Server: =============================================
Server:       Welcome to Wheel of Lore
Server: =============================================
Server:
Server: Enter your account email:
Client: player@example.com

--- If account exists ---
Server: Password:                          (ECHO off: IAC WILL ECHO)
Client: ********
  -> Correct:
     Server:                               (ECHO on: IAC WONT ECHO)
     Server: Welcome back, player@example.com!
     -> State: Authenticated (proceed to character select/play)
  -> Incorrect:
     Server:                               (ECHO on: IAC WONT ECHO)
     Server: Incorrect password. Disconnecting.
     -> Close connection

--- If account does not exist ---
Server: No account found for player@example.com.
Server: Would you like to create a new account? (yes/no)
Client: yes
Server: Confirm email — is player@example.com correct? (yes/no)
Client: yes
Server: Choose a password:                 (ECHO off)
Client: ********
Server: Confirm password:
Client: ********
  -> Passwords match:
     Server:                               (ECHO on)
     Server: Account created! Welcome, player@example.com!
     -> State: Authenticated
  -> Passwords don't match:
     Server:                               (ECHO on)
     Server: Passwords do not match. Disconnecting.
     -> Close connection
```

Key details:
- **ECHO toggling:** `IAC WILL ECHO` tells the client "I will echo, so you stop echoing locally" — effectively hiding input. `IAC WONT ECHO` re-enables client local echo. This is standard MUD practice for password entry.
- **No retry loops:** A wrong password immediately disconnects. This is deliberate — it prevents brute-force attempts and matches ACK!TNG behavior. Rate limiting at the connection level provides additional protection.
- **Login timeout:** The 180-second login timeout applies to the entire auth flow. If the player goes idle mid-registration, the connection closes.

```csharp
public class TelnetAuthFlow
{
    public async Task<AuthResult> RunAsync(
        IProtocolTransport transport,
        IAccountRepository accounts,
        CancellationToken ct)
    {
        await transport.SendAsync(Encoding.UTF8.GetBytes(LOGIN_BANNER), ct);
        await transport.SendAsync(
            "Enter your account email: "u8.ToArray(), ct);
        await transport.FlushAsync(ct);

        var emailResult = await transport.ReceiveAsync(ct);
        if (!emailResult.Success) return AuthResult.Disconnected;
        var email = emailResult.Line!.Trim().ToLowerInvariant();

        var account = await accounts.FindByEmailAsync(email, ct);

        if (account != null)
            return await HandleLoginAsync(transport, account, ct);
        else
            return await HandleRegistrationAsync(transport, email,
                                                  accounts, ct);
    }

    private async Task<AuthResult> HandleLoginAsync(
        IProtocolTransport transport,
        Account account,
        CancellationToken ct)
    {
        // Suppress client echo for password entry.
        await transport.SendAsync(
            new byte[] { IAC, WILL, TELOPT_ECHO }, ct);
        await transport.SendAsync("Password: "u8.ToArray(), ct);
        await transport.FlushAsync(ct);

        var pwResult = await transport.ReceiveAsync(ct);

        // Re-enable client echo.
        await transport.SendAsync(
            new byte[] { IAC, WONT, TELOPT_ECHO }, ct);

        if (!pwResult.Success) return AuthResult.Disconnected;

        if (!PasswordHasher.Verify(pwResult.Line!, account.PasswordHash))
        {
            await transport.SendAsync(
                "\r\nIncorrect password. Disconnecting.\r\n"u8.ToArray(), ct);
            await transport.FlushAsync(ct);
            return AuthResult.Failed;
        }

        await transport.SendAsync(
            $"\r\nWelcome back, {account.Email}!\r\n"u8(ct), ct);
        return AuthResult.Success(account);
    }
}
```

### WebSocket Authentication

WebSocket clients present a login form or registration form in their UI. The auth flow is a single JSON message exchange rather than sequential prompts:

```json
// --- Login ---
// Client -> Server:
{"type": "auth", "action": "login", "email": "player@example.com", "password": "secret"}

// Server -> Client (success):
{"type": "auth", "status": "ok", "message": "Welcome back, player@example.com!"}

// Server -> Client (failure — wrong password):
{"type": "auth", "status": "error", "message": "Incorrect password."}
// Connection closed by server.

// Server -> Client (failure — no such account):
{"type": "auth", "status": "no_account", "email": "player@example.com",
 "message": "No account found. Please register."}

// --- Registration ---
// Client -> Server:
{"type": "auth", "action": "register", "email": "player@example.com",
 "password": "secret", "confirm_password": "secret"}

// Server -> Client (success):
{"type": "auth", "status": "ok", "message": "Account created! Welcome!"}

// Server -> Client (failure — passwords don't match):
{"type": "auth", "status": "error", "message": "Passwords do not match."}
// Connection closed by server.

// Server -> Client (failure — account already exists):
{"type": "auth", "status": "error", "message": "An account with that email already exists."}
// Connection remains open so client can retry with login.
```

Key differences from telnet:
- **Stateless request/response:** The web client sends all auth fields in one message. No multi-step prompting.
- **No echo toggling:** The web UI handles password field masking natively.
- **Retry on "account exists":** Unlike telnet, the WS client keeps the connection open if the email already exists, so the user can switch to the login form without reconnecting.
- **No retry on wrong password:** Same as telnet — wrong password closes the connection to prevent brute force.

```csharp
public class WebSocketAuthFlow
{
    public async Task<AuthResult> RunAsync(
        IProtocolTransport transport,
        IAccountRepository accounts,
        CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var msg = await transport.ReceiveAsync(ct);
            if (!msg.Success) return AuthResult.Disconnected;

            var request = JsonSerializer.Deserialize<AuthRequest>(msg.Line!);
            if (request == null) continue;

            switch (request.Action)
            {
                case "login":
                    return await HandleLoginAsync(transport, request,
                                                   accounts, ct);
                case "register":
                    var result = await HandleRegisterAsync(transport, request,
                                                            accounts, ct);
                    if (result.Status == AuthStatus.AccountExists)
                    {
                        // Keep connection open — client can retry.
                        await SendAuthResponse(transport,
                            "error", "An account with that email already exists.", ct);
                        continue;
                    }
                    return result;

                default:
                    await SendAuthResponse(transport,
                        "error", "Unknown auth action.", ct);
                    continue;
            }
        }
        return AuthResult.Disconnected;
    }
}
```

### Password Hashing

Passwords are hashed using `Rfc2898DeriveBytes` (PBKDF2) with SHA-256, a random 16-byte salt, and 100,000 iterations. The stored hash format is `$pbkdf2-sha256$100000$<base64-salt>$<base64-hash>`.

ACK!TNG uses SHA-256 directly; we use PBKDF2 for proper key stretching.

### Session Takeover

When a player authenticates with an email that already has an active session (e.g., their old connection died silently):

1. The `ConnectionManager` looks up existing sessions by account email
2. The old session receives: `"\r\nAnother connection has logged in with your account. Disconnecting.\r\n"`
3. The old session is closed and removed
4. The new session inherits the player's game state (character, room, etc.)

This handles the dead-socket problem — a player whose internet drops can reconnect immediately without waiting for TCP keepalive to expire.

## Session Lifecycle

```
  TCP Accept
      |
      v
  [Pre-check] --- Ban list, max connections, rate limit
      |
      v
  [Detecting] --- ProtocolDetector.DetectAndWrapAsync()
      |            MSG_PEEK first 4 bytes, route to protocol
      v
  [Negotiating] --- transport.NegotiateAsync()
      |              Telnet: IAC WILL/DO exchange
      |              WS: handshake already complete (no-op)
      v
  [Authenticating] --- AuthFlow.RunAsync()
      |                 Telnet: line-by-line email/password prompts
      |                 WS: JSON auth message exchange
      |                 Timeout: 180s for entire auth phase
      v
  [Playing] --- Main session loop
      |          Input:  ReceiveAsync() -> game loop command queue
      |          Output: game loop output queue -> SendAsync()
      |          Idle timeout: configurable (default 1hr)
      |          Snooping: admin can attach SnoopLink
      v
  [Closed] --- Graceful quit, timeout, kicked, or error
               Flush output buffer
               Save character state
               Remove from ConnectionManager
               Dispose transport
               Close TCP
```

### Snoop Support

Admins can watch another player's session. This is implemented as a linked list of `SnoopLink` objects on the target session:

```csharp
public class SnoopLink
{
    public ClientSession Snooper { get; }
    public bool SeeInput { get; }   // see what the target types
    public bool SeeOutput { get; }  // see what the target sees
}
```

When the session sends output or receives input, it iterates its snoop links and forwards a copy. This must be built into `ClientSession` from the start — bolting it on later requires touching every I/O path.

## Connection Manager

```csharp
public class ConnectionManager
{
    private readonly ConcurrentDictionary<Guid, ClientSession> _sessions = new();
    private int _count;

    public int Count => _count;

    public void Add(ClientSession session)
    {
        if (_sessions.TryAdd(session.Id, session))
            Interlocked.Increment(ref _count);
    }

    public void Remove(Guid id)
    {
        if (_sessions.TryRemove(id, out _))
            Interlocked.Decrement(ref _count);
    }

    /// Find an active session by account email (for session takeover).
    public ClientSession? FindByEmail(string email) =>
        _sessions.Values.FirstOrDefault(s =>
            s.State == SessionState.Playing &&
            s.AccountEmail?.Equals(email, StringComparison.OrdinalIgnoreCase) == true);

    /// All sessions currently in the Playing state.
    public IEnumerable<ClientSession> ActiveSessions =>
        _sessions.Values.Where(s => s.State == SessionState.Playing);

    /// Broadcast to all active sessions with optional filter.
    public async Task BroadcastAsync(string text,
        Func<ClientSession, bool>? filter = null,
        CancellationToken ct = default)
    {
        var targets = filter != null
            ? ActiveSessions.Where(filter)
            : ActiveSessions;

        // Fan out sends in parallel; isolate per-session errors.
        await Parallel.ForEachAsync(targets, ct, async (session, token) =>
        {
            try
            {
                await session.SendOutputAsync(text, token);
            }
            catch (Exception)
            {
                // Session will be cleaned up by its own error handler.
            }
        });
    }
}
```

## Output Buffering and Prompts

MUDs don't send output line-by-line. A single command can trigger a room description, combat messages, channel chatter from other players, and a prompt — all batched into one write. The `OutputBuffer` accumulates output during a game tick and flushes it with a trailing prompt.

```csharp
public class OutputBuffer
{
    private readonly StringBuilder _pending = new();
    private string? _prompt;

    /// Queue text to be sent on next flush.
    public void Write(string text) => _pending.Append(text);

    /// Set the prompt to append after flushing output.
    public void SetPrompt(string prompt) => _prompt = prompt;

    /// Flush all pending output + prompt to the transport.
    public async ValueTask FlushAsync(IProtocolTransport transport,
                                       CancellationToken ct)
    {
        if (_pending.Length == 0 && _prompt == null)
            return;

        if (_prompt != null)
            _pending.Append(_prompt);

        var text = _pending.ToString();
        _pending.Clear();

        // Protocol-specific encoding happens inside the transport.
        await transport.SendAsync(
            Encoding.UTF8.GetBytes(text), ct);
        await transport.FlushAsync(ct);
    }
}
```

For WebSocket clients, `SendAsync` wraps the text in a `{"type": "output", "data": "..."}` JSON frame. The prompt is sent separately as `{"type": "prompt", "data": "..."}` so the web UI can render it distinctly (e.g., in a fixed status bar).

## Game Loop Boundary

This is the hardest architectural problem. MUDs need a single-threaded tick-based game loop (combat rounds, area resets, regeneration, weather). But each socket session runs on its own async task. These two models must meet at a well-defined boundary.

### Design: Command Queue + Output Queue

```
  Session Tasks (async, many)         Game Loop (single thread, one)
  ──────────────────────────          ─────────────────────────────
  ReceiveAsync() -> parse
       |
       v
  ┌─────────────────────┐            ┌──────────────────────────┐
  │  CommandQueue        │ ────────> │  Drain commands           │
  │  (ConcurrentQueue)   │           │  Execute game logic       │
  └─────────────────────┘            │  Queue output per-session │
                                     └──────────┬───────────────┘
                                                 |
  ┌─────────────────────┐                        v
  │  OutputBuffer        │ <──────── ┌──────────────────────────┐
  │  (per session)       │           │  Enqueue output text      │
  └──────────┬──────────┘            └──────────────────────────┘
             |
             v
  FlushAsync() -> SendAsync()
```

```csharp
// Each session pushes commands into a thread-safe queue.
public record GameCommand(ClientSession Session, string Line);

public class GameCommandQueue
{
    private readonly ConcurrentQueue<GameCommand> _queue = new();

    public void Enqueue(GameCommand cmd) => _queue.Enqueue(cmd);

    public bool TryDequeue(out GameCommand? cmd) => _queue.TryDequeue(out cmd);
}
```

The game loop runs on a dedicated thread (not the thread pool) via `Task.Factory.StartNew` with `TaskCreationOptions.LongRunning`. It ticks at a fixed rate (e.g., 100ms = 10 ticks/sec like ACK!TNG's `PULSE_PER_SECOND`), drains the command queue, processes game logic, and enqueues output to each session's `OutputBuffer`. After each tick, it signals sessions to flush their output.

This means:
- **Session tasks** only do I/O: read from transport, push to command queue, flush output buffer when signaled
- **Game loop** only does game logic: drain commands, execute, push output
- **No shared mutable game state** between async tasks — the game loop is the single owner

The socket layer design must accommodate this: `ClientSession.RunAsync()` alternates between reading input and flushing output, driven by a signaling mechanism (e.g., `SemaphoreSlim` or `Channel<T>`) from the game loop.

## Character Encoding

Telnet and WebSocket use different character encodings on the wire. The transport layer handles translation so the session/game logic always works with .NET `string` (UTF-16).

| Protocol | Wire Encoding | Notes |
|----------|--------------|-------|
| Telnet | Latin-1 (ISO-8859-1) | Default for most MUD clients. Extended ASCII chars (128-255) map 1:1 to Unicode. |
| Telnet-TLS | Latin-1 (ISO-8859-1) | Same as plain telnet. |
| WebSocket | UTF-8 | Required by RFC 6455 for text frames. |
| WebSocket Secure | UTF-8 | Same as plain WebSocket. |

```csharp
// In TelnetCodec:
private static readonly Encoding Latin1 = Encoding.Latin1;

public string DecodeInput(ReadOnlySpan<byte> raw) =>
    Latin1.GetString(raw);

public byte[] EncodeOutput(string text) =>
    Latin1.GetBytes(text);

// In WsCodec:
public string DecodeInput(ReadOnlySpan<byte> raw) =>
    Encoding.UTF8.GetString(raw);

public byte[] EncodeOutput(string text) =>
    Encoding.UTF8.GetBytes(text);
```

If a telnet client negotiates CHARSET (RFC 2066, option 42) and requests UTF-8, the telnet codec switches to UTF-8 encoding. This is optional and not commonly supported by MUD clients, but the codec is designed to allow it.

## Configuration

```json
{
  "Server": {
    "Port": 6969,
    "TlsCertPath": "/etc/letsencrypt/live/example.com/fullchain.pem",
    "TlsKeyPath": "/etc/letsencrypt/live/example.com/privkey.pem",
    "DetectionTimeoutMs": 1000,
    "LoginTimeoutSeconds": 180,
    "IdleTimeoutSeconds": 3600,
    "MaxConnections": 256,
    "BindAddress": "::",
    "EnableIPv6DualStack": true,
    "TcpKeepAliveTimeSec": 60,
    "TcpKeepAliveIntervalSec": 10,
    "TcpKeepAliveRetryCount": 3,
    "RateLimitPerIp": 5,
    "RateLimitWindowSeconds": 60
  }
}
```

```csharp
public class ServerOptions
{
    public int Port { get; set; } = 6969;
    public string? TlsCertPath { get; set; }
    public string? TlsKeyPath { get; set; }
    public TimeSpan DetectionTimeout { get; set; } = TimeSpan.FromSeconds(1);
    public TimeSpan LoginTimeout { get; set; } = TimeSpan.FromSeconds(180);
    public TimeSpan IdleTimeout { get; set; } = TimeSpan.FromHours(1);
    public int MaxConnections { get; set; } = 256;
    public string BindAddress { get; set; } = "::";
    public bool EnableIPv6DualStack { get; set; } = true;
    public int TcpKeepAliveTimeSec { get; set; } = 60;
    public int TcpKeepAliveIntervalSec { get; set; } = 10;
    public int TcpKeepAliveRetryCount { get; set; } = 3;
    public int RateLimitPerIp { get; set; } = 5;
    public int RateLimitWindowSeconds { get; set; } = 60;
}
```

When no TLS certificate is configured, TLS/WSS connections are rejected at detection time with a log warning. This allows running in dev mode with telnet/WS only.

## .NET Implementation Notes

### Why Not Kestrel?

Kestrel is optimized for HTTP and would add overhead for raw telnet. By using `TcpListener` directly:
- Full control over the byte stream from the first byte (needed for MSG_PEEK detection)
- No HTTP parsing overhead for telnet connections
- Simpler protocol detection (no middleware pipeline to work around)
- Lower memory footprint per connection

An optional Kestrel endpoint on a separate port can serve HTTP REST APIs (GSGP/who) later if the single-port HTTP handling proves insufficient.

### System.IO.Pipelines

For the telnet codecs, `System.IO.Pipelines` (`PipeReader`/`PipeWriter`) should be used rather than raw `Stream.ReadAsync`:

- Zero-copy buffer management via pooled memory
- Backpressure when a client isn't reading fast enough (slow reader won't cause unbounded server memory growth)
- Efficient partial-read handling (critical for IAC parsing where a single `Read` may return half an IAC sequence)

```csharp
// In TelnetCodec constructor:
_reader = PipeReader.Create(_stream, new StreamPipeReaderOptions(
    minimumReadSize: 256));
_writer = PipeWriter.Create(_stream);
```

### Thread Safety

- Each `ClientSession` runs on its own async task
- Session tasks only do I/O; they do not access shared game state directly
- Game state is owned exclusively by the single-threaded game loop
- `ConnectionManager` uses `ConcurrentDictionary` with an `Interlocked` counter
- `GameCommandQueue` uses `ConcurrentQueue` — lock-free, thread-safe
- Broadcast operations isolate per-session errors so one broken connection doesn't block others

## Comparison with ACK!TNG

| Aspect | ACK!TNG | This Design |
|--------|---------|-------------|
| Language | C + OpenSSL | C# .NET 8+ |
| Ports required | 6 | 1 (single port serves all protocols) |
| Protocol detection | TLS sniffing on sniff port only | MSG_PEEK auto-detect on single port |
| WebSocket | nginx loopback required | Native in-process |
| TLS library | OpenSSL (manual, blocking) | SslStream (managed, async) |
| TLS cert reload | Manual restart | FileSystemWatcher + per-connection callback |
| I/O model | select() loop, single-threaded | async/await per session + single-threaded game loop |
| Telnet options | ECHO, SGA, NAWS, MSSP, MSDP, GMCP, MCCP2, MCCP3 | All the same |
| Authentication | In-band telnet prompts only | Telnet prompts + WebSocket JSON auth |
| Compression | MCCP2 + MCCP3 (raw zlib) | MCCP2 + MCCP3 (ZLibStream) |
| Encoding | Implicit Latin-1 | Explicit Latin-1 (telnet) / UTF-8 (WebSocket) |
| Dead socket detection | Idle timeout only | TCP keepalive + idle timeout + session takeover |
| Hot reboot | FD inheritance via exec() | Connection draining (future work) |
| Password storage | SHA-256 | PBKDF2-SHA256 with salt + iterations |

## Known Limitations and Risks

### Protocol Detection Edge Cases

- **Auto-login clients sending "GET " as first bytes:** Theoretically possible but not a realistic scenario. A telnet client would need to auto-send exactly `"GET "` before the server sends any prompt. No known MUD client does this.
- **Malformed TLS:** If a client sends `0x16` followed by garbage, `SslStream.AuthenticateAsServerAsync` will throw. This is handled by the catch block in `HandleConnectionAsync` — the connection is logged and closed.
- **Slow TLS handshake:** The 1-second detection timeout only applies to the initial peek. The TLS handshake itself has no explicit timeout. A client could stall during the handshake to hold resources. Consider adding a separate TLS handshake timeout.

### PROXY Protocol (Future)

If deployed behind HAProxy or CloudFlare, the PROXY protocol v1/v2 header arrives **before** any application data, including TLS ClientHello. This changes the detection order:

```
PROXY header -> strip, extract real IP -> then normal detection
```

This must be decided before deployment behind a reverse proxy. The detection algorithm can be extended: PROXY v1 starts with `"PROXY "` (6 bytes) and PROXY v2 starts with a 12-byte magic sequence. Neither conflicts with TLS (0x16), HTTP (`"GET "`), or telnet.

### Hot Reboot

ACK!TNG inherits file descriptors via `exec()`. .NET doesn't support FD inheritance across process boundaries in the same way. Options:
1. **Connection draining:** Notify all clients "Rebooting...", save state, restart, clients reconnect
2. **Unix domain socket handoff:** Pass active connections to the new process via ancillary messages (Linux only, complex)
3. **In-process reload:** Reload game data without restarting the process (limited scope)

Connection draining is the most practical initial approach.

### Concurrency Hazards

- `SslStream` prior to .NET 6 does not support concurrent reads and writes. Since we're targeting .NET 8+, this is not an issue — but worth noting for compatibility.
- The `OutputBuffer` is written by the game loop thread and flushed by the session's async task. Access must be synchronized (e.g., lock or `Channel<string>`).

## Future Considerations

- **CHARSET (RFC 2066, option 42):** Allow telnet clients to negotiate UTF-8 encoding
- **MXP (MUD eXtension Protocol, option 91):** Rich text markup for supporting clients
- **ATCP (Achaea Telnet Client Protocol):** Precursor to GMCP, used by some IRE clients
- **HTTP REST API expansion:** GSGP, who list, admin endpoints on the same port
- **Metrics/observability:** Connection counts, protocol breakdown, auth success/failure rates
- **Configurable auth retry policy:** Currently one-shot fail for wrong passwords; could allow N retries
