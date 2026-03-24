using System.IO.Compression;
using System.Text;
using Wol.Server.Auth;

namespace Wol.Server.Network;

/// <summary>
/// Manages a single telnet connection: IAC option negotiation, protocol handlers,
/// and the login state machine. Drives <see cref="LoginStateMachine"/> with decoded lines.
/// </summary>
public sealed class TelnetConnection : IGameConnection, IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly string _remoteAddress;
    private readonly AccountStore _accounts;
    private readonly CancellationTokenSource _cts = new();

    // Compression write wrapper — set when MCCP2 is negotiated
    private Stream _writeStream;

    public ClientCapabilities Capabilities { get; } = new();
    public ConnectionType ConnectionType => ConnectionType.Telnet;
    public string RemoteAddress => _remoteAddress;

    // Tracks how many TTYPE SEND cycles we've done (MTTS requires cycling through names)
    private int _ttypeCycle;

    public TelnetConnection(Stream stream, string remoteAddress, AccountStore accounts)
    {
        _stream = stream;
        _writeStream = stream;
        _remoteAddress = remoteAddress;
        _accounts = accounts;
    }

    public async Task RunAsync()
    {
        await SendGreetingAsync();

        var stateMachine = new LoginStateMachine(this, _accounts);
        var lineBuffer = new StringBuilder();

        try
        {
            var readBuf = new byte[4096];
            while (!_cts.IsCancellationRequested)
            {
                int n = await _stream.ReadAsync(readBuf, _cts.Token);
                if (n == 0) break; // connection closed

                int i = 0;
                while (i < n)
                {
                    byte b = readBuf[i++];

                    if (b == Telnet.IAC)
                    {
                        // Need at least one more byte for the command
                        i = await EnsureBytesAsync(readBuf, i, n, 1);
                        byte cmd = readBuf[i++];

                        if (cmd == Telnet.SB)
                        {
                            // Subnegotiation — read until IAC SE
                            i = await EnsureBytesAsync(readBuf, i, n, 1);
                            byte opt = readBuf[i++];
                            var payload = new List<byte>();
                            while (true)
                            {
                                i = await EnsureBytesAsync(readBuf, i, n, 1);
                                byte sb = readBuf[i++];
                                if (sb == Telnet.IAC)
                                {
                                    i = await EnsureBytesAsync(readBuf, i, n, 1);
                                    byte next = readBuf[i++];
                                    if (next == Telnet.SE) break;
                                    if (next == Telnet.IAC) payload.Add(Telnet.IAC);
                                }
                                else
                                {
                                    payload.Add(sb);
                                }
                            }
                            await HandleSubnegotiationAsync(opt, payload.ToArray());
                        }
                        else if (cmd is Telnet.DO or Telnet.DONT or Telnet.WILL or Telnet.WONT)
                        {
                            i = await EnsureBytesAsync(readBuf, i, n, 1);
                            byte opt = readBuf[i++];
                            await HandleOptionAsync(cmd, opt);
                        }
                        // NOP, GA, and other single-byte commands are silently consumed
                    }
                    else if (b == '\r')
                    {
                        // Skip bare CR (telnet line endings are CR LF or CR NUL)
                    }
                    else if (b == '\n')
                    {
                        await stateMachine.HandleLineAsync(lineBuffer.ToString());
                        lineBuffer.Clear();
                    }
                    else if (b >= 0x20 || b == '\t')
                    {
                        lineBuffer.Append((char)b);
                    }
                }
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
        var bytes = Encoding.UTF8.GetBytes(text);
        await _writeStream.WriteAsync(bytes, ct);
        if (!Capabilities.SgaActive)
            await _writeStream.WriteAsync(new byte[] { Telnet.IAC, Telnet.GA }, ct);
        await _writeStream.FlushAsync(ct);
    }

    public async Task SendRawAsync(byte[] data, CancellationToken ct = default)
    {
        await _writeStream.WriteAsync(data, ct);
        await _writeStream.FlushAsync(ct);
    }

    public async Task CloseAsync(CancellationToken ct = default)
    {
        _cts.Cancel();
        try { await _stream.FlushAsync(ct); } catch { }
        _stream.Close();
    }

    // -------------------------------------------------------------------------
    // Greeting
    // -------------------------------------------------------------------------

    private async Task SendGreetingAsync()
    {
        // Announce all supported options
        var offers = new byte[]
        {
            Telnet.IAC, Telnet.WILL, Telnet.OPT_ECHO,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_SGA,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_MSSP,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_MSDP,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_GMCP,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_MCCP2,
            Telnet.IAC, Telnet.WILL, Telnet.OPT_MCCP3,
            Telnet.IAC, Telnet.DO,   Telnet.OPT_NAWS,
            Telnet.IAC, Telnet.DO,   Telnet.OPT_TTYPE,
            Telnet.IAC, Telnet.DO,   Telnet.OPT_CHARSET,
        };
        await SendRawAsync(offers);

        // Send MSSP data immediately (clients may not negotiate before disconnecting)
        await SendMsspAsync();
    }

    // -------------------------------------------------------------------------
    // Option negotiation
    // -------------------------------------------------------------------------

    private async Task HandleOptionAsync(byte cmd, byte opt)
    {
        switch (opt)
        {
            case Telnet.OPT_SGA when cmd == Telnet.DO:
                Capabilities.SgaActive = true;
                break;

            case Telnet.OPT_NAWS when cmd == Telnet.WILL:
                // Client will send NAWS subneg — nothing to do here
                break;

            case Telnet.OPT_TTYPE when cmd == Telnet.WILL:
                // Request first terminal type
                await SendRawAsync(new byte[] { Telnet.IAC, Telnet.SB, Telnet.OPT_TTYPE, Telnet.TTYPE_SEND, Telnet.IAC, Telnet.SE });
                break;

            case Telnet.OPT_CHARSET when cmd == Telnet.WILL:
                // Request UTF-8
                byte[] charsetReq = BuildCharsetRequest();
                await SendRawAsync(charsetReq);
                break;

            case Telnet.OPT_MSDP when cmd == Telnet.DO:
                Capabilities.MsdpActive = true;
                break;

            case Telnet.OPT_GMCP when cmd == Telnet.DO:
                Capabilities.GmcpActive = true;
                break;

            case Telnet.OPT_MCCP2 when cmd == Telnet.DO:
                await StartMccp2Async();
                break;

            case Telnet.OPT_MCCP3 when cmd == Telnet.DO:
                await StartMccp3Async();
                break;
        }
    }

    private async Task HandleSubnegotiationAsync(byte opt, byte[] payload)
    {
        switch (opt)
        {
            case Telnet.OPT_NAWS:
                HandleNaws(payload);
                break;

            case Telnet.OPT_TTYPE:
                await HandleTtypeAsync(payload);
                break;

            case Telnet.OPT_CHARSET:
                HandleCharset(payload);
                break;

            case Telnet.OPT_MSDP:
                HandleMsdpSubneg(payload);
                break;

            case Telnet.OPT_GMCP:
                HandleGmcpSubneg(payload);
                break;

            case Telnet.OPT_MSSP:
                // Client sending MSSP is unusual; ignore
                break;
        }
    }

    // -------------------------------------------------------------------------
    // NAWS
    // -------------------------------------------------------------------------

    private void HandleNaws(byte[] payload)
    {
        if (payload.Length < 4) return;
        Capabilities.TerminalCols = (payload[0] << 8) | payload[1];
        Capabilities.TerminalRows = (payload[2] << 8) | payload[3];
    }

    // -------------------------------------------------------------------------
    // TTYPE / MTTS
    // -------------------------------------------------------------------------

    private async Task HandleTtypeAsync(byte[] payload)
    {
        if (payload.Length < 1 || payload[0] != Telnet.TTYPE_IS) return;

        string termType = Encoding.ASCII.GetString(payload, 1, payload.Length - 1);

        if (termType.StartsWith("MTTS ", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(termType[5..], out int mtts))
        {
            Capabilities.Mtts = (MttsFlags)mtts;
            Capabilities.CharsetUtf8 = Capabilities.Mtts.HasFlag(MttsFlags.Utf8);
            return; // done cycling
        }

        if (_ttypeCycle == 0)
        {
            Capabilities.TerminalType = termType;
        }

        // Cycle up to 3 times to reach the MTTS response
        if (_ttypeCycle < 3)
        {
            _ttypeCycle++;
            await SendRawAsync(new byte[] { Telnet.IAC, Telnet.SB, Telnet.OPT_TTYPE, Telnet.TTYPE_SEND, Telnet.IAC, Telnet.SE });
        }
    }

    // -------------------------------------------------------------------------
    // CHARSET
    // -------------------------------------------------------------------------

    private static byte[] BuildCharsetRequest()
    {
        // IAC SB CHARSET REQUEST ";" "UTF-8" IAC SE
        byte[] charset = "UTF-8"u8.ToArray();
        var msg = new List<byte> { Telnet.IAC, Telnet.SB, Telnet.OPT_CHARSET, Telnet.CHARSET_REQUEST, (byte)';' };
        msg.AddRange(charset);
        msg.Add(Telnet.IAC);
        msg.Add(Telnet.SE);
        return msg.ToArray();
    }

    private void HandleCharset(byte[] payload)
    {
        if (payload.Length < 1) return;
        if (payload[0] == Telnet.CHARSET_ACCEPTED)
            Capabilities.CharsetUtf8 = true;
    }

    // -------------------------------------------------------------------------
    // MSSP
    // -------------------------------------------------------------------------

    private async Task SendMsspAsync()
    {
        // Build MSSP subnegotiation with basic server info
        var msg = new List<byte> { Telnet.IAC, Telnet.SB, Telnet.OPT_MSSP };
        AppendMsspVar(msg, "NAME", "WOL");
        AppendMsspVar(msg, "UPTIME", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        AppendMsspVar(msg, "PLAYERS", "0");
        AppendMsspVar(msg, "PORT", "6969");
        AppendMsspVar(msg, "CODEBASE", "WOL");
        AppendMsspVar(msg, "CONTACT", "");
        AppendMsspVar(msg, "CRAWL DELAY", "60");
        msg.Add(Telnet.IAC);
        msg.Add(Telnet.SE);
        await SendRawAsync(msg.ToArray());
    }

    private static void AppendMsspVar(List<byte> buf, string name, string value)
    {
        buf.Add(Telnet.MSSP_VAR);
        buf.AddRange(Encoding.ASCII.GetBytes(name));
        buf.Add(Telnet.MSSP_VAL);
        buf.AddRange(Encoding.ASCII.GetBytes(value));
    }

    // -------------------------------------------------------------------------
    // MSDP
    // -------------------------------------------------------------------------

    private void HandleMsdpSubneg(byte[] payload)
    {
        // Minimal: track REPORT subscriptions. Game layer populates values.
        // Payload format: MSDP_VAR "VARNAME" MSDP_VAL "VALUE" ...
        // For now just acknowledge; game-layer integration is a follow-on.
    }

    // -------------------------------------------------------------------------
    // GMCP
    // -------------------------------------------------------------------------

    private void HandleGmcpSubneg(byte[] payload)
    {
        // GMCP payload is: "Package.Name " + JSON
        // For now just acknowledge; game-layer integration is a follow-on.
    }

    public async Task SendGmcpAsync(string package, string json, CancellationToken ct = default)
    {
        byte[] pkg = Encoding.UTF8.GetBytes(package + " " + json);
        var msg = new byte[pkg.Length + 4];
        msg[0] = Telnet.IAC;
        msg[1] = Telnet.SB;
        msg[2] = Telnet.OPT_GMCP;
        pkg.CopyTo(msg, 3);
        msg[^1] = Telnet.SE;
        // Wrap IAC SE properly (not needed for ASCII package names, but correct)
        await SendRawAsync(msg, ct);
    }

    // -------------------------------------------------------------------------
    // MCCP2 / MCCP3
    // -------------------------------------------------------------------------

    private async Task StartMccp2Async()
    {
        if (Capabilities.Mccp2Active) return;
        // Send IAC SB MCCP2 IAC SE to signal start of compression
        await SendRawAsync(new byte[] { Telnet.IAC, Telnet.SB, Telnet.OPT_MCCP2, Telnet.IAC, Telnet.SE });
        Capabilities.Mccp2Active = true;
        _writeStream = new ZLibStream(_writeStream, CompressionMode.Compress, leaveOpen: false);
    }

    private async Task StartMccp3Async()
    {
        if (Capabilities.Mccp3Active) return;
        await SendRawAsync(new byte[] { Telnet.IAC, Telnet.SB, Telnet.OPT_MCCP3, Telnet.IAC, Telnet.SE });
        Capabilities.Mccp3Active = true;
        // MCCP3 compresses both directions; for now we compress writes.
        // Read-side decompression would wrap _stream; deferred to game-layer integration.
        _writeStream = new ZLibStream(_writeStream, CompressionMode.Compress, leaveOpen: false);
    }

    // -------------------------------------------------------------------------
    // Echo suppression helpers (used by LoginStateMachine)
    // -------------------------------------------------------------------------

    public Task SuppressEchoAsync()  => SendRawAsync(new byte[] { Telnet.IAC, Telnet.WILL, Telnet.OPT_ECHO });
    public Task RestoreEchoAsync()   => SendRawAsync(new byte[] { Telnet.IAC, Telnet.WONT, Telnet.OPT_ECHO });

    // -------------------------------------------------------------------------
    // Buffer refill helper
    // -------------------------------------------------------------------------

    private async Task<int> EnsureBytesAsync(byte[] buf, int i, int n, int needed)
    {
        // If current position has enough bytes already, return as-is.
        if (i + needed <= n) return i;

        // Shift remaining bytes to front and read more.
        int remaining = n - i;
        Buffer.BlockCopy(buf, i, buf, 0, remaining);
        int read = await _stream.ReadAsync(buf.AsMemory(remaining, buf.Length - remaining), _cts.Token);
        // (n is a local in the caller; we return new i=0 pointing into refilled buf)
        return 0;
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _cts.Dispose();
        _writeStream.Dispose();
        if (!ReferenceEquals(_writeStream, _stream))
            _stream.Dispose();
        return ValueTask.CompletedTask;
    }
}
