using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Wol.Server.Auth;

namespace Wol.Server.Network;

public sealed class ConnectionListener
{
    private readonly int _port;
    private readonly X509Certificate2? _tlsCert;
    private readonly TimeSpan _sniffTimeout;
    private readonly AccountStore _accounts;
    private readonly ILogger<ConnectionListener> _logger;

    public ConnectionListener(
        int port,
        X509Certificate2? tlsCert,
        TimeSpan sniffTimeout,
        AccountStore accounts,
        ILogger<ConnectionListener> logger)
    {
        _port = port;
        _tlsCert = tlsCert;
        _sniffTimeout = sniffTimeout;
        _accounts = accounts;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        var listener = new TcpListener(IPAddress.Any, _port);
        listener.Start();
        _logger.LogInformation("Listening on port {Port} (TLS {TlsStatus})",
            _port, _tlsCert != null ? "enabled" : "disabled — plain only");

        try
        {
            while (!ct.IsCancellationRequested)
            {
                TcpClient client = await listener.AcceptTcpClientAsync(ct);
                _ = Task.Run(() => HandleClientAsync(client, ct), ct);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken ct)
    {
        string remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _logger.LogDebug("Accepted connection from {Remote}", remote);

        try
        {
            client.NoDelay = true;
            var peekable = new PeekableStream(client.GetStream());

            var (kind, stream) = await ProtocolDetector.DetectAsync(peekable, _tlsCert, _sniffTimeout, ct);
            _logger.LogDebug("{Remote} → {Protocol}", remote, kind);

            switch (kind)
            {
                case ProtocolKind.PlainTelnet:
                case ProtocolKind.TlsTelnet:
                {
                    await using var conn = new TelnetConnection(stream, remote, _accounts);
                    await conn.RunAsync();
                    break;
                }
                case ProtocolKind.WebSocket:
                case ProtocolKind.WebSocketSecure:
                {
                    await using var conn = new WebSocketConnection(stream, remote, _accounts);
                    await conn.RunAsync();
                    break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
            _logger.LogDebug("Connection from {Remote} closed: {Message}", remote, ex.Message);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled error on connection from {Remote}", remote);
        }
        finally
        {
            client.Dispose();
        }
    }
}
