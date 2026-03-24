namespace Wol.Server.Network;

public enum ConnectionType { Telnet, WebSocket }

public interface IGameConnection
{
    ConnectionType ConnectionType { get; }
    string RemoteAddress { get; }

    Task SendAsync(string text, CancellationToken ct = default);
    Task SendRawAsync(byte[] data, CancellationToken ct = default);
    Task CloseAsync(CancellationToken ct = default);
}
