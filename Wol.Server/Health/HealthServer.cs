using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Prometheus;

namespace Wol.Server.Health;

/// <summary>
/// Runs a lightweight Kestrel HTTP server on the internal network
/// for /health and /metrics endpoints. Separate from the main game
/// traffic listener (port 6969).
/// </summary>
public static class HealthServer
{
    public static async Task RunAsync(
        string bindAddress,
        int port,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(k => k.Listen(
            System.Net.IPAddress.Parse(bindAddress), port));
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(loggerFactory);

        var app = builder.Build();

        app.UseHttpMetrics();
        app.MapMetrics("/metrics");
        app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

        await app.StartAsync(ct);
        await Task.Delay(Timeout.Infinite, ct);
    }
}
