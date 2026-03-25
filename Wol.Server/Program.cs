using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Wol.Server.Auth;
using Wol.Server.Network;

// Build configuration
// AppContext.BaseDirectory = directory of the compiled binary, regardless of working directory.
// Cert paths in appsettings.json are resolved relative to working directory (set by the service).
IConfiguration config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile("appsettings.json", optional: false)
    .AddEnvironmentVariables()
    .Build();

// Set up DI / logging
var services = new ServiceCollection();
services.AddLogging(b =>
{
    b.AddConsole();
    b.AddConfiguration(config.GetSection("Logging"));
});
services.AddSingleton<AccountStore>();
var provider = services.BuildServiceProvider();

var logger = provider.GetRequiredService<ILogger<ConnectionListener>>();

// Network config
int port = config.GetValue<int>("Network:Port", 6969);
int sniffMs = config.GetValue<int>("Network:SniffTimeoutMs", 1000);
string? certPath = config["Network:TlsCertPath"];
string? keyPath  = config["Network:TlsKeyPath"];

X509Certificate2? tlsCert = null;
if (!string.IsNullOrEmpty(certPath) && !string.IsNullOrEmpty(keyPath) &&
    File.Exists(certPath) && File.Exists(keyPath))
{
    try
    {
        tlsCert = X509Certificate2.CreateFromPemFile(certPath, keyPath);
        logger.LogInformation("TLS certificate loaded from {Cert}", certPath);
    }
    catch (Exception ex)
    {
        logger.LogWarning("Failed to load TLS certificate: {Message} — TLS disabled.", ex.Message);
    }
}
else
{
    logger.LogWarning("TLS cert/key not found — TLS and WSS disabled.");
}

var accounts = provider.GetRequiredService<AccountStore>();
var listenerLogger = provider.GetRequiredService<ILogger<ConnectionListener>>();

var listener = new ConnectionListener(
    port,
    tlsCert,
    TimeSpan.FromMilliseconds(sniffMs),
    accounts,
    listenerLogger);

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

// Health/metrics server on internal interface (separate from game traffic on :6969)
var healthBindAddress = config["Health:BindAddress"] ?? "0.0.0.0";
var healthPort = config.GetValue<int>("Health:Port", 8443);
var healthTask = Wol.Server.Health.HealthServer.RunAsync(
    healthBindAddress, healthPort, provider.GetRequiredService<ILoggerFactory>(), cts.Token);

logger.LogInformation("WOL server starting. Health: {Bind}:{Port}. Press Ctrl+C to stop.",
    healthBindAddress, healthPort);
await Task.WhenAny(listener.RunAsync(cts.Token), healthTask);
cts.Cancel();
logger.LogInformation("WOL server stopped.");
