using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Prometheus;

namespace Wol.Server.Health;

/// <summary>
/// Background service that periodically pings the /health endpoint of
/// each configured dependency. Logs warnings and increments a Prometheus
/// counter when a dependency is unreachable.
/// </summary>
public sealed class DependencyHealthChecker : BackgroundService
{
    private readonly ILogger<DependencyHealthChecker> _logger;
    private readonly HttpClient _http;
    private readonly List<DependencyTarget> _targets;
    private readonly TimeSpan _interval;

    private static readonly Counter DependencyFailures = Metrics.CreateCounter(
        "dependency_health_failures_total",
        "Number of failed dependency health checks",
        new CounterConfiguration { LabelNames = new[] { "dependency" } });

    private static readonly Gauge DependencyUp = Metrics.CreateGauge(
        "dependency_up",
        "Whether a dependency is reachable (1 = up, 0 = down)",
        new GaugeConfiguration { LabelNames = new[] { "dependency" } });

    public DependencyHealthChecker(
        ILogger<DependencyHealthChecker> logger,
        IConfiguration config)
    {
        _logger = logger;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        _interval = TimeSpan.FromSeconds(
            int.Parse(config["DEPENDENCY_CHECK_INTERVAL_SECONDS"] ?? "15"));

        // Parse dependency URLs from env: DEPENDENCY_URLS=name1=url1,name2=url2
        _targets = new List<DependencyTarget>();
        var raw = config["DEPENDENCY_URLS"] ?? "";
        foreach (var entry in raw.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = entry.Split('=', 2);
            if (parts.Length == 2)
                _targets.Add(new DependencyTarget(parts[0].Trim(), parts[1].Trim()));
        }
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_targets.Count == 0)
        {
            _logger.LogInformation("No dependency URLs configured, health checker idle");
            return;
        }

        _logger.LogInformation("Monitoring {Count} dependencies every {Interval}s: {Names}",
            _targets.Count, _interval.TotalSeconds,
            string.Join(", ", _targets.Select(t => t.Name)));

        while (!stoppingToken.IsCancellationRequested)
        {
            foreach (var target in _targets)
            {
                try
                {
                    var response = await _http.GetAsync(target.Url, stoppingToken);
                    if (response.IsSuccessStatusCode)
                    {
                        DependencyUp.WithLabels(target.Name).Set(1);
                    }
                    else
                    {
                        DependencyUp.WithLabels(target.Name).Set(0);
                        DependencyFailures.WithLabels(target.Name).Inc();
                        _logger.LogWarning(
                            "Dependency {Name} returned {Status} at {Url}",
                            target.Name, (int)response.StatusCode, target.Url);
                    }
                }
                catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
                {
                    DependencyUp.WithLabels(target.Name).Set(0);
                    DependencyFailures.WithLabels(target.Name).Inc();
                    _logger.LogWarning(
                        "Dependency {Name} unreachable at {Url}: {Error}",
                        target.Name, target.Url, ex.Message);
                }
            }

            await Task.Delay(_interval, stoppingToken);
        }
    }

    private sealed record DependencyTarget(string Name, string Url);
}
