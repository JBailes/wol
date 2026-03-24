using System.Text.Json;
using Wol.Server.Network;

namespace Wol.Server.Auth;

/// <summary>
/// Email-based login/registration flow for both telnet and WebSocket connections.
///
/// Telnet: driven by text lines via <see cref="HandleLineAsync"/>.
/// WebSocket: driven by JSON messages via <see cref="HandleJsonAsync"/>.
/// </summary>
public sealed class LoginStateMachine
{
    private enum State
    {
        PromptEmail,
        PromptPassword,
        ConfirmNewEmail,
        PromptNewPassword,
        PromptConfirmPassword,
        LoggedIn,
    }

    private readonly IGameConnection _conn;
    private readonly AccountStore _accounts;

    private State _state = State.PromptEmail;
    private string _email = string.Empty;
    private string _newPassword = string.Empty;

    public LoginStateMachine(IGameConnection conn, AccountStore accounts)
    {
        _conn = conn;
        _accounts = accounts;

        // Telnet: send initial prompt after construction
        if (conn.ConnectionType == ConnectionType.Telnet)
            _ = SendPromptAsync();
    }

    // -------------------------------------------------------------------------
    // Telnet entry point
    // -------------------------------------------------------------------------

    public async Task HandleLineAsync(string line)
    {
        line = line.Trim();

        switch (_state)
        {
            case State.PromptEmail:
                await HandleEmailInputAsync(line);
                break;

            case State.PromptPassword:
                await HandlePasswordInputAsync(line);
                break;

            case State.ConfirmNewEmail:
                await HandleConfirmEmailAsync(line);
                break;

            case State.PromptNewPassword:
                await HandleNewPasswordInputAsync(line);
                break;

            case State.PromptConfirmPassword:
                await HandleConfirmPasswordAsync(line);
                break;
        }
    }

    // -------------------------------------------------------------------------
    // WebSocket entry point
    // -------------------------------------------------------------------------

    public async Task HandleJsonAsync(string json)
    {
        JsonElement root;
        try { root = JsonSerializer.Deserialize<JsonElement>(json); }
        catch { await SendWsErrorAsync("Invalid JSON."); return; }

        string action = root.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";

        switch (action)
        {
            case "login":
            {
                string email    = root.TryGetProperty("email",    out var e) ? e.GetString() ?? "" : "";
                string password = root.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";

                if (!_accounts.Exists(email))
                {
                    await SendWsJsonAsync(new { status = "register_required" });
                    return;
                }
                if (!_accounts.Verify(email, password))
                {
                    await SendWsJsonAsync(new { status = "error", message = "Wrong password." });
                    await _conn.CloseAsync();
                    return;
                }
                _email = email;
                _state = State.LoggedIn;
                await SendWsJsonAsync(new { status = "ok", email });
                break;
            }

            case "register":
            {
                string email    = root.TryGetProperty("email",    out var e) ? e.GetString() ?? "" : "";
                string password = root.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
                string confirm  = root.TryGetProperty("confirm",  out var c) ? c.GetString() ?? "" : "";

                if (_accounts.Exists(email))
                {
                    await SendWsJsonAsync(new { status = "error", message = "Email already registered." });
                    return;
                }
                if (password != confirm)
                {
                    await SendWsJsonAsync(new { status = "error", message = "Passwords do not match." });
                    return;
                }
                _accounts.Create(email, password);
                _email = email;
                _state = State.LoggedIn;
                await SendWsJsonAsync(new { status = "ok", email });
                break;
            }

            default:
                await SendWsErrorAsync("Unknown action.");
                break;
        }
    }

    // -------------------------------------------------------------------------
    // Telnet state handlers
    // -------------------------------------------------------------------------

    private async Task HandleEmailInputAsync(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            await _conn.SendAsync("Enter email: ");
            return;
        }

        _email = email;

        if (_accounts.Exists(email))
        {
            _state = State.PromptPassword;
            await SuppressEchoAsync();
            await _conn.SendAsync("Password: ");
        }
        else
        {
            _state = State.ConfirmNewEmail;
            await _conn.SendAsync($"New account. Is {email} correct? [y/n] ");
        }
    }

    private async Task HandlePasswordInputAsync(string password)
    {
        await RestoreEchoAsync();
        if (_accounts.Verify(_email, password))
        {
            _state = State.LoggedIn;
            await _conn.SendAsync($"\r\nWelcome! Logged in as {_email}.\r\n");
            // TODO: hand off to game session
        }
        else
        {
            await _conn.SendAsync("\r\nWrong password.\r\n");
            await _conn.CloseAsync();
        }
    }

    private async Task HandleConfirmEmailAsync(string input)
    {
        if (input.Equals("y", StringComparison.OrdinalIgnoreCase))
        {
            _state = State.PromptNewPassword;
            await SuppressEchoAsync();
            await _conn.SendAsync("Choose a password: ");
        }
        else
        {
            _email = string.Empty;
            _state = State.PromptEmail;
            await _conn.SendAsync("Enter email: ");
        }
    }

    private async Task HandleNewPasswordInputAsync(string password)
    {
        _newPassword = password;
        _state = State.PromptConfirmPassword;
        await _conn.SendAsync("\r\nConfirm password: ");
    }

    private async Task HandleConfirmPasswordAsync(string confirm)
    {
        await RestoreEchoAsync();
        if (confirm == _newPassword)
        {
            _accounts.Create(_email, _newPassword);
            _newPassword = string.Empty;
            _state = State.LoggedIn;
            await _conn.SendAsync($"\r\nAccount created. Welcome, {_email}!\r\n");
            // TODO: hand off to game session
        }
        else
        {
            _newPassword = string.Empty;
            _state = State.PromptNewPassword;
            await _conn.SendAsync("\r\nPasswords do not match.\r\nChoose a password: ");
            await SuppressEchoAsync();
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private Task SendPromptAsync() => _conn.SendAsync("Enter email: ");

    private Task SendWsJsonAsync(object payload) =>
        _conn.SendAsync(JsonSerializer.Serialize(payload));

    private Task SendWsErrorAsync(string message) =>
        SendWsJsonAsync(new { status = "error", message });

    private async Task SuppressEchoAsync()
    {
        if (_conn is TelnetConnection tc)
            await tc.SuppressEchoAsync();
    }

    private async Task RestoreEchoAsync()
    {
        if (_conn is TelnetConnection tc)
            await tc.RestoreEchoAsync();
    }
}
