namespace Wol.Server.Auth;

/// <summary>
/// In-memory account store stub. Backed by a real database in a follow-on proposal.
/// </summary>
public sealed class AccountStore
{
    private readonly Dictionary<string, string> _accounts = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    /// <summary>Returns true if an account with this email exists.</summary>
    public bool Exists(string email)
    {
        lock (_lock) return _accounts.ContainsKey(email);
    }

    /// <summary>Returns true if the password matches the stored hash.</summary>
    public bool Verify(string email, string password)
    {
        string? hash;
        lock (_lock) _accounts.TryGetValue(email, out hash);
        return hash != null && BCrypt.Net.BCrypt.Verify(password, hash);
    }

    /// <summary>Creates a new account. Throws if the email is already registered.</summary>
    public void Create(string email, string password)
    {
        string hash = BCrypt.Net.BCrypt.HashPassword(password);
        lock (_lock)
        {
            if (_accounts.ContainsKey(email))
                throw new InvalidOperationException($"Account '{email}' already exists.");
            _accounts[email] = hash;
        }
    }
}
