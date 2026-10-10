namespace SecretBallot.Server;

public sealed class SecretBallotSettings {
    public string Authority { get; init; } = "";
    public string ClientId { get; init; } = "";
    public string ClientSecret { get; init; } = "";
    public string KeycloakBaseUrl { get; init; } = "";
    public string Realm { get; init; } = "";
    public string EligibilityAttribute { get; init; } = "ekklesia_eligible";
    public string[] AdminUsernames { get; init; } = Array.Empty<string>();

    public bool IsAdmin(string? username) {
        if (string.IsNullOrEmpty(username))
            return false;
        return AdminUsernames.Contains(username, StringComparer.OrdinalIgnoreCase);
    }
}
