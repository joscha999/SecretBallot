using System.Text.Json;

namespace SecretBallot.Server.Keycloak;

/// <summary>Caches one client-credentials token until shortly before it expires.</summary>
public sealed class KeycloakTokenProvider {
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(10);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? token;
    private DateTimeOffset expiresAt;

    public async Task<string> GetTokenAsync(HttpClient http, SecretBallotSettings settings, CancellationToken ct) {
        await _gate.WaitAsync(ct);
        try {
            if (token != null && DateTimeOffset.UtcNow + RefreshMargin < expiresAt)
                return token;

            var url = $"{settings.KeycloakBaseUrl.TrimEnd('/')}/realms/{Uri.EscapeDataString(settings.Realm)}/protocol/openid-connect/token";
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "client_credentials",
                ["client_id"] = settings.ClientId,
                ["client_secret"] = settings.ClientSecret
            });
            using var response = await http.PostAsync(url, form, ct);
            response.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            token = doc.RootElement.GetProperty("access_token").GetString()!;
            expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(doc.RootElement.GetProperty("expires_in").GetInt32());
            return token;
        } finally {
            _gate.Release();
        }
    }
}
