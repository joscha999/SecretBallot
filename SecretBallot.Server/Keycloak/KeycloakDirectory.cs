using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SecretBallot.Server.Keycloak;

public sealed class KeycloakDirectory : IKeycloakDirectory {
    private readonly HttpClient _http;
    private readonly SecretBallotSettings _settings;
    private readonly KeycloakTokenProvider _tokens;
    private readonly ILogger<KeycloakDirectory> _logger;

    private string AdminBase => $"{_settings.KeycloakBaseUrl.TrimEnd('/')}/admin/realms/{Uri.EscapeDataString(_settings.Realm)}";

    public KeycloakDirectory(HttpClient http, SecretBallotSettings settings, KeycloakTokenProvider tokens, ILogger<KeycloakDirectory> logger) {
        _http = http;
        _settings = settings;
        _tokens = tokens;
        _logger = logger;
    }

    public async Task<Eligibility> GetEligibilityAsync(string subject, CancellationToken ct) {
        try {
            using var response = await GetAsync($"{AdminBase}/users/{Uri.EscapeDataString(subject)}", ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return Eligibility.NotEligible;
            if (!response.IsSuccessStatusCode) {
                _logger.LogWarning("Eligibility lookup returned HTTP {Status}", (int)response.StatusCode);
                return Eligibility.Unknown;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return ReadEligibility(doc.RootElement);
        } catch (Exception ex) when (IsLookupFailure(ex)) {
            _logger.LogWarning("Eligibility lookup failed: {Exception}", ex);
            return Eligibility.Unknown;
        }
    }

    public async Task<DirectoryUser?> FindByUsernameAsync(string username, CancellationToken ct) {
        using var response = await GetAsync($"{AdminBase}/users?username={Uri.EscapeDataString(username)}&exact=true", ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        foreach (var user in doc.RootElement.EnumerateArray()) {
            var name = user.GetProperty("username").GetString() ?? "";
            if (string.Equals(name, username, StringComparison.OrdinalIgnoreCase))
                return new DirectoryUser(user.GetProperty("id").GetString()!, name);
        }
        return null;
    }

    private static bool IsLookupFailure(Exception ex) {
        if (ex is HttpRequestException)
            return true;
        if (ex is JsonException)
            return true;
        if (ex is TaskCanceledException)
            return true;
        if (ex is KeyNotFoundException)
            return true;
        return ex is InvalidOperationException;
    }

    private async Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct) {
        var token = await _tokens.GetTokenAsync(_http, _settings, ct);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _http.SendAsync(request, ct);
    }

    private Eligibility ReadEligibility(JsonElement user) {
        if (user.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False)
            return Eligibility.NotEligible;
        if (!user.TryGetProperty("attributes", out var attributes))
            return Eligibility.NotEligible;
        if (!attributes.TryGetProperty(_settings.EligibilityAttribute, out var values) || values.GetArrayLength() == 0)
            return Eligibility.NotEligible;
        return string.Equals(values[0].GetString(), "true", StringComparison.OrdinalIgnoreCase) ? Eligibility.Eligible : Eligibility.NotEligible;
    }
}
