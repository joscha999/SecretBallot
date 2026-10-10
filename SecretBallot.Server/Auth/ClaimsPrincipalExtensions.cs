using System.Security.Claims;

namespace SecretBallot.Server.Auth;

public static class ClaimsPrincipalExtensions {
    extension(ClaimsPrincipal user) {
        public string Subject => user.FindFirstValue("sub") ?? throw new InvalidOperationException("Authenticated user without sub claim");
        public string? Username => user.FindFirstValue("preferred_username");
        public string DisplayName => user.FindFirstValue("name") ?? user.FindFirstValue("preferred_username") ?? "";
        public bool IsLoggedIn => user.Identity?.IsAuthenticated == true;
    }
}
