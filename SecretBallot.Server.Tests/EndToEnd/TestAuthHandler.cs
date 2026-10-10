using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecretBallot.Server.Tests.EndToEnd;

/// <summary>Authenticates the user named in the X-Test-User header.</summary>
public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions> {
    public const string SchemeName = "Test";

    public TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
        var user = Request.Headers["X-Test-User"].ToString();
        if (user.Length == 0)
            return Task.FromResult(AuthenticateResult.NoResult());

        var identity = new ClaimsIdentity(new[] {
            new Claim("sub", user),
            new Claim("preferred_username", user),
            new Claim("name", user)
        }, SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
