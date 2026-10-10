using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SecretBallot.Server;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Tests.Keycloak;

public class KeycloakDirectoryTests {
    private static readonly SecretBallotSettings Settings = new() {
        KeycloakBaseUrl = "https://sso.example",
        Realm = "Piraten",
        ClientId = "ballot",
        ClientSecret = "secret"
    };

    private static KeycloakDirectory Create(Func<HttpRequestMessage, HttpResponseMessage> userResponse) {
        var http = new HttpClient(new StubHandler(userResponse));
        return new KeycloakDirectory(http, Settings, new KeycloakTokenProvider(), NullLogger<KeycloakDirectory>.Instance);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) {
        return new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    [Test]
    public async Task Eligible_when_attribute_true() {
        var directory = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true,\"attributes\":{\"ekklesia_eligible\":[\"true\"]}}"));
        await Assert.That(await directory.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Eligible);
    }

    [Test]
    public async Task Not_eligible_when_attribute_false_missing_or_disabled() {
        var falseAttr = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true,\"attributes\":{\"ekklesia_eligible\":[\"false\"]}}"));
        var missing = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true}"));
        var disabled = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":false,\"attributes\":{\"ekklesia_eligible\":[\"true\"]}}"));
        await Assert.That(await falseAttr.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
        await Assert.That(await missing.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
        await Assert.That(await disabled.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
    }

    [Test]
    public async Task Unknown_when_keycloak_fails() {
        var serverError = Create(_ => Json(HttpStatusCode.InternalServerError, "{}"));
        var unreachable = Create(_ => throw new HttpRequestException("down"));
        await Assert.That(await serverError.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Unknown);
        await Assert.That(await unreachable.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Unknown);
    }

    [Test]
    public async Task Not_eligible_when_user_unknown() {
        var directory = Create(_ => Json(HttpStatusCode.NotFound, "{}"));
        await Assert.That(await directory.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
    }

    private sealed class StubHandler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _userResponse;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> userResponse) {
            _userResponse = userResponse;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            if (request.RequestUri!.AbsolutePath.EndsWith("/token"))
                return Task.FromResult(Json(HttpStatusCode.OK, "{\"access_token\":\"t\",\"expires_in\":60}"));
            return Task.FromResult(_userResponse(request));
        }
    }
}
