using System.Net;

namespace SecretBallot.Server.Tests.EndToEnd;

public class CsrfTests {
    [Test]
    public async Task State_changing_request_without_marker_header_is_refused() {
        await using var factory = new BallotServerFactory();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/keyholder/ballots/{Guid.NewGuid()}/close");
        request.Headers.Add("X-Test-User", "admin");

        using var response = await client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Forbidden);
    }

    [Test]
    public async Task State_changing_request_with_marker_header_reaches_the_endpoint() {
        await using var factory = new BallotServerFactory();
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, $"/api/keyholder/ballots/{Guid.NewGuid()}/close");
        request.Headers.Add("X-Test-User", "admin");
        request.Headers.Add("X-Secret-Ballot", "1");

        using var response = await client.SendAsync(request);

        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Conflict);
    }
}
