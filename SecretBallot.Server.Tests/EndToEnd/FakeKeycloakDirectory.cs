using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Tests.EndToEnd;

public sealed class FakeKeycloakDirectory : IKeycloakDirectory {
    public Task<Eligibility> GetEligibilityAsync(string subject, CancellationToken ct) {
        return Task.FromResult(subject == "ineligible" ? Eligibility.NotEligible : Eligibility.Eligible);
    }

    public Task<DirectoryUser?> FindByUsernameAsync(string username, CancellationToken ct) {
        return Task.FromResult<DirectoryUser?>(new DirectoryUser(username, username));
    }
}
