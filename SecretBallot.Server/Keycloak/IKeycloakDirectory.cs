namespace SecretBallot.Server.Keycloak;

public interface IKeycloakDirectory {
    Task<Eligibility> GetEligibilityAsync(string subject, CancellationToken ct);
    Task<DirectoryUser?> FindByUsernameAsync(string username, CancellationToken ct);
}

public sealed record DirectoryUser(string Id, string Username);
