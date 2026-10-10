using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class PublicEndpoints {
    public static void MapPublicEndpoints(this WebApplication app) {
        app.MapGet("/api/me", async (ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings, IKeycloakDirectory directory, CancellationToken ct) => {
            if (!user.IsLoggedIn)
                return Results.Json(new MeResponse(false, "", null, false, null, null));

            var eligibility = await directory.GetEligibilityAsync(user.Subject, ct);
            bool? eligible = eligibility == Eligibility.Unknown ? null : eligibility == Eligibility.Eligible;
            return Results.Json(new MeResponse(true, user.DisplayName, user.Username, settings.IsAdmin(user.Username), eligible, state.FindKeyHolder(user.Subject)));
        });

        app.MapGet("/api/ballots", (ClaimsPrincipal user, ElectionState state) =>
            Results.Json(state.GetBallots(user.IsLoggedIn ? user.Subject : null)));

        app.MapGet("/api/ballots/current", (ClaimsPrincipal user, ElectionState state) => {
            var current = state.GetCurrent();
            var hasVoted = current != null && user.IsLoggedIn && state.HasVoted(current.Id, user.Subject);
            return Results.Json(new CurrentBallotResponse(current, hasVoted));
        });

        app.MapGet("/api/ballots/{id:guid}/bulletin", (Guid id, ElectionState state) => {
            var bulletin = state.GetBulletin(id);
            return bulletin == null ? ApiResults.Error("Für diesen Wahlgang gibt es noch keine öffentliche Liste.", 404) : Results.Json(bulletin);
        });

        app.MapGet("/api/ballots/{id:guid}/publication", (Guid id, ElectionState state) => {
            var publication = state.GetPublication(id);
            return publication == null ? ApiResults.Error("Dieser Wahlgang ist noch nicht abgeschlossen.", 404) : Results.Json(publication);
        });
    }
}
