using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class VoterEndpoints {
    public static void MapVoterEndpoints(this WebApplication app) {
        app.MapPost("/api/ballots/{id:guid}/votes", async (Guid id, VoteRequest request, ClaimsPrincipal user, ElectionState state, IKeycloakDirectory directory, CancellationToken ct) => {
            var eligibility = await directory.GetEligibilityAsync(user.Subject, ct);
            if (eligibility == Eligibility.Unknown)
                return ApiResults.Error("Die Stimmberechtigung konnte gerade nicht geprüft werden. Bitte versuche es gleich noch einmal.", 503);
            if (eligibility == Eligibility.NotEligible)
                return ApiResults.Error("Laut Piratenlogin bist du nicht stimmberechtigt (Beiträge gezahlt). Bei Fragen hilft piratenlogin@piratenpartei.de.", 403);

            var ciphertext = ApiResults.DecodeBase64(request.Ciphertext);
            if (ciphertext == null)
                return ApiResults.Error("Der Stimmzettel ist beschädigt.", 400);

            return state.Cast(id, user.Subject, ciphertext) switch {
                CastOutcome.Accepted => Results.NoContent(),
                CastOutcome.AlreadyVoted => ApiResults.Error("Du hast in diesem Wahlgang bereits abgestimmt.", 409),
                CastOutcome.Malformed => ApiResults.Error("Der Stimmzettel ist beschädigt.", 400),
                _ => ApiResults.Error("Dieser Wahlgang ist nicht geöffnet.", 409)
            };
        }).RequireAuthorization();
    }
}
