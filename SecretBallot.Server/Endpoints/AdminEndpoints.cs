using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class AdminEndpoints {
    public static void MapAdminEndpoints(this WebApplication app) {
        var group = app.MapGroup("/api/admin").RequireAuthorization();

        group.MapGet("/keyholders", (ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);
            return Results.Json(state.GetKeyHolders());
        });

        group.MapPut("/keyholders", async (List<KeyHolderEntryRequest> entries, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings,
            IKeycloakDirectory directory, ILogger<ElectionState> logger, CancellationToken ct) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);

            var assignments = new List<KeyHolderAssignment>();
            foreach (var entry in entries) {
                DirectoryUser? found;
                try {
                    found = await directory.FindByUsernameAsync(entry.Username.Trim(), ct);
                } catch (Exception ex) {
                    logger.LogWarning("Keycloak username lookup failed: {Exception}", ex);
                    return ApiResults.Error("Das Piratenlogin ist gerade nicht erreichbar.", 502);
                }
                if (found == null)
                    return ApiResults.Error($"Benutzername „{entry.Username}“ wurde im Piratenlogin nicht gefunden.", 400);
                assignments.Add(new KeyHolderAssignment(entry.Role, found.Id, found.Username, entry.Leads));
            }
            return ApiResults.From(state.ReplaceKeyHolders(assignments));
        });

        group.MapPost("/ballots", (CreateBallotRequest request, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);

            BallotType? type = request.Type switch {
                "approval" => BallotType.Approval,
                "single" => BallotType.Single,
                "yesno" => BallotType.YesNo,
                _ => null
            };
            if (type == null)
                return ApiResults.Error("Unbekannte Wahlart.", 400);

            var result = state.CreateBallot(new BallotDraft(request.Title, type.Value, request.Options, request.Seats), out var id);
            return result.Ok ? Results.Json(new CreatedResponse(id)) : ApiResults.From(result);
        });
    }
}
