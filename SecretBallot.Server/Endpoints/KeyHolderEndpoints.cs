using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;

namespace SecretBallot.Server.Endpoints;

public static class KeyHolderEndpoints {
    public static void MapKeyHolderEndpoints(this WebApplication app) {
        var group = app.MapGroup("/api/keyholder").RequireAuthorization();

        group.MapPut("/keys", (RegisterKeysRequest request, ClaimsPrincipal user, ElectionState state, ILogger<ElectionState> logger) => {
            var encryption = ApiResults.DecodeBase64(request.EncryptionKey);
            var signing = ApiResults.DecodeBase64(request.SigningKey);
            if (encryption == null || signing == null)
                return ApiResults.Error("Die Schlüssel haben kein gültiges Format.", 400);

            var result = state.RegisterKeys(user.Subject, encryption, signing);
            if (!result.Ok)
                logger.LogWarning("Key registration rejected: {Reason}", result.Error);
            return ApiResults.From(result);
        });

        group.MapPost("/confirm", (ConfirmKeysRequest request, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.ConfirmKeys(user.Subject, request.EncryptionFingerprint, request.SigningFingerprint)));

        group.MapPost("/retire", (ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.RetireKeys(user.Subject)));

        group.MapPost("/ballots/{id:guid}/open", (Guid id, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.Open(id, user.Subject)));

        group.MapPost("/ballots/{id:guid}/close", (Guid id, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) =>
            ApiResults.From(state.Close(id, user.Subject, settings.IsAdmin(user.Username))));

        group.MapGet("/ballots/{id:guid}", (Guid id, ClaimsPrincipal user, ElectionState state) => {
            var closed = state.GetClosed(id, user.Subject);
            return closed == null ? ApiResults.Error("Kein geschlossener Wahlgang mit deiner Beteiligung.", 404) : Results.Json(closed);
        });

        group.MapGet("/ballots/{id:guid}/layers/{index:int}", (Guid id, int index, ClaimsPrincipal user, ElectionState state) => {
            var items = state.GetLayer(id, index, user.Subject);
            return items == null ? ApiResults.Error("Diese Schicht liegt nicht vor.", 404) : Results.Json(new LayerItems(items.ToList()));
        });

        group.MapPut("/ballots/{id:guid}/layers/{index:int}", (Guid id, int index, LayerItems request, ClaimsPrincipal user, ElectionState state) => {
            var decoded = request.Items.Select(ApiResults.DecodeBase64).ToList();
            if (decoded.Any(item => item == null))
                return ApiResults.Error("Die Schicht enthält beschädigte Einträge.", 400);
            return ApiResults.From(state.PutLayer(id, index, user.Subject, decoded.Select(item => item!).ToList()));
        });

        group.MapPut("/ballots/{id:guid}/result", (Guid id, ResultRequest request, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.PutResult(id, user.Subject, request.Document)));

        group.MapPut("/ballots/{id:guid}/signature", (Guid id, SignatureRequest request, ClaimsPrincipal user, ElectionState state) => {
            var signature = ApiResults.DecodeBase64(request.Signature);
            if (signature == null)
                return ApiResults.Error("Die Unterschrift hat kein gültiges Format.", 400);
            return ApiResults.From(state.PutSignature(id, user.Subject, signature));
        });
    }
}
