using SecretBallot.Server.Election;

namespace SecretBallot.Server.Endpoints;

public static class ApiResults {
    public static IResult Error(string message, int status) => Results.Json(new ErrorResponse(message), statusCode: status);

    public static IResult From(RuleResult result) => result.Ok ? Results.NoContent() : Error(result.Error!, StatusCodes.Status409Conflict);

    public static byte[]? DecodeBase64(string? text) {
        if (string.IsNullOrEmpty(text))
            return null;
        var buffer = new byte[text.Length];
        return Convert.TryFromBase64String(text, buffer, out var written) ? buffer[..written] : null;
    }
}
