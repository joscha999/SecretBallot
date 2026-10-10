using SecretBallot.Server.Endpoints;

namespace SecretBallot.Server;

public static class RequestMarker {
    public const string HeaderName = "X-Secret-Ballot";

    // A custom header forces a CORS preflight, which this server never answers, so state-changing API calls can only come from its own pages.
    public static void UseRequestMarkerCheck(this WebApplication app) {
        app.Use(async (context, next) => {
            if (RequiresMarker(context.Request) && !context.Request.Headers.ContainsKey(HeaderName)) {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(new ErrorResponse("Anfrage abgelehnt. Bitte die Seite neu laden."));
                return;
            }
            await next();
        });
    }

    private static bool RequiresMarker(HttpRequest request) {
        if (HttpMethods.IsGet(request.Method) || HttpMethods.IsHead(request.Method))
            return false;
        return request.Path.StartsWithSegments("/api");
    }
}
