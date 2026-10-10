namespace SecretBallot.Server;

public static class SecurityHeaders {
    private const string ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

    public static void UseSecurityHeaders(this WebApplication app) {
        app.Use(async (context, next) => {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            headers.CacheControl = "no-store";
            await next();
        });
    }
}
