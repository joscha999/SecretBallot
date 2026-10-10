using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace SecretBallot.Server.Auth;

public static class AuthSetup {
    public const string OidcScheme = "oidc";

    public static void AddBallotAuthentication(this IServiceCollection services, SecretBallotSettings settings) {
        services
            .AddAuthentication(options => {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options => {
                options.Cookie.Name = "sb_session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromHours(14);
                options.Events.OnRedirectToLogin = context => {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = context => {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(OidcScheme, options => {
                options.Authority = settings.Authority;
                options.ClientId = settings.ClientId;
                options.ClientSecret = settings.ClientSecret;
                options.ResponseType = "code";
                options.UsePkce = true;
                options.MapInboundClaims = false;
                options.SaveTokens = false;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.TokenValidationParameters.NameClaimType = "preferred_username";
            });
        services.AddAuthorization();
    }

    public static void MapAuthEndpoints(this WebApplication app) {
        app.MapGet("/login", (string? returnUrl) => {
            var target = ReturnUrl.IsLocal(returnUrl) ? returnUrl! : "/";
            return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, new[] { OidcScheme });
        });
        app.MapGet("/logout", async (HttpContext context) => {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/");
        });
    }
}
