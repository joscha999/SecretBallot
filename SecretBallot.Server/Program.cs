using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using SecretBallot.Server;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Endpoints;
using SecretBallot.Server.Keycloak;

var builder = WebApplication.CreateBuilder(args);
var settings = builder.Configuration.GetSection("SecretBallot").Get<SecretBallotSettings>() ?? new SecretBallotSettings();

builder.Services.AddSingleton(settings);
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddSingleton<ElectionState>();
builder.Services.AddSingleton<KeycloakTokenProvider>();
builder.Services.AddHttpClient<IKeycloakDirectory, KeycloakDirectory>();
builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
builder.Services.AddBallotAuthentication(settings);
builder.Services.Configure<ForwardedHeadersOptions>(options => {
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
    app.UseHsts();
app.UseSecurityHeaders();
app.UseRequestMarkerCheck();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapPublicEndpoints();
app.MapVoterEndpoints();
app.MapKeyHolderEndpoints();
app.MapAdminEndpoints();

app.Run();

public partial class Program { }
