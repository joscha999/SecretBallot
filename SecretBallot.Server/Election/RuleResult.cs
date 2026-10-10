namespace SecretBallot.Server.Election;

public sealed record RuleResult(bool Ok, string? Error) {
    public static RuleResult Success { get; } = new(true, null);

    public static RuleResult Fail(string error) => new(false, error);
}
