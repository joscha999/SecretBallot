using SecretBallot.Server.Auth;

namespace SecretBallot.Server.Tests.Auth;

public class ReturnUrlTests {
    [Test]
    [Arguments("/")]
    [Arguments("/schluessel.html")]
    public async Task Local_paths_are_accepted(string url) {
        await Assert.That(ReturnUrl.IsLocal(url)).IsTrue();
    }

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("https://evil.example")]
    [Arguments("//evil.example")]
    [Arguments("/\\evil.example")]
    [Arguments("/\t/evil.example")]
    [Arguments("/\n/evil.example")]
    public async Task Foreign_or_ambiguous_targets_are_rejected(string? url) {
        await Assert.That(ReturnUrl.IsLocal(url)).IsFalse();
    }
}
