using SecretBallot.Server.Election;

namespace SecretBallot.Server.Tests.Election;

public class CrossLanguageTests {
    private const string KeyBase64 = "BGsX0fLhLEJH+Lzm5WOkQPJ3A+eTiAoO4zXDOfbVhqDXgSeGG7nrdV5FkJVmXFWnSXkm7Ca/ptQIsjPbpuRHxGc=";
    private const string BallotId = "6f0c3c1e-6c55-4b0e-9a57-1f2f9a0c9d11";
    private const string ExpectedCombined = "0bef 8ab0 4984 f198 9f06 e5ec 8538 4f4b";
    private const string ExpectedKeyFingerprint = "1480 d306 aa6f 9d79 6e6f def9 ef25 0d95";

    [Test]
    public async Task Combined_fingerprint_matches_javascript() {
        var key = Convert.FromBase64String(KeyBase64);
        await Assert.That(CryptoFormats.CombinedFingerprint(Guid.Parse(BallotId), new[] { key })).IsEqualTo(ExpectedCombined);
    }

    [Test]
    public async Task Key_fingerprint_matches_javascript() {
        await Assert.That(CryptoFormats.Fingerprint(Convert.FromBase64String(KeyBase64))).IsEqualTo(ExpectedKeyFingerprint);
    }
}
