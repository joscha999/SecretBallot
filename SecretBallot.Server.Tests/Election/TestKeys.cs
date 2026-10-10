using System.Security.Cryptography;
using System.Text;

namespace SecretBallot.Server.Tests.Election;

public sealed class TestKeys {
    public ECDsa Signing { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] EncryptionPublic { get; }
    public byte[] SigningPublic { get; }

    public TestKeys() {
        using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        EncryptionPublic = Raw(encryption.ExportParameters(false).Q);
        SigningPublic = Raw(Signing.ExportParameters(false).Q);
    }

    public byte[] Sign(string document) {
        return Signing.SignData(Encoding.UTF8.GetBytes(document), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static byte[] Raw(ECPoint point) {
        var raw = new byte[65];
        raw[0] = 4;
        point.X!.CopyTo(raw, 1);
        point.Y!.CopyTo(raw, 33);
        return raw;
    }
}
