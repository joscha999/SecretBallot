using System.Security.Cryptography;
using System.Text;

namespace SecretBallot.Server.Election;

public static class CryptoFormats {
    public const byte Version = 1;
    public const int PlaintextSize = 512;
    public const int LayerOverhead = 94;
    private const string KeysDomain = "pp-ballot-keys-v1";

    public static int CiphertextSize(int layerCount) => PlaintextSize + layerCount * LayerOverhead;

    public static string Sha256Hex(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static string Fingerprint(byte[] data) => Format(SHA256.HashData(data));

    public static string CombinedFingerprint(Guid ballotId, IEnumerable<byte[]> keys) {
        var buffer = new List<byte>();
        buffer.AddRange(Encoding.UTF8.GetBytes(KeysDomain));
        buffer.AddRange(Encoding.UTF8.GetBytes(ballotId.ToString()));
        foreach (var key in keys)
            buffer.AddRange(key);
        return Format(SHA256.HashData(buffer.ToArray()));
    }

    public static List<byte[]> SortByHash(IEnumerable<byte[]> items) {
        return items
            .Select(item => (Item: item, Hash: Sha256Hex(item)))
            .OrderBy(entry => entry.Hash, StringComparer.Ordinal)
            .Select(entry => entry.Item)
            .ToList();
    }

    public static bool IsValidP256PublicKey(byte[] raw) {
        if (raw.Length != 65 || raw[0] != 4)
            return false;

        try {
            using var key = ECDsa.Create(ToParameters(raw));
            return true;
        } catch (CryptographicException) {
            return false;
        }
    }

    public static bool VerifySignature(byte[] publicKey, string document, byte[] signature) {
        using var key = ECDsa.Create(ToParameters(publicKey));
        return key.VerifyData(Encoding.UTF8.GetBytes(document), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static ECParameters ToParameters(byte[] raw) {
        return new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = raw[1..33], Y = raw[33..65] }
        };
    }

    private static string Format(byte[] digest) {
        var hex = Convert.ToHexStringLower(digest, 0, 16);
        return string.Join(' ', Enumerable.Range(0, 8).Select(i => hex.Substring(i * 4, 4)));
    }
}
