using System.Text;
using System.Text.Json;

namespace SecretBallot.Server.Election;

public static class BundleWriter {
    public static string Write(Ballot ballot, IReadOnlyList<byte[]> sortedCiphertexts) {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) {
            writer.WriteStartObject();
            writer.WriteNumber("v", 1);
            writer.WriteString("ballot", ballot.Id.ToString());
            writer.WriteString("definition", ballot.DefinitionJson);
            writer.WriteString("combinedFingerprint", ballot.CombinedFingerprint);
            writer.WriteStartArray("keyHolders");
            foreach (var holder in ballot.KeyHolders) {
                writer.WriteStartObject();
                writer.WriteNumber("position", holder.Position);
                writer.WriteString("role", holder.Role);
                writer.WriteString("encryptionKey", Convert.ToBase64String(holder.EncryptionKey));
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteNumber("voterCount", ballot.VoterCount);
            writer.WriteStartArray("ciphertexts");
            foreach (var ciphertext in sortedCiphertexts)
                writer.WriteStringValue(Convert.ToBase64String(ciphertext));
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
