namespace SecretBallot.Server.Election;

public sealed class Ballot {
    public required Guid Id { get; init; }
    public required string Title { get; init; }
    public required string DefinitionJson { get; init; }
    public BallotStatus Status { get; set; } = BallotStatus.Draft;
    public List<KeyHolderSnapshot> KeyHolders { get; set; } = new();
    // Who voted and what was cast live in two collections that are never joined; ElectionState.Cast inserts ciphertexts at a random index so their memory order does not mirror the order of Voted.
    public HashSet<string> Voted { get; } = new(StringComparer.Ordinal);
    public List<byte[]> Ciphertexts { get; } = new();
    public int VoterCount { get; set; }
    public string? CombinedFingerprint { get; set; }
    public string? BundleJson { get; set; }
    public List<List<byte[]>> Layers { get; } = new();
    public string? ResultDocument { get; set; }
    public string?[] Signatures { get; set; } = Array.Empty<string?>();
}

public sealed record KeyHolderSnapshot(int Position, string Role, string Subject, bool Leads, byte[] EncryptionKey, byte[] SigningKey);
