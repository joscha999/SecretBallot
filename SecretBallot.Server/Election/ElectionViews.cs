namespace SecretBallot.Server.Election;

public sealed record KeyHolderAssignment(string Role, string Subject, string Username, bool Leads);

public sealed record KeyHolderView(int Position, string Role, string Username, bool Leads, string? EncryptionKey, string? SigningKey,
    string? EncryptionFingerprint, string? SigningFingerprint, bool Confirmed);

public sealed record BallotDraft(string Title, BallotType Type, IReadOnlyList<string> Options, int Seats);

public sealed record PublicKeyEntry(int Position, string Role, string EncryptionKey, string SigningKey);

public sealed record OpenBallotView(Guid Id, string Title, string DefinitionJson, IReadOnlyList<PublicKeyEntry> KeyHolders, string CombinedFingerprint);

public sealed record BallotSummary(Guid Id, string Title, BallotStatus Status, int VoteCount, int KeyHolderCount, int LayerCount, bool HasResult,
    int SignatureCount, string? CombinedFingerprint, int MyPosition, bool ILead, bool ISigned);

public sealed record BulletinView(Guid Id, string Title, int VoterCount, int CiphertextCount, IReadOnlyList<string> Receipts);

public sealed record ClosedBallotView(Guid Id, string Title, string DefinitionJson, string BundleJson, string CombinedFingerprint, int VoterCount,
    IReadOnlyList<PublicKeyEntry> KeyHolders, string? ResultDocument, IReadOnlyList<string?> Signatures);

public sealed record PublicationView(Guid Id, string Title, string DefinitionJson, string BundleJson, string CombinedFingerprint, int VoterCount,
    IReadOnlyList<PublicKeyEntry> KeyHolders, IReadOnlyList<IReadOnlyList<string>> Layers, string ResultDocument, IReadOnlyList<string> Signatures);
