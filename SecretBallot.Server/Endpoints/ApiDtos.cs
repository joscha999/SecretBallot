using SecretBallot.Server.Election;

namespace SecretBallot.Server.Endpoints;

public sealed record ErrorResponse(string Error);
public sealed record MeResponse(bool LoggedIn, string Name, string? Username, bool IsAdmin, bool? Eligible, KeyHolderView? KeyHolder);
public sealed record CurrentBallotResponse(OpenBallotView? Ballot, bool HasVoted);
public sealed record VoteRequest(string Ciphertext);
public sealed record LayerItems(List<string> Items);
public sealed record ResultRequest(string Document);
public sealed record SignatureRequest(string Signature);
public sealed record RegisterKeysRequest(string EncryptionKey, string SigningKey);
public sealed record ConfirmKeysRequest(string EncryptionFingerprint, string SigningFingerprint);
public sealed record KeyHolderEntryRequest(string Role, string Username, bool Leads);
public sealed record CreateBallotRequest(string Title, string Type, List<string> Options, int Seats);
public sealed record CreatedResponse(Guid Id);
