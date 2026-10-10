namespace SecretBallot.Server.Election;

public sealed class KeyHolder {
    public required string Subject { get; init; }
    public required string Username { get; init; }
    public required string Role { get; init; }
    public bool Leads { get; init; }
    public byte[]? EncryptionKey { get; set; }
    public byte[]? SigningKey { get; set; }
    public bool Confirmed { get; set; }
}
