using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace SecretBallot.Server.Election;

/// <summary>All election state, guarded by one lock.</summary>
public sealed class ElectionState {
    private const int MaxOptions = 50;
    private const int MaxTextLength = 200;
    private const int MaxResultLength = 65536;

    private readonly Lock _lock = new();
    private readonly List<KeyHolder> _keyHolders = new();
    private readonly Dictionary<Guid, Ballot> _ballots = new();
    private readonly HashSet<string> _retiredKeys = new(StringComparer.Ordinal);

    public IReadOnlyList<KeyHolderView> GetKeyHolders() {
        lock (_lock) {
            return _keyHolders.Select(ToView).ToList();
        }
    }

    public KeyHolderView? FindKeyHolder(string subject) {
        lock (_lock) {
            var index = _keyHolders.FindIndex(k => k.Subject == subject);
            return index < 0 ? null : ToView(_keyHolders[index], index);
        }
    }

    public RuleResult ReplaceKeyHolders(IReadOnlyList<KeyHolderAssignment> assignments) {
        var invalid = ValidateAssignments(assignments);
        if (invalid != null)
            return RuleResult.Fail(invalid);

        lock (_lock) {
            var previous = _keyHolders.ToDictionary(k => k.Subject);
            _keyHolders.Clear();
            foreach (var assignment in assignments) {
                var holder = new KeyHolder {
                    Subject = assignment.Subject,
                    Username = assignment.Username,
                    Role = assignment.Role.Trim(),
                    Leads = assignment.Leads
                };
                if (previous.TryGetValue(assignment.Subject, out var old)) {
                    holder.EncryptionKey = old.EncryptionKey;
                    holder.SigningKey = old.SigningKey;
                    holder.Confirmed = old.Confirmed;
                }
                _keyHolders.Add(holder);
            }
        }
        return RuleResult.Success;
    }

    public RuleResult RegisterKeys(string subject, byte[] encryptionKey, byte[] signingKey) {
        if (!CryptoFormats.IsValidP256PublicKey(encryptionKey) || !CryptoFormats.IsValidP256PublicKey(signingKey))
            return RuleResult.Fail("Die Schlüssel haben kein gültiges Format.");

        lock (_lock) {
            var holder = _keyHolders.Find(k => k.Subject == subject);
            if (holder == null)
                return RuleResult.Fail("Du bist nicht als schlüsselhaltende Person eingetragen.");
            if (_retiredKeys.Contains(Convert.ToBase64String(encryptionKey)))
                return RuleResult.Fail("Diese Schlüssel wurden bereits veröffentlicht und dürfen nicht wiederverwendet werden. Bitte neue Schlüssel erzeugen.");

            holder.EncryptionKey = encryptionKey;
            holder.SigningKey = signingKey;
            holder.Confirmed = false;
            return RuleResult.Success;
        }
    }

    public RuleResult ConfirmKeys(string subject, string encryptionFingerprint, string signingFingerprint) {
        lock (_lock) {
            var holder = _keyHolders.Find(k => k.Subject == subject);
            if (!HasRegisteredKeys(holder))
                return RuleResult.Fail("Es sind noch keine Schlüssel registriert.");
            if (!HasFingerprints(holder, encryptionFingerprint, signingFingerprint))
                return RuleResult.Fail("Die Fingerabdrücke stimmen nicht überein. Bitte sofort die Wahlleitung und die Verwaltung informieren.");

            holder.Confirmed = true;
            return RuleResult.Success;
        }
    }

    public RuleResult RetireKeys(string subject) {
        lock (_lock) {
            var holder = _keyHolders.Find(k => k.Subject == subject);
            if (!HasRegisteredKeys(holder))
                return RuleResult.Fail("Es sind keine Schlüssel registriert.");
            if (_ballots.Values.Any(b => IsPending(b) && b.KeyHolders.Any(k => k.Subject == subject)))
                return RuleResult.Fail("Erst veröffentlichen, wenn alle Wahlgänge mit diesen Schlüsseln abgeschlossen und unterschrieben sind.");

            _retiredKeys.Add(Convert.ToBase64String(holder.EncryptionKey!));
            holder.EncryptionKey = null;
            holder.SigningKey = null;
            holder.Confirmed = false;
            return RuleResult.Success;
        }
    }

    public RuleResult CreateBallot(BallotDraft draft, out Guid id) {
        id = Guid.NewGuid();
        var invalid = ValidateDraft(draft);
        if (invalid != null)
            return RuleResult.Fail(invalid);

        var ballot = new Ballot {
            Id = id,
            Title = draft.Title.Trim(),
            DefinitionJson = BallotDefinitionWriter.Write(id, draft)
        };
        lock (_lock) {
            _ballots.Add(id, ballot);
        }
        return RuleResult.Success;
    }

    public IReadOnlyList<BallotSummary> GetBallots(string? subject) {
        lock (_lock) {
            return _ballots.Values.Select(b => ToSummary(b, subject)).ToList();
        }
    }

    public OpenBallotView? GetCurrent() {
        lock (_lock) {
            var ballot = _ballots.Values.FirstOrDefault(b => b.Status == BallotStatus.Open);
            if (ballot == null)
                return null;
            return new OpenBallotView(ballot.Id, ballot.Title, ballot.DefinitionJson, ToPublicKeys(ballot.KeyHolders), ballot.CombinedFingerprint!);
        }
    }

    public bool HasVoted(Guid id, string subject) {
        lock (_lock) {
            return _ballots.TryGetValue(id, out var ballot) && ballot.Voted.Contains(subject);
        }
    }

    public RuleResult Open(Guid id, string subject) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot))
                return RuleResult.Fail("Unbekannter Wahlgang.");
            if (!_keyHolders.Any(k => k.Leads && k.Subject == subject))
                return RuleResult.Fail("Nur die Wahlleitung kann Wahlgänge öffnen.");
            if (ballot.Status != BallotStatus.Draft)
                return RuleResult.Fail("Dieser Wahlgang wurde bereits geöffnet.");
            if (_ballots.Values.Any(b => b.Status == BallotStatus.Open))
                return RuleResult.Fail("Es läuft bereits ein anderer Wahlgang.");
            if (_keyHolders.Any(k => !k.Confirmed))
                return RuleResult.Fail("Noch nicht alle Schlüssel sind registriert und bestätigt.");

            ballot.KeyHolders = _keyHolders
                .Select((k, i) => new KeyHolderSnapshot(i, k.Role, k.Subject, k.Leads, k.EncryptionKey!, k.SigningKey!))
                .ToList();
            ballot.CombinedFingerprint = CryptoFormats.CombinedFingerprint(id, ballot.KeyHolders.Select(k => k.EncryptionKey));
            ballot.Signatures = new string?[ballot.KeyHolders.Count];
            ballot.Status = BallotStatus.Open;
            return RuleResult.Success;
        }
    }

    public RuleResult Close(Guid id, string subject, bool isAdmin) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Open)
                return RuleResult.Fail("Dieser Wahlgang ist nicht geöffnet.");
            if (!isAdmin && !ballot.KeyHolders.Any(k => k.Leads && k.Subject == subject))
                return RuleResult.Fail("Nur die Wahlleitung kann Wahlgänge schließen.");

            ballot.VoterCount = ballot.Voted.Count;
            var sorted = CryptoFormats.SortByHash(ballot.Ciphertexts);
            ballot.Voted.Clear();
            ballot.Ciphertexts.Clear();
            ballot.Layers.Add(sorted);
            ballot.BundleJson = BundleWriter.Write(ballot, sorted);
            ballot.Status = BallotStatus.Closed;
            return RuleResult.Success;
        }
    }

    public CastOutcome Cast(Guid id, string subject, byte[] ciphertext) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Open)
                return CastOutcome.NotOpen;
            if (ciphertext.Length != CryptoFormats.CiphertextSize(ballot.KeyHolders.Count) || ciphertext[0] != CryptoFormats.Version)
                return CastOutcome.Malformed;
            if (!ballot.Voted.Add(subject))
                return CastOutcome.AlreadyVoted;

            ballot.Ciphertexts.Insert(RandomNumberGenerator.GetInt32(ballot.Ciphertexts.Count + 1), ciphertext);
            return CastOutcome.Accepted;
        }
    }

    public BulletinView? GetBulletin(Guid id) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Layers.Count == 0)
                return null;
            var receipts = ballot.Layers[0].Select(CryptoFormats.Sha256Hex).ToList();
            return new BulletinView(ballot.Id, ballot.Title, ballot.VoterCount, ballot.Layers[0].Count, receipts);
        }
    }

    public ClosedBallotView? GetClosed(Guid id, string subject) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Layers.Count == 0)
                return null;
            if (!ballot.KeyHolders.Any(k => k.Subject == subject))
                return null;
            return new ClosedBallotView(ballot.Id, ballot.Title, ballot.DefinitionJson, ballot.BundleJson!, ballot.CombinedFingerprint!,
                ballot.VoterCount, ToPublicKeys(ballot.KeyHolders), ballot.ResultDocument, ballot.Signatures.ToList());
        }
    }

    public IReadOnlyList<string>? GetLayer(Guid id, int index, string subject) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || index < 0 || index >= ballot.Layers.Count)
                return null;
            if (!ballot.KeyHolders.Any(k => k.Subject == subject))
                return null;
            return ballot.Layers[index].Select(Convert.ToBase64String).ToList();
        }
    }

    public RuleResult PutLayer(Guid id, int index, string subject, List<byte[]> items) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Closed)
                return RuleResult.Fail("Dieser Wahlgang ist nicht geschlossen.");
            var holderCount = ballot.KeyHolders.Count;
            if (!IsNextLayer(ballot, index))
                return RuleResult.Fail("Diese Schicht ist nicht an der Reihe oder wurde bereits hochgeladen.");
            if (ballot.KeyHolders[index - 1].Subject != subject)
                return RuleResult.Fail("Diese Schicht gehört einer anderen Person.");
            if (items.Count > ballot.Layers[index - 1].Count)
                return RuleResult.Fail("Die Schicht enthält mehr Einträge als die vorherige.");
            if (items.Count == 0 && ballot.Layers[index - 1].Count > 0)
                return RuleResult.Fail("Es wurde kein Stimmzettel entschlüsselt. Wurde die richtige Sicherungsdatei geladen?");
            var expectedSize = CryptoFormats.CiphertextSize(holderCount - index);
            if (items.Any(item => item.Length != expectedSize))
                return RuleResult.Fail("Die Schicht enthält Einträge mit falscher Größe.");

            ballot.Layers.Add(CryptoFormats.SortByHash(items));
            return RuleResult.Success;
        }
    }

    public RuleResult PutResult(Guid id, string subject, string document) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Closed)
                return RuleResult.Fail("Dieser Wahlgang ist nicht geschlossen.");
            if (ballot.Layers.Count != ballot.KeyHolders.Count + 1)
                return RuleResult.Fail("Es sind noch nicht alle Schichten entschlüsselt.");
            if (ballot.KeyHolders[^1].Subject != subject)
                return RuleResult.Fail("Das Ergebnis legt die letzte schlüsselhaltende Person fest.");
            if (ballot.ResultDocument != null)
                return RuleResult.Fail("Das Ergebnis wurde bereits festgelegt.");
            if (document.Length == 0 || document.Length > MaxResultLength)
                return RuleResult.Fail("Das Ergebnisdokument ist ungültig.");

            ballot.ResultDocument = document;
            return RuleResult.Success;
        }
    }

    public RuleResult PutSignature(Guid id, string subject, byte[] signature) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Closed)
                return RuleResult.Fail("Es liegt kein Ergebnis zum Unterschreiben vor.");
            if (ballot.ResultDocument == null)
                return RuleResult.Fail("Es liegt kein Ergebnis zum Unterschreiben vor.");
            var holder = ballot.KeyHolders.Find(k => k.Subject == subject);
            if (holder == null)
                return RuleResult.Fail("Du gehörst nicht zu den schlüsselhaltenden Personen dieses Wahlgangs.");
            if (ballot.Signatures[holder.Position] != null)
                return RuleResult.Fail("Du hast bereits unterschrieben.");
            if (!CryptoFormats.VerifySignature(holder.SigningKey, ballot.ResultDocument, signature))
                return RuleResult.Fail("Die Unterschrift passt nicht zu deinem registrierten Signaturschlüssel.");

            ballot.Signatures[holder.Position] = Convert.ToBase64String(signature);
            if (ballot.Signatures.All(s => s != null))
                ballot.Status = BallotStatus.Finished;
            return RuleResult.Success;
        }
    }

    public PublicationView? GetPublication(Guid id) {
        lock (_lock) {
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.Status != BallotStatus.Finished)
                return null;
            var layers = ballot.Layers
                .Select(layer => (IReadOnlyList<string>)layer.Select(Convert.ToBase64String).ToList())
                .ToList();
            return new PublicationView(ballot.Id, ballot.Title, ballot.DefinitionJson, ballot.BundleJson!, ballot.CombinedFingerprint!,
                ballot.VoterCount, ToPublicKeys(ballot.KeyHolders), layers, ballot.ResultDocument!, ballot.Signatures.Select(s => s!).ToList());
        }
    }

    internal IReadOnlyList<byte[]> PeekCiphertextOrder(Guid id) {
        lock (_lock) {
            return _ballots[id].Ciphertexts.ToList();
        }
    }

    private static bool HasRegisteredKeys([NotNullWhen(true)] KeyHolder? holder) {
        if (holder == null)
            return false;
        if (holder.EncryptionKey == null)
            return false;
        return holder.SigningKey != null;
    }

    private static bool HasFingerprints(KeyHolder holder, string encryptionFingerprint, string signingFingerprint) {
        if (CryptoFormats.Fingerprint(holder.EncryptionKey!) != encryptionFingerprint)
            return false;
        return CryptoFormats.Fingerprint(holder.SigningKey!) == signingFingerprint;
    }

    private static bool IsPending(Ballot ballot) => ballot.Status == BallotStatus.Open || ballot.Status == BallotStatus.Closed;

    private static bool IsNextLayer(Ballot ballot, int index) {
        if (index < 1)
            return false;
        if (index > ballot.KeyHolders.Count)
            return false;
        return ballot.Layers.Count == index;
    }

    private static bool HasValidSeats(BallotDraft draft, int optionCount) {
        if (draft.Type != BallotType.Approval)
            return true;
        if (draft.Seats < 1)
            return false;
        return draft.Seats <= optionCount;
    }

    private BallotSummary ToSummary(Ballot ballot, string? subject) {
        var mine = ballot.KeyHolders.Find(k => k.Subject == subject);
        var leads = ballot.Status == BallotStatus.Draft
            ? _keyHolders.Any(k => k.Leads && k.Subject == subject)
            : ballot.KeyHolders.Any(k => k.Leads && k.Subject == subject);
        var fingerprint = ballot.CombinedFingerprint ?? PreviewFingerprint(ballot.Id);
        var count = ballot.Status == BallotStatus.Open ? ballot.Voted.Count : ballot.VoterCount;
        var holderCount = ballot.Status == BallotStatus.Draft ? _keyHolders.Count : ballot.KeyHolders.Count;
        return new BallotSummary(ballot.Id, ballot.Title, ballot.Status, count, holderCount, ballot.Layers.Count,
            ballot.ResultDocument != null, ballot.Signatures.Count(s => s != null), fingerprint,
            mine?.Position ?? -1, leads, mine != null && ballot.Signatures[mine.Position] != null);
    }

    private string? PreviewFingerprint(Guid id) {
        if (_keyHolders.Count == 0 || _keyHolders.Any(k => k.EncryptionKey == null))
            return null;
        return CryptoFormats.CombinedFingerprint(id, _keyHolders.Select(k => k.EncryptionKey!));
    }

    private static List<PublicKeyEntry> ToPublicKeys(List<KeyHolderSnapshot> holders) {
        return holders
            .Select(k => new PublicKeyEntry(k.Position, k.Role, Convert.ToBase64String(k.EncryptionKey), Convert.ToBase64String(k.SigningKey)))
            .ToList();
    }

    private static KeyHolderView ToView(KeyHolder holder, int position) {
        return new KeyHolderView(position, holder.Role, holder.Username, holder.Leads,
            holder.EncryptionKey == null ? null : Convert.ToBase64String(holder.EncryptionKey),
            holder.SigningKey == null ? null : Convert.ToBase64String(holder.SigningKey),
            holder.EncryptionKey == null ? null : CryptoFormats.Fingerprint(holder.EncryptionKey),
            holder.SigningKey == null ? null : CryptoFormats.Fingerprint(holder.SigningKey),
            holder.Confirmed);
    }

    private static string? ValidateAssignments(IReadOnlyList<KeyHolderAssignment> assignments) {
        if (assignments.Count == 0)
            return "Es wird mindestens eine schlüsselhaltende Person benötigt.";
        if (assignments.Count(a => a.Leads) != 1)
            return "Genau eine Person muss die Wahl leiten.";
        if (assignments.Select(a => a.Subject).Distinct().Count() != assignments.Count)
            return "Jede Person darf nur einmal eingetragen sein.";
        if (assignments.Any(a => string.IsNullOrWhiteSpace(a.Role) || a.Role.Length > MaxTextLength))
            return "Jeder Eintrag braucht eine Rolle (höchstens 200 Zeichen).";
        return null;
    }

    private static string? ValidateDraft(BallotDraft draft) {
        if (string.IsNullOrWhiteSpace(draft.Title) || draft.Title.Length > MaxTextLength)
            return "Der Titel fehlt oder ist zu lang.";
        if (draft.Type == BallotType.YesNo)
            return null;

        var options = draft.Options.Select(o => o.Trim()).ToList();
        if (options.Count == 0 || options.Count >= MaxOptions)
            return "Bitte zwischen 1 und 49 Optionen angeben.";
        if (options.Any(o => o.Length == 0 || o.Length > MaxTextLength))
            return "Optionen dürfen nicht leer und höchstens 200 Zeichen lang sein.";
        if (options.Distinct(StringComparer.OrdinalIgnoreCase).Count() != options.Count)
            return "Jede Option darf nur einmal vorkommen.";
        if (!HasValidSeats(draft, options.Count))
            return "Die Zahl der Sitze muss zwischen 1 und der Zahl der Optionen liegen.";
        return null;
    }
}
