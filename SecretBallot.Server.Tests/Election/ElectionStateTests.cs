using SecretBallot.Server.Election;

namespace SecretBallot.Server.Tests.Election;

public class ElectionStateTests {
    private readonly ElectionState _state = new();
    private readonly List<TestKeys> _keys = new();

    private void SetUpHolders(int count) {
        var assignments = new List<KeyHolderAssignment>();
        for (var i = 0; i < count; i++)
            assignments.Add(new KeyHolderAssignment($"Rolle {i}", $"sub-{i}", $"user{i}", i == 0));
        _state.ReplaceKeyHolders(assignments);

        for (var i = 0; i < count; i++) {
            var keys = new TestKeys();
            _keys.Add(keys);
            _state.RegisterKeys($"sub-{i}", keys.EncryptionPublic, keys.SigningPublic);
            _state.ConfirmKeys($"sub-{i}", CryptoFormats.Fingerprint(keys.EncryptionPublic), CryptoFormats.Fingerprint(keys.SigningPublic));
        }
    }

    private Guid CreateOpenBallot(int holders) {
        SetUpHolders(holders);
        _state.CreateBallot(new BallotDraft("Beisitzer", BallotType.Approval, new[] { "Anna", "Bert" }, 2), out var id);
        _state.Open(id, "sub-0");
        return id;
    }

    private static byte[] Ciphertext(int holders, byte fill) {
        var bytes = new byte[CryptoFormats.CiphertextSize(holders)];
        Array.Fill(bytes, fill);
        bytes[0] = CryptoFormats.Version;
        return bytes;
    }

    [Test]
    public async Task Second_cast_by_same_subject_is_rejected() {
        var id = CreateOpenBallot(1);
        await Assert.That(_state.Cast(id, "voter", Ciphertext(1, 7))).IsEqualTo(CastOutcome.Accepted);
        await Assert.That(_state.Cast(id, "voter", Ciphertext(1, 8))).IsEqualTo(CastOutcome.AlreadyVoted);
    }

    [Test]
    public async Task Wrong_size_or_version_is_malformed() {
        var id = CreateOpenBallot(2);
        await Assert.That(_state.Cast(id, "a", Ciphertext(1, 7))).IsEqualTo(CastOutcome.Malformed);
        var wrongVersion = Ciphertext(2, 7);
        wrongVersion[0] = 2;
        await Assert.That(_state.Cast(id, "b", wrongVersion)).IsEqualTo(CastOutcome.Malformed);
        await Assert.That(_state.HasVoted(id, "b")).IsFalse();
    }

    [Test]
    public async Task Cannot_open_with_unconfirmed_keys() {
        _state.ReplaceKeyHolders(new[] { new KeyHolderAssignment("WL", "sub-0", "user0", true) });
        var keys = new TestKeys();
        _state.RegisterKeys("sub-0", keys.EncryptionPublic, keys.SigningPublic);
        _state.CreateBallot(new BallotDraft("Test", BallotType.YesNo, Array.Empty<string>(), 1), out var id);
        await Assert.That(_state.Open(id, "sub-0").Ok).IsFalse();
    }

    [Test]
    public async Task Confirm_with_wrong_fingerprint_fails() {
        _state.ReplaceKeyHolders(new[] { new KeyHolderAssignment("WL", "sub-0", "user0", true) });
        var keys = new TestKeys();
        _state.RegisterKeys("sub-0", keys.EncryptionPublic, keys.SigningPublic);
        var result = _state.ConfirmKeys("sub-0", "0000 0000 0000 0000 0000 0000 0000 0000", CryptoFormats.Fingerprint(keys.SigningPublic));
        await Assert.That(result.Ok).IsFalse();
    }

    [Test]
    public async Task Only_leader_opens_and_only_one_ballot_at_a_time() {
        SetUpHolders(2);
        _state.CreateBallot(new BallotDraft("A", BallotType.YesNo, Array.Empty<string>(), 1), out var first);
        _state.CreateBallot(new BallotDraft("B", BallotType.YesNo, Array.Empty<string>(), 1), out var second);
        await Assert.That(_state.Open(first, "sub-1").Ok).IsFalse();
        await Assert.That(_state.Open(first, "sub-0").Ok).IsTrue();
        await Assert.That(_state.Open(second, "sub-0").Ok).IsFalse();
    }

    [Test]
    public async Task Close_sorts_by_hash_and_counts_voters() {
        var id = CreateOpenBallot(1);
        for (byte i = 1; i <= 5; i++)
            _state.Cast(id, $"voter-{i}", Ciphertext(1, i));
        await Assert.That(_state.Close(id, "sub-0", false).Ok).IsTrue();

        var bulletin = _state.GetBulletin(id)!;
        await Assert.That(bulletin.VoterCount).IsEqualTo(5);
        await Assert.That(bulletin.CiphertextCount).IsEqualTo(5);
        await Assert.That(bulletin.Receipts.SequenceEqual(bulletin.Receipts.Order(StringComparer.Ordinal))).IsTrue();
        await Assert.That(_state.HasVoted(id, "voter-1")).IsFalse();
        await Assert.That(_state.Cast(id, "late", Ciphertext(1, 9))).IsEqualTo(CastOutcome.NotOpen);
    }

    [Test]
    public async Task Admin_can_close_as_fallback_others_cannot() {
        var id = CreateOpenBallot(2);
        await Assert.That(_state.Close(id, "sub-1", false).Ok).IsFalse();
        await Assert.That(_state.Close(id, "someone", true).Ok).IsTrue();
    }

    [Test]
    public async Task Layers_must_come_in_order_from_the_right_person_with_right_sizes() {
        var id = CreateOpenBallot(2);
        _state.Cast(id, "v1", Ciphertext(2, 1));
        _state.Cast(id, "v2", Ciphertext(2, 2));
        _state.Close(id, "sub-0", false);

        var layer1 = new List<byte[]> { new byte[CryptoFormats.CiphertextSize(1)], new byte[CryptoFormats.CiphertextSize(1)] };
        var final = new List<byte[]> { new byte[512], new byte[512] };

        await Assert.That(_state.PutLayer(id, 2, "sub-1", final).Ok).IsFalse();
        await Assert.That(_state.PutLayer(id, 1, "sub-1", layer1).Ok).IsFalse();
        await Assert.That(_state.PutLayer(id, 1, "sub-0", final).Ok).IsFalse();
        await Assert.That(_state.PutLayer(id, 1, "sub-0", layer1).Ok).IsTrue();
        await Assert.That(_state.PutLayer(id, 1, "sub-0", layer1).Ok).IsFalse();
        var tooMany = new List<byte[]> { new byte[512], new byte[512], new byte[512] };
        await Assert.That(_state.PutLayer(id, 2, "sub-1", tooMany).Ok).IsFalse();
        await Assert.That(_state.PutLayer(id, 2, "sub-1", final).Ok).IsTrue();
    }

    [Test]
    public async Task Result_and_signatures_finish_the_ballot() {
        var id = CreateOpenBallot(2);
        _state.Cast(id, "v1", Ciphertext(2, 1));
        _state.Close(id, "sub-0", false);
        _state.PutLayer(id, 1, "sub-0", new List<byte[]> { new byte[CryptoFormats.CiphertextSize(1)] });
        _state.PutLayer(id, 2, "sub-1", new List<byte[]> { new byte[512] });

        await Assert.That(_state.PutResult(id, "sub-0", "{}").Ok).IsFalse();
        await Assert.That(_state.PutResult(id, "sub-1", "{\"v\":1}").Ok).IsTrue();
        await Assert.That(_state.PutSignature(id, "sub-0", _keys[1].Sign("{\"v\":1}")).Ok).IsFalse();
        await Assert.That(_state.PutSignature(id, "sub-0", _keys[0].Sign("{\"v\":1}")).Ok).IsTrue();
        await Assert.That(_state.GetPublication(id)).IsNull();
        await Assert.That(_state.PutSignature(id, "sub-1", _keys[1].Sign("{\"v\":1}")).Ok).IsTrue();

        var publication = _state.GetPublication(id)!;
        await Assert.That(publication.Layers.Count).IsEqualTo(3);
        await Assert.That(publication.Signatures.Count).IsEqualTo(2);
    }

    [Test]
    public async Task Replacing_list_keeps_keys_of_same_person_and_drops_others() {
        SetUpHolders(2);
        _state.ReplaceKeyHolders(new[] {
            new KeyHolderAssignment("WL", "sub-1", "user1", true),
            new KeyHolderAssignment("WH", "sub-9", "user9", false)
        });
        var holders = _state.GetKeyHolders();
        await Assert.That(holders[0].Confirmed).IsTrue();
        await Assert.That(holders[1].EncryptionKey).IsNull();
    }

    [Test]
    public async Task Key_list_needs_exactly_one_leader() {
        var none = _state.ReplaceKeyHolders(new[] { new KeyHolderAssignment("WL", "a", "a", false) });
        var two = _state.ReplaceKeyHolders(new[] {
            new KeyHolderAssignment("WL", "a", "a", true),
            new KeyHolderAssignment("WH", "b", "b", true)
        });
        await Assert.That(none.Ok).IsFalse();
        await Assert.That(two.Ok).IsFalse();
    }

    [Test]
    public async Task Single_choice_definition_gets_none_option() {
        SetUpHolders(1);
        _state.CreateBallot(new BallotDraft("Stichwahl", BallotType.Single, new[] { "Anna", "Bert" }, 1), out var id);
        _state.Open(id, "sub-0");
        var current = _state.GetCurrent()!;
        await Assert.That(current.DefinitionJson).Contains("keinen der Kandidierenden");
        await Assert.That(current.DefinitionJson).Contains("\"noneOptionIndex\":2");
    }

    [Test]
    public async Task Approval_seats_must_not_exceed_options() {
        SetUpHolders(1);
        var result = _state.CreateBallot(new BallotDraft("X", BallotType.Approval, new[] { "Anna" }, 2), out _);
        await Assert.That(result.Ok).IsFalse();
    }

    [Test]
    public async Task Retired_keys_block_opening_and_cannot_be_registered_again() {
        SetUpHolders(1);
        var keys = _keys[0];
        await Assert.That(_state.RetireKeys("sub-0").Ok).IsTrue();
        _state.CreateBallot(new BallotDraft("Stichwahl", BallotType.YesNo, Array.Empty<string>(), 1), out var id);
        await Assert.That(_state.Open(id, "sub-0").Ok).IsFalse();
        await Assert.That(_state.RegisterKeys("sub-0", keys.EncryptionPublic, keys.SigningPublic).Ok).IsFalse();

        var fresh = new TestKeys();
        await Assert.That(_state.RegisterKeys("sub-0", fresh.EncryptionPublic, fresh.SigningPublic).Ok).IsTrue();
    }

    [Test]
    public async Task Retire_is_refused_while_a_ballot_with_these_keys_is_not_finished() {
        var id = CreateOpenBallot(1);
        await Assert.That(_state.RetireKeys("sub-0").Ok).IsFalse();
        _state.Cast(id, "v1", Ciphertext(1, 1));
        _state.Close(id, "sub-0", false);
        await Assert.That(_state.RetireKeys("sub-0").Ok).IsFalse();
    }

    [Test]
    public async Task Empty_layer_is_rejected_when_previous_layer_has_ballots() {
        var id = CreateOpenBallot(2);
        _state.Cast(id, "v1", Ciphertext(2, 1));
        _state.Close(id, "sub-0", false);
        await Assert.That(_state.PutLayer(id, 1, "sub-0", new List<byte[]>()).Ok).IsFalse();
    }

    [Test]
    public async Task Stored_ciphertext_order_does_not_follow_submission_order() {
        var id = CreateOpenBallot(1);
        var submitted = new List<byte[]>();
        for (byte i = 1; i <= 30; i++) {
            var ciphertext = Ciphertext(1, i);
            submitted.Add(ciphertext);
            _state.Cast(id, $"voter-{i}", ciphertext);
        }
        await Assert.That(_state.PeekCiphertextOrder(id).SequenceEqual(submitted)).IsFalse();
    }
}
