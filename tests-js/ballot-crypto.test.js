"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const BallotCrypto = require("../SecretBallot.Server/wwwroot/js/ballot-crypto.js");

const ballotId = "6f0c3c1e-6c55-4b0e-9a57-1f2f9a0c9d11";

async function makeHolders(count) {
    const holders = [];
    for (let i = 0; i < count; i++)
        holders.push(await BallotCrypto.generateEncryptionKeyPair());
    return holders;
}

async function peelAll(holders, id, envelope) {
    let data = envelope;
    for (const holder of holders)
        data = await BallotCrypto.decryptLayer(holder.privateKey, id, data);
    return data;
}

test("plaintext is padded to 512 bytes", () => {
    const plaintext = BallotCrypto.buildPlaintext(ballotId, "ab", [0, 2]);
    assert.equal(plaintext.length, 512);
    const parsed = JSON.parse(BallotCrypto.decodePlaintext(plaintext));
    assert.deepEqual(parsed.choice, [0, 2]);
    assert.equal(parsed.ballot, ballotId);
    assert.equal(parsed.v, 1);
});

test("plaintext with 50 chosen options still fits", () => {
    const choice = Array.from({ length: 50 }, (_, i) => i);
    assert.equal(BallotCrypto.buildPlaintext(ballotId, "f".repeat(64), choice).length, 512);
});

for (const count of [1, 4]) {
    test("layered round trip with " + count + " key holders", async () => {
        const holders = await makeHolders(count);
        const plaintext = BallotCrypto.buildPlaintext(ballotId, "ab", [1]);
        const envelope = await BallotCrypto.encryptBallot(holders.map(h => h.publicKey), ballotId, plaintext);
        assert.equal(envelope.length, BallotCrypto.ciphertextSize(count));
        assert.equal(envelope.length, 512 + count * 94);
        assert.deepEqual(await peelAll(holders, ballotId, envelope), plaintext);
    });
}

test("identical choices give different ciphertexts of equal length", async () => {
    const holders = await makeHolders(2);
    const keys = holders.map(h => h.publicKey);
    const first = await BallotCrypto.encryptBallot(keys, ballotId, BallotCrypto.buildPlaintext(ballotId, "ab", [0]));
    const second = await BallotCrypto.encryptBallot(keys, ballotId, BallotCrypto.buildPlaintext(ballotId, "ab", [0]));
    assert.equal(first.length, second.length);
    assert.notEqual(BallotCrypto.toHex(first), BallotCrypto.toHex(second));
});

test("fewer than all key holders cannot read the ballot", async () => {
    const holders = await makeHolders(4);
    const envelope = await BallotCrypto.encryptBallot(holders.map(h => h.publicKey), ballotId, BallotCrypto.buildPlaintext(ballotId, "ab", [0]));
    const three = await peelAll(holders.slice(0, 3), ballotId, envelope);
    assert.equal(three.length, 512 + 94);
    await assert.rejects(BallotCrypto.decryptLayer(holders[0].privateKey, ballotId, three));
    await assert.rejects(BallotCrypto.decryptLayer(holders[1].privateKey, ballotId, envelope));
});

test("tampered ciphertext fails and is counted", async () => {
    const holders = await makeHolders(1);
    const envelope = await BallotCrypto.encryptBallot([holders[0].publicKey], ballotId, BallotCrypto.buildPlaintext(ballotId, "ab", [0]));
    const tampered = envelope.slice();
    tampered[200] ^= 1;
    const result = await BallotCrypto.decryptLayerList(holders[0].privateKey, ballotId, [envelope, tampered]);
    assert.equal(result.outputs.length, 1);
    assert.equal(result.failed, 1);
});

test("ciphertext replayed into another ballot fails", async () => {
    const holders = await makeHolders(1);
    const envelope = await BallotCrypto.encryptBallot([holders[0].publicKey], ballotId, BallotCrypto.buildPlaintext(ballotId, "ab", [0]));
    await assert.rejects(BallotCrypto.decryptLayer(holders[0].privateKey, "another-ballot", envelope));
});

test("sortByHash orders by sha256 hex", async () => {
    const items = [BallotCrypto.utf8("a"), BallotCrypto.utf8("b"), BallotCrypto.utf8("c")];
    const sorted = await BallotCrypto.sortByHash(items);
    const hashes = await Promise.all(sorted.map(BallotCrypto.sha256Hex));
    assert.deepEqual(hashes, [...hashes].sort());
});

test("fingerprints have 8 groups of 4 hex digits and depend on ballot id", async () => {
    const holder = await BallotCrypto.generateEncryptionKeyPair();
    const raw = await BallotCrypto.exportRawPublicKey(holder.publicKey);
    assert.match(await BallotCrypto.fingerprint(raw), /^([0-9a-f]{4} ){7}[0-9a-f]{4}$/);
    const first = await BallotCrypto.combinedFingerprint(ballotId, [raw]);
    const second = await BallotCrypto.combinedFingerprint("other", [raw]);
    assert.notEqual(first, second);
});

test("backup round trip restores identical keys and rejects a wrong password", async () => {
    const encryption = await BallotCrypto.generateEncryptionKeyPair();
    const signing = await BallotCrypto.generateSigningKeyPair();
    const content = {
        role: "Wahlleitung",
        encryptionPrivateKey: await BallotCrypto.exportPrivateJwk(encryption.privateKey),
        signingPrivateKey: await BallotCrypto.exportPrivateJwk(signing.privateKey)
    };
    const file = await BallotCrypto.createBackup("korrekt pferd batterie", content);
    const restored = await BallotCrypto.openBackup("korrekt pferd batterie", file);
    assert.ok(BallotCrypto.backupMatches(content, restored));
    await assert.rejects(BallotCrypto.openBackup("falsch", file));
    const raw = await BallotCrypto.exportRawPublicKey(encryption.publicKey);
    assert.deepEqual(await BallotCrypto.publicRawFromPrivateJwk(restored.encryptionPrivateKey), raw);
});

test("signatures verify only for the signed text", async () => {
    const signing = await BallotCrypto.generateSigningKeyPair();
    const raw = await BallotCrypto.exportRawPublicKey(signing.publicKey);
    const signature = await BallotCrypto.sign(signing.privateKey, "{\"a\":1}");
    assert.ok(await BallotCrypto.verify(raw, "{\"a\":1}", signature));
    assert.equal(await BallotCrypto.verify(raw, "{\"a\":2}", signature), false);
});
