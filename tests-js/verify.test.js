"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
globalThis.BallotCrypto = require("../SecretBallot.Server/wwwroot/js/ballot-crypto.js");
globalThis.BallotTally = require("../SecretBallot.Server/wwwroot/js/ballot-tally.js");
const BallotVerify = require("../SecretBallot.Server/wwwroot/js/verify.js");
const C = globalThis.BallotCrypto;
const T = globalThis.BallotTally;

async function buildPublication() {
    const id = "6f0c3c1e-6c55-4b0e-9a57-1f2f9a0c9d11";
    const definitionJson = JSON.stringify({ id, title: "Beisitzer", type: "approval", options: ["Anna", "Bert"], seats: 2, noneOptionIndex: -1 });
    const definitionHash = await C.sha256Hex(C.utf8(definitionJson));
    const holders = [];
    for (let i = 0; i < 2; i++) {
        const encryption = await C.generateEncryptionKeyPair();
        const signing = await C.generateSigningKeyPair();
        holders.push({ encryption, signing, encryptionRaw: await C.exportRawPublicKey(encryption.publicKey), signingRaw: await C.exportRawPublicKey(signing.publicKey) });
    }
    const combinedFingerprint = await C.combinedFingerprint(id, holders.map(h => h.encryptionRaw));
    const envelopes = [];
    for (const choice of [[0], [0, 1], []])
        envelopes.push(await C.encryptBallot(holders.map(h => h.encryption.publicKey), id, C.buildPlaintext(id, definitionHash, choice)));
    const layers = [await C.sortByHash(envelopes)];
    for (const holder of holders)
        layers.push((await C.decryptLayerList(holder.encryption.privateKey, id, layers[layers.length - 1])).outputs);
    const bundleJson = JSON.stringify({ v: 1, ballot: id, definition: definitionJson, combinedFingerprint, keyHolders: holders.map((h, i) => ({ position: i, role: "R" + i, encryptionKey: C.toBase64(h.encryptionRaw) })), voterCount: 3, ciphertexts: layers[0].map(C.toBase64) });
    const tally = T.tally(JSON.parse(definitionJson), definitionHash, layers[2].map(C.decodePlaintext), 3);
    const resultDocument = T.buildResultDocument({ ballotId: id, title: "Beisitzer", definitionHash, bundleHash: await C.sha256Hex(C.utf8(bundleJson)), combinedFingerprint, voterCount: 3, tally });
    const signatures = [];
    for (const holder of holders)
        signatures.push(await C.sign(holder.signing.privateKey, resultDocument));
    const publication = {
        id, title: "Beisitzer", definitionJson, bundleJson, combinedFingerprint, voterCount: 3,
        keyHolders: holders.map((h, i) => ({ position: i, role: "R" + i, encryptionKey: C.toBase64(h.encryptionRaw), signingKey: C.toBase64(h.signingRaw) })),
        layers: layers.map(layer => layer.map(C.toBase64)), resultDocument, signatures
    };
    const keyFiles = await Promise.all(holders.map(async (h, i) => JSON.stringify({ format: "pp-ballot-decryption-key-v1", role: "R" + i, position: i, encryptionPrivateKey: await C.exportPrivateJwk(h.encryption.privateKey) })));
    return { publication, keyFiles, receipt: await C.sha256Hex(envelopes[0]), fingerprint: combinedFingerprint };
}

test("valid publication passes every check", async () => {
    const { publication, keyFiles, fingerprint } = await buildPublication();
    const report = await BallotVerify.verifyPublication(publication, keyFiles, fingerprint.toUpperCase().replace(/ /g, ""));
    assert.ok(report.checks.every(c => c.ok), JSON.stringify(report.checks.filter(c => !c.ok)));
    assert.deepEqual(report.tally.counts, [2, 1]);
});

test("tampered ciphertext is flagged", async () => {
    const { publication, keyFiles, fingerprint } = await buildPublication();
    const bytes = C.fromBase64(publication.layers[0][0]);
    bytes[300] ^= 1;
    publication.layers[0][0] = C.toBase64(bytes);
    const report = await BallotVerify.verifyPublication(publication, keyFiles, fingerprint);
    assert.ok(report.checks.some(c => !c.ok));
});

test("a missing signature fails", async () => {
    const { publication, keyFiles, fingerprint } = await buildPublication();
    publication.signatures[1] = publication.signatures[0];
    const report = await BallotVerify.verifyPublication(publication, keyFiles, fingerprint);
    assert.ok(report.checks.some(c => !c.ok && c.label.startsWith("Unterschrift")));
});

test("receipt lookup", async () => {
    const { publication, receipt } = await buildPublication();
    assert.ok(await BallotVerify.findReceipt(publication, receipt.substring(0, 16)));
    assert.equal(await BallotVerify.findReceipt(publication, "0000000000000000"), false);
});

test("a self-consistent but re-forged publication fails against the read-out fingerprint", async () => {
    const original = await buildPublication();
    const forged = await buildPublication();
    const report = await BallotVerify.verifyPublication(forged.publication, forged.keyFiles, original.fingerprint);
    assert.ok(report.checks.some(c => !c.ok && c.label.startsWith("Vorgelesener Fingerabdruck")));
});

test("a missing read-out fingerprint fails", async () => {
    const { publication, keyFiles } = await buildPublication();
    const report = await BallotVerify.verifyPublication(publication, keyFiles, "");
    assert.ok(report.checks.some(c => !c.ok && c.label.startsWith("Vorgelesener Fingerabdruck")));
});

test("key files are matched by public key, not by stated position", async () => {
    const { publication, keyFiles, fingerprint } = await buildPublication();
    const swapped = keyFiles.map((text, i) => JSON.stringify(Object.assign(JSON.parse(text), { position: keyFiles.length - 1 - i }))).reverse();
    const report = await BallotVerify.verifyPublication(publication, swapped, fingerprint);
    assert.ok(report.checks.every(c => c.ok), JSON.stringify(report.checks.filter(c => !c.ok)));
});

test("report exposes the result document hash and signing key fingerprints", async () => {
    const { publication, keyFiles, fingerprint } = await buildPublication();
    const report = await BallotVerify.verifyPublication(publication, keyFiles, fingerprint);
    assert.equal(report.resultDocumentHash, await C.sha256Hex(C.utf8(publication.resultDocument)));
    assert.equal(report.signingFingerprints.length, 2);
});
