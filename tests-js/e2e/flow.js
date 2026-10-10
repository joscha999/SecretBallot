"use strict";
const assert = require("node:assert/strict");
globalThis.BallotCrypto = require("../../SecretBallot.Server/wwwroot/js/ballot-crypto.js");
globalThis.BallotTally = require("../../SecretBallot.Server/wwwroot/js/ballot-tally.js");
const BallotVerify = require("../../SecretBallot.Server/wwwroot/js/verify.js");
const C = globalThis.BallotCrypto;
const T = globalThis.BallotTally;

const baseUrl = process.argv[2];
const holderCount = Number(process.argv[3] || "2");

async function call(user, method, path, body) {
    const headers = { "Accept": "application/json", "X-Secret-Ballot": "1" };
    if (user)
        headers["X-Test-User"] = user;
    if (body !== undefined)
        headers["Content-Type"] = "application/json";
    const response = await fetch(baseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await response.text();
    return { status: response.status, data: text.length > 0 ? JSON.parse(text) : null };
}

async function ok(user, method, path, body) {
    const result = await call(user, method, path, body);
    if (result.status >= 300)
        throw new Error(method + " " + path + " as " + user + " -> " + result.status + " " + JSON.stringify(result.data));
    return result.data;
}

async function setUpKeyHolders() {
    const entries = [];
    for (let i = 0; i < holderCount; i++)
        entries.push({ role: "Rolle " + i, username: "kh" + i, leads: i === 0 });
    await ok("admin", "PUT", "/api/admin/keyholders", entries);

    const holders = [];
    for (let i = 0; i < holderCount; i++) {
        const user = "kh" + i;
        const encryption = await C.generateEncryptionKeyPair();
        const signing = await C.generateSigningKeyPair();
        const encryptionRaw = await C.exportRawPublicKey(encryption.publicKey);
        const signingRaw = await C.exportRawPublicKey(signing.publicKey);
        await ok(user, "PUT", "/api/keyholder/keys", { encryptionKey: C.toBase64(encryptionRaw), signingKey: C.toBase64(signingRaw) });
        const me = await ok(user, "GET", "/api/me");
        assert.equal(me.keyHolder.encryptionFingerprint, await C.fingerprint(encryptionRaw));
        await ok(user, "POST", "/api/keyholder/confirm", { encryptionFingerprint: me.keyHolder.encryptionFingerprint, signingFingerprint: me.keyHolder.signingFingerprint });
        holders.push({ user, encryption, signing });
    }
    return holders;
}

async function vote(user, choice) {
    const { ballot } = await ok(user, "GET", "/api/ballots/current");
    const rawKeys = ballot.keyHolders.map(k => C.fromBase64(k.encryptionKey));
    assert.equal(await C.combinedFingerprint(ballot.id, rawKeys), ballot.combinedFingerprint);
    const keys = await Promise.all(rawKeys.map(C.importEncryptionPublicKey));
    const definitionHash = await C.sha256Hex(C.utf8(ballot.definitionJson));
    const envelope = await C.encryptBallot(keys, ballot.id, C.buildPlaintext(ballot.id, definitionHash, choice));
    const result = await call(user, "POST", "/api/ballots/" + ballot.id + "/votes", { ciphertext: C.toBase64(envelope) });
    return { status: result.status, receipt: await C.sha256Hex(envelope), envelope };
}

async function main() {
    const holders = await setUpKeyHolders();
    const created = await ok("admin", "POST", "/api/admin/ballots", { title: "Beisitzer", type: "approval", options: ["Anna", "Bert", "Cem"], seats: 2 });
    const id = created.id;

    assert.equal((await call("v0", "POST", "/api/keyholder/ballots/" + id + "/open")).status, 409);
    await ok("kh0", "POST", "/api/keyholder/ballots/" + id + "/open");

    const readOutFingerprint = (await ok("v0", "GET", "/api/ballots/current")).ballot.combinedFingerprint;
    const choices = [[0, 1], [0, 1], [0], [1, 2], []];
    const receipts = [];
    for (let i = 0; i < choices.length; i++) {
        const cast = await vote("v" + i, choices[i]);
        assert.equal(cast.status, 204);
        assert.equal(cast.envelope.length, 512 + holderCount * 94);
        receipts.push(cast.receipt);
    }
    assert.equal((await vote("v0", [2])).status, 409);
    assert.equal((await vote("ineligible", [0])).status, 403);
    assert.equal((await vote(null, [0])).status, 401);

    await ok("kh0", "POST", "/api/keyholder/ballots/" + id + "/close");
    const bulletin = await ok(null, "GET", "/api/ballots/" + id + "/bulletin");
    assert.equal(bulletin.voterCount, 5);
    assert.equal(bulletin.ciphertextCount, 5);
    for (const receipt of receipts)
        assert.ok(bulletin.receipts.includes(receipt));

    for (let i = 0; i < holderCount; i++) {
        const previous = await ok(holders[i].user, "GET", "/api/keyholder/ballots/" + id + "/layers/" + i);
        const { outputs, failed } = await C.decryptLayerList(holders[i].encryption.privateKey, id, previous.items.map(C.fromBase64));
        assert.equal(failed, 0);
        await ok(holders[i].user, "PUT", "/api/keyholder/ballots/" + id + "/layers/" + (i + 1), { items: outputs.map(C.toBase64) });
    }

    const last = holders[holderCount - 1];
    const closed = await ok(last.user, "GET", "/api/keyholder/ballots/" + id);
    const finalLayer = await ok(last.user, "GET", "/api/keyholder/ballots/" + id + "/layers/" + holderCount);
    const definitionHash = await C.sha256Hex(C.utf8(closed.definitionJson));
    const tally = T.tally(JSON.parse(closed.definitionJson), definitionHash, finalLayer.items.map(item => C.decodePlaintext(C.fromBase64(item))), JSON.parse(closed.bundleJson).ciphertexts.length);
    const document = T.buildResultDocument({
        ballotId: id, title: closed.title, definitionHash, bundleHash: await C.sha256Hex(C.utf8(closed.bundleJson)),
        combinedFingerprint: closed.combinedFingerprint, voterCount: closed.voterCount, tally
    });
    await ok(last.user, "PUT", "/api/keyholder/ballots/" + id + "/result", { document });

    for (const holder of holders)
        await ok(holder.user, "PUT", "/api/keyholder/ballots/" + id + "/signature", { signature: await C.sign(holder.signing.privateKey, document) });

    const publication = await ok(null, "GET", "/api/ballots/" + id + "/publication");
    const keyFiles = await Promise.all(holders.map(async (holder, position) =>
        JSON.stringify({ format: "pp-ballot-decryption-key-v1", position, encryptionPrivateKey: await C.exportPrivateJwk(holder.encryption.privateKey) })));
    const report = await BallotVerify.verifyPublication(publication, keyFiles, readOutFingerprint);
    const failedChecks = report.checks.filter(c => !c.ok);
    assert.deepEqual(failedChecks, []);
    assert.deepEqual(report.tally.counts, [3, 3, 1]);
    assert.deepEqual(report.tally.withEmpty.elected, [0, 1]);
    assert.ok(await BallotVerify.findReceipt(publication, receipts[3]));
    for (const holder of holders) {
        await ok(holder.user, "POST", "/api/keyholder/retire");
        const raw = await C.exportRawPublicKey(holder.encryption.publicKey);
        const signingRaw = await C.exportRawPublicKey(holder.signing.publicKey);
        const reuse = await call(holder.user, "PUT", "/api/keyholder/keys", { encryptionKey: C.toBase64(raw), signingKey: C.toBase64(signingRaw) });
        assert.equal(reuse.status, 409);
    }
    const next = await ok("admin", "POST", "/api/admin/ballots", { title: "Stichwahl", type: "single", options: ["Anna", "Bert"], seats: 1 });
    assert.equal((await call("kh0", "POST", "/api/keyholder/ballots/" + next.id + "/open")).status, 409);

    console.log("E2E OK with " + holderCount + " key holders, " + report.checks.length + " checks");
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
