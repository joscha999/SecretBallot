# SecretBallot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A small web tool for secret online elections where the server knows who voted, the key holders together know what was voted, and anyone can recount after publication.

**Architecture:** A .NET 10 minimal API keeps all state in RAM and serves plain classic-script JavaScript pages from `wwwroot`. Ballots are encrypted in the browser in N layers (ECDH P-256 + HKDF + AES-GCM), one per key holder; key holders peel their layer in their own browser in list order. The tally and all crypto live in two shared scripts that the voting page, the key holder page, the offline verifier and the Node tests all use.

**Tech Stack:** .NET 10, ASP.NET Core minimal API, Microsoft.AspNetCore.Authentication.OpenIdConnect, TUnit, Web Crypto API, Node 24 (`node --test`, development only).

**Spec:** `/media/SMB/SecretBallot/docs/superpowers/specs/2026-10-09-secretballot-design.md` (design) on top of `/media/SMB/TODO/obpt-2026-10-10/secret-ballot-tool-spec.md` (base spec).

## Global Constraints

- Code, identifiers, API contracts in English; every user-visible string in German.
- Code style: `/media/SMB/Quartermaster/CLAUDE.md` (K&R braces, `if` body on next line, braces omitted only for a single statement without else, `System.Threading.Lock`, `var`, fluent LINQ, explicit access modifiers, `_camelCase` only for readonly fields, no region comments). The same `if` rules apply to JavaScript.
- Comments: none by default; a comment only for a non-obvious WHY. Explanations go into `docs/`.
- No README. No git commands (the user commits).
- No persistence: no database, no file writes, `UseEphemeralDataProtectionProvider()`.
- No code path logs request bodies; no log line contains a subject together with ballot data.
- Crypto constants: P-256, HKDF-SHA-256 with salt = ephemeral public key and info = `"pp-ballot-v1" || ballot id`, AES-256-GCM with 96-bit IV and ballot id as AAD, envelope `version(1)=0x01 || ephemeral key (65) || IV (12) || ciphertext+tag`, plaintext padded with spaces to 512 bytes, layer overhead 94 bytes, size `512 + N * 94`.
- Fingerprint: first 16 bytes of SHA-256, lowercase hex, 8 groups of 4 separated by spaces. Combined fingerprint over `"pp-ballot-keys-v1" || ballot id || K1 || ... || KN`.
- Backup: PBKDF2-SHA-256, 600 000 iterations, 16-byte salt, AES-256-GCM.
- Ciphertexts and keys travel as standard base64; hashes as lowercase hex.
- Builds: `dotnet build -m:1`; tests: `dotnet run --project SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`, never `dotnet test`. JS tests: `node --test tests-js/`. Keep heavy work to 2 threads.
- Node is development-only; the deployed tool is the .NET server and static files.

## Deviations decided while planning

- All scripts are classic scripts exposing globals (`BallotCrypto`, `BallotTally`, `BallotDom`, `BallotApi`), not ES modules, so `pruefen.html` works from `file://` and Node can `require()` them.
- SRI is replaced by a published SHA-256 list of every `wwwroot` file (`tools/wwwroot-hashes.sh`). The HTML comes from the same server as the scripts, so SRI attributes would add no protection against a compromised server.
- An admin may close an open ballot as a fallback when the leader is unreachable. Closing reveals nothing.
- Private keys live only in page memory. Every action that needs them (register after restart, decrypt, sign, export) first loads the backup file.

## Review Focus

- Network failure after the server accepted a vote: the retry gets "bereits abgestimmt", and the voter must still see the receipt of the ciphertext they sent. Pinned in Task 6 (UI keeps the receipt computed before sending) and Task 3 (`Cast` returns `AlreadyVoted` distinctly).
- Server restart after keys were registered: the key list is empty except for what the admin re-enters; key holders must be able to register again from the backup file. Pinned in Task 7 (restore path calls register) and Task 3 (register after replace works).
- Approval ballots where every ballot is empty (majority base 0) must elect nobody without dividing by zero. Pinned in Task 2 tests.
- Layer uploads by the wrong person, out of order, twice, or with wrong item sizes must be rejected. Pinned in Task 3 tests.
- Keycloak down or answering 500 during a cast must reject the vote, never accept it. Pinned in Task 4 tests.

---

### Task 1: Solution scaffold and crypto script

**Files:**
- Create: `/media/SMB/SecretBallot/SecretBallot.slnx`
- Create: `/media/SMB/SecretBallot/Directory.Build.props`
- Create: `/media/SMB/SecretBallot/global.json`
- Create: `/media/SMB/SecretBallot/.editorconfig` (copy of `/media/SMB/MemberDataImport/.editorconfig`)
- Create: `/media/SMB/SecretBallot/SecretBallot.Server/SecretBallot.Server.csproj`
- Create: `/media/SMB/SecretBallot/SecretBallot.Server/wwwroot/js/ballot-crypto.js`
- Test: `/media/SMB/SecretBallot/tests-js/ballot-crypto.test.js`

**Interfaces:**
- Produces (global `BallotCrypto`, also `module.exports`): `VERSION`, `PLAINTEXT_SIZE`, `LAYER_OVERHEAD`, `ciphertextSize(layerCount)`, `concatBytes(...parts)`, `utf8(text)`, `toHex(bytes)`, `toBase64(bytes)`, `fromBase64(text)`, `randomBytes(n)`, `sha256Hex(bytes)`, `fingerprint(rawKey) -> string`, `combinedFingerprint(ballotId, rawKeys[]) -> string`, `generateEncryptionKeyPair()`, `generateSigningKeyPair()`, `exportRawPublicKey(key) -> Uint8Array(65)`, `exportPrivateJwk(key)`, `importEncryptionPublicKey(raw)`, `importEncryptionPrivateJwk(jwk)`, `importSigningPrivateJwk(jwk)`, `publicRawFromPrivateJwk(jwk) -> Uint8Array(65)`, `encryptLayer(publicKey, ballotId, bytes)`, `decryptLayer(privateKey, ballotId, envelope)`, `encryptBallot(publicKeysInOrder[], ballotId, plaintext)`, `decryptLayerList(privateKey, ballotId, envelopes[]) -> {outputs, failed}`, `sortByHash(items[])`, `buildPlaintext(ballotId, definitionHash, choice[]) -> Uint8Array(512)`, `decodePlaintext(bytes) -> string`, `createBackup(password, content) -> string`, `openBackup(password, text) -> content`, `backupMatches(a, b) -> bool`, `sign(privateKey, text) -> base64`, `verify(publicRaw, text, signatureBase64) -> bool`.
- Backup content shape: `{ role, encryptionPrivateKey: JWK, signingPrivateKey: JWK }`.

- [ ] **Step 1: Scaffold files**

`Directory.Build.props`:
```xml
<Project>
  <PropertyGroup>
    <BaseIntermediateOutputPath>/tmp/sb-build/$(MSBuildProjectName)/obj/</BaseIntermediateOutputPath>
  </PropertyGroup>
</Project>
```

`global.json`:
```json
{
    "test": {
        "runner": "Microsoft.Testing.Platform"
    }
}
```

`SecretBallot.slnx`:
```xml
<Solution>
  <Project Path="SecretBallot.Server/SecretBallot.Server.csproj" />
  <Project Path="SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj" />
</Solution>
```

`SecretBallot.Server/SecretBallot.Server.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.OpenIdConnect" Version="10.0.*" />
  </ItemGroup>
</Project>
```

`cp /media/SMB/MemberDataImport/.editorconfig /media/SMB/SecretBallot/.editorconfig`

- [ ] **Step 2: Write the failing tests**

`tests-js/ballot-crypto.test.js`:
```js
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd /media/SMB/SecretBallot && node --test tests-js/`
Expected: FAIL, `Cannot find module '../SecretBallot.Server/wwwroot/js/ballot-crypto.js'`

- [ ] **Step 4: Implement `ballot-crypto.js`**

```js
(function (root) {
    "use strict";

    const subtle = root.crypto.subtle;
    const VERSION = 1;
    const PLAINTEXT_SIZE = 512;
    const PUBLIC_KEY_SIZE = 65;
    const IV_SIZE = 12;
    const TAG_SIZE = 16;
    const LAYER_OVERHEAD = 1 + PUBLIC_KEY_SIZE + IV_SIZE + TAG_SIZE;
    const KDF_INFO = "pp-ballot-v1";
    const KEYS_DOMAIN = "pp-ballot-keys-v1";
    const BACKUP_FORMAT = "pp-ballot-backup-v1";
    const BACKUP_ITERATIONS = 600000;
    const ECDH = { name: "ECDH", namedCurve: "P-256" };
    const ECDSA = { name: "ECDSA", namedCurve: "P-256" };
    const SIGN_PARAMS = { name: "ECDSA", hash: "SHA-256" };

    const encoder = new TextEncoder();
    const decoder = new TextDecoder("utf-8", { fatal: true });

    function utf8(text) {
        return encoder.encode(text);
    }

    function concatBytes(...parts) {
        const total = parts.reduce((sum, part) => sum + part.length, 0);
        const result = new Uint8Array(total);
        let offset = 0;
        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }
        return result;
    }

    function toHex(bytes) {
        return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    }

    function toBase64(bytes) {
        let binary = "";
        for (const b of bytes)
            binary += String.fromCharCode(b);
        return btoa(binary);
    }

    function fromBase64(text) {
        const binary = atob(text);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++)
            bytes[i] = binary.charCodeAt(i);
        return bytes;
    }

    function randomBytes(count) {
        return root.crypto.getRandomValues(new Uint8Array(count));
    }

    function ciphertextSize(layerCount) {
        return PLAINTEXT_SIZE + layerCount * LAYER_OVERHEAD;
    }

    async function sha256(bytes) {
        return new Uint8Array(await subtle.digest("SHA-256", bytes));
    }

    async function sha256Hex(bytes) {
        return toHex(await sha256(bytes));
    }

    function formatFingerprint(digest) {
        const hex = toHex(digest.subarray(0, 16));
        return hex.match(/.{4}/g).join(" ");
    }

    async function fingerprint(rawKey) {
        return formatFingerprint(await sha256(rawKey));
    }

    async function combinedFingerprint(ballotId, rawKeys) {
        return formatFingerprint(await sha256(concatBytes(utf8(KEYS_DOMAIN), utf8(ballotId), ...rawKeys)));
    }

    function generateEncryptionKeyPair() {
        return subtle.generateKey(ECDH, true, ["deriveBits"]);
    }

    function generateSigningKeyPair() {
        return subtle.generateKey(ECDSA, true, ["sign", "verify"]);
    }

    async function exportRawPublicKey(key) {
        return new Uint8Array(await subtle.exportKey("raw", key));
    }

    function exportPrivateJwk(key) {
        return subtle.exportKey("jwk", key);
    }

    function importEncryptionPublicKey(raw) {
        return subtle.importKey("raw", raw, ECDH, true, []);
    }

    function importEncryptionPrivateJwk(jwk) {
        return subtle.importKey("jwk", jwk, ECDH, true, ["deriveBits"]);
    }

    function importSigningPrivateJwk(jwk) {
        return subtle.importKey("jwk", jwk, ECDSA, false, ["sign"]);
    }

    async function publicRawFromPrivateJwk(jwk) {
        const algorithm = jwk.key_ops && jwk.key_ops.includes("sign") ? ECDSA : ECDH;
        const publicJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true };
        const usages = algorithm === ECDSA ? ["verify"] : [];
        return exportRawPublicKey(await subtle.importKey("jwk", publicJwk, algorithm, true, usages));
    }

    async function deriveLayerKey(privateKey, peerPublicKey, ephemeralRaw, ballotId) {
        const shared = await subtle.deriveBits({ name: "ECDH", public: peerPublicKey }, privateKey, 256);
        const hkdfKey = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
        const hkdf = { name: "HKDF", hash: "SHA-256", salt: ephemeralRaw, info: concatBytes(utf8(KDF_INFO), utf8(ballotId)) };
        return subtle.deriveKey(hkdf, hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }

    async function encryptLayer(recipientPublicKey, ballotId, bytes) {
        const ephemeral = await generateEncryptionKeyPair();
        const ephemeralRaw = await exportRawPublicKey(ephemeral.publicKey);
        const key = await deriveLayerKey(ephemeral.privateKey, recipientPublicKey, ephemeralRaw, ballotId);
        const iv = randomBytes(IV_SIZE);
        const sealed = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: utf8(ballotId) }, key, bytes);
        return concatBytes(Uint8Array.of(VERSION), ephemeralRaw, iv, new Uint8Array(sealed));
    }

    async function decryptLayer(privateKey, ballotId, envelope) {
        if (envelope.length < LAYER_OVERHEAD || envelope[0] !== VERSION)
            throw new Error("malformed envelope");

        const ephemeralRaw = envelope.slice(1, 1 + PUBLIC_KEY_SIZE);
        const iv = envelope.slice(1 + PUBLIC_KEY_SIZE, 1 + PUBLIC_KEY_SIZE + IV_SIZE);
        const sealed = envelope.slice(1 + PUBLIC_KEY_SIZE + IV_SIZE);
        const ephemeralPublic = await importEncryptionPublicKey(ephemeralRaw);
        const key = await deriveLayerKey(privateKey, ephemeralPublic, ephemeralRaw, ballotId);
        return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv, additionalData: utf8(ballotId) }, key, sealed));
    }

    async function encryptBallot(publicKeysInOrder, ballotId, plaintext) {
        let data = plaintext;
        for (let i = publicKeysInOrder.length - 1; i >= 0; i--)
            data = await encryptLayer(publicKeysInOrder[i], ballotId, data);
        return data;
    }

    async function sortByHash(items) {
        const keyed = await Promise.all(items.map(async item => ({ item, hash: await sha256Hex(item) })));
        keyed.sort((a, b) => a.hash < b.hash ? -1 : (a.hash > b.hash ? 1 : 0));
        return keyed.map(entry => entry.item);
    }

    async function decryptLayerList(privateKey, ballotId, envelopes) {
        const outputs = [];
        let failed = 0;
        for (const envelope of envelopes) {
            try {
                outputs.push(await decryptLayer(privateKey, ballotId, envelope));
            } catch (error) {
                failed++;
            }
        }
        return { outputs: await sortByHash(outputs), failed };
    }

    function buildPlaintext(ballotId, definitionHash, choice) {
        const json = JSON.stringify({ v: 1, ballot: ballotId, def: definitionHash, choice, nonce: toHex(randomBytes(16)) });
        const bytes = utf8(json);
        if (bytes.length > PLAINTEXT_SIZE)
            throw new Error("plaintext too long");

        const padded = new Uint8Array(PLAINTEXT_SIZE).fill(0x20);
        padded.set(bytes);
        return padded;
    }

    function decodePlaintext(bytes) {
        return decoder.decode(bytes).trimEnd();
    }

    async function backupKey(password, salt, iterations) {
        const base = await subtle.importKey("raw", utf8(password), "PBKDF2", false, ["deriveKey"]);
        const pbkdf2 = { name: "PBKDF2", hash: "SHA-256", salt, iterations };
        return subtle.deriveKey(pbkdf2, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    }

    async function createBackup(password, content) {
        const salt = randomBytes(16);
        const iv = randomBytes(IV_SIZE);
        const key = await backupKey(password, salt, BACKUP_ITERATIONS);
        const sealed = await subtle.encrypt({ name: "AES-GCM", iv }, key, utf8(JSON.stringify(content)));
        return JSON.stringify({
            format: BACKUP_FORMAT,
            role: content.role,
            iterations: BACKUP_ITERATIONS,
            salt: toBase64(salt),
            iv: toBase64(iv),
            data: toBase64(new Uint8Array(sealed))
        });
    }

    async function openBackup(password, text) {
        const file = JSON.parse(text);
        if (file.format !== BACKUP_FORMAT)
            throw new Error("not a backup file");

        const key = await backupKey(password, fromBase64(file.salt), file.iterations);
        const plain = await subtle.decrypt({ name: "AES-GCM", iv: fromBase64(file.iv) }, key, fromBase64(file.data));
        return JSON.parse(decoder.decode(new Uint8Array(plain)));
    }

    function backupMatches(original, restored) {
        if (original.encryptionPrivateKey.d !== restored.encryptionPrivateKey.d)
            return false;
        return original.signingPrivateKey.d === restored.signingPrivateKey.d;
    }

    async function sign(privateKey, text) {
        return toBase64(new Uint8Array(await subtle.sign(SIGN_PARAMS, privateKey, utf8(text))));
    }

    async function verify(publicRaw, text, signatureBase64) {
        const key = await subtle.importKey("raw", publicRaw, ECDSA, true, ["verify"]);
        return subtle.verify(SIGN_PARAMS, key, fromBase64(signatureBase64), utf8(text));
    }

    const api = {
        VERSION, PLAINTEXT_SIZE, LAYER_OVERHEAD,
        ciphertextSize, concatBytes, utf8, toHex, toBase64, fromBase64, randomBytes,
        sha256Hex, fingerprint, combinedFingerprint,
        generateEncryptionKeyPair, generateSigningKeyPair, exportRawPublicKey, exportPrivateJwk,
        importEncryptionPublicKey, importEncryptionPrivateJwk, importSigningPrivateJwk, publicRawFromPrivateJwk,
        encryptLayer, decryptLayer, encryptBallot, decryptLayerList, sortByHash,
        buildPlaintext, decodePlaintext,
        createBackup, openBackup, backupMatches,
        sign, verify
    };

    if (typeof module !== "undefined" && module.exports)
        module.exports = api;
    else
        root.BallotCrypto = api;
})(globalThis);
```

Note: `publicRawFromPrivateJwk` distinguishes ECDH from ECDSA keys via `key_ops`; Web Crypto exports `key_ops: ["deriveBits"]` for ECDH and `["sign"]` for ECDSA private keys, so both work.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /media/SMB/SecretBallot && node --test tests-js/`
Expected: all tests PASS.

---

### Task 2: Tally script

**Files:**
- Create: `/media/SMB/SecretBallot/SecretBallot.Server/wwwroot/js/ballot-tally.js`
- Test: `/media/SMB/SecretBallot/tests-js/ballot-tally.test.js`

**Interfaces:**
- Consumes: definition object parsed from `definitionJson`: `{ id, title, type: "approval"|"single"|"yesno", options: string[], seats, noneOptionIndex }` (Task 3 writes it).
- Produces (global `BallotTally`): `validatePlaintext(text, definition, definitionHash) -> { valid: true, choice } | { valid: false, reason }`, `tally(definition, definitionHash, plaintextTexts[], ciphertextCount) -> TallyResult`, `buildResultDocument(input) -> string`.
- `TallyResult`: `{ ciphertextCount, validCount, invalidCount, emptyCount, counts: number[], invalidReasons: string[], withEmpty: Outcome, withoutEmpty: Outcome }`; `Outcome`: `{ base, elected: number[], tied: number[], seatsUnfilled }`.
- `buildResultDocument({ ballotId, title, definitionHash, bundleHash, combinedFingerprint, voterCount, tally })` returns a JSON string with a fixed key order (the signed document).

- [ ] **Step 1: Write the failing tests**

`tests-js/ballot-tally.test.js`:
```js
"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const BallotTally = require("../SecretBallot.Server/wwwroot/js/ballot-tally.js");

const approval = { id: "b1", title: "Beisitzer", type: "approval", options: ["Anna", "Bert", "Cem"], seats: 2, noneOptionIndex: -1 };
const single = { id: "b2", title: "Stichwahl", type: "single", options: ["Anna", "Bert", "keinen der Kandidierenden"], seats: 1, noneOptionIndex: 2 };
const yesNo = { id: "b3", title: "Frage", type: "yesno", options: ["Ja", "Nein"], seats: 1, noneOptionIndex: -1 };

function ballot(definition, choice, overrides) {
    return JSON.stringify(Object.assign({ v: 1, ballot: definition.id, def: "h", choice, nonce: "00" }, overrides || {}));
}

function run(definition, choices) {
    const texts = choices.map(c => ballot(definition, c));
    return BallotTally.tally(definition, "h", texts, texts.length);
}

test("two seats filled by absolute majority in order of approvals", () => {
    const result = run(approval, [[0, 1], [0, 1], [0], [1, 2]]);
    assert.deepEqual(result.counts, [3, 3, 1]);
    assert.deepEqual(result.withEmpty.elected, [0, 1]);
    assert.equal(result.withEmpty.seatsUnfilled, 0);
});

test("one seat filled, second unfilled", () => {
    const result = run(approval, [[0], [0], [0, 1], [2]]);
    assert.deepEqual(result.withEmpty.elected, [0]);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("tie at the cut-off is reported, not decided", () => {
    const result = run(approval, [[0, 1, 2], [0, 1, 2], [0, 1, 2], [0]]);
    assert.deepEqual(result.withEmpty.elected, [0]);
    assert.deepEqual(result.withEmpty.tied, [1, 2]);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("nobody reaches a majority", () => {
    const result = run(approval, [[0], [1], [2], []]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.equal(result.withEmpty.seatsUnfilled, 2);
});

test("all ballots empty elects nobody in both bases", () => {
    const result = run(approval, [[], [], []]);
    assert.equal(result.emptyCount, 3);
    assert.equal(result.withoutEmpty.base, 0);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.deepEqual(result.withoutEmpty.elected, []);
});

test("empty ballots change the majority base", () => {
    const result = run(approval, [[0], [0], [], []]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.deepEqual(result.withoutEmpty.elected, [0]);
});

test("single choice won by none-of-them elects nobody", () => {
    const result = run(single, [[2], [2], [0]]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("single choice winner with majority", () => {
    const result = run(single, [[1], [1], [0]]);
    assert.deepEqual(result.withEmpty.elected, [1]);
});

test("yes/no accepted when yes beats no", () => {
    const result = run(yesNo, [[0], [0], [1], []]);
    assert.deepEqual(result.withEmpty.elected, [0]);
});

test("invalid plaintexts are counted with reasons", () => {
    const texts = [
        ballot(approval, [0]),
        ballot(approval, [0], { ballot: "other" }),
        ballot(approval, [0], { def: "x" }),
        ballot(approval, [5]),
        ballot(approval, [0, 0]),
        "{kaputt",
        ballot(single, [0, 1])
    ];
    const result = BallotTally.tally(approval, "h", texts, texts.length + 1);
    assert.equal(result.validCount, 1);
    assert.equal(result.invalidCount, 7);
    assert.equal(result.invalidReasons.length, 6);
});

test("single choice with two marks is invalid", () => {
    const check = BallotTally.validatePlaintext(ballot(single, [0, 1]), single, "h");
    assert.equal(check.valid, false);
});

test("result document is deterministic", () => {
    const tallyResult = run(approval, [[0]]);
    const input = { ballotId: "b1", title: "Beisitzer", definitionHash: "h", bundleHash: "bh", combinedFingerprint: "fp", voterCount: 1, tally: tallyResult };
    assert.equal(BallotTally.buildResultDocument(input), BallotTally.buildResultDocument(input));
    assert.equal(JSON.parse(BallotTally.buildResultDocument(input)).ballot, "b1");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /media/SMB/SecretBallot && node --test tests-js/`
Expected: FAIL, `Cannot find module '../SecretBallot.Server/wwwroot/js/ballot-tally.js'`

- [ ] **Step 3: Implement `ballot-tally.js`**

```js
(function (root) {
    "use strict";

    function parse(text) {
        try {
            return JSON.parse(text);
        } catch (error) {
            return null;
        }
    }

    function hasValidIndices(choice, optionCount) {
        if (!Array.isArray(choice))
            return false;
        if (!choice.every(index => Number.isInteger(index) && index >= 0 && index < optionCount))
            return false;
        return new Set(choice).size === choice.length;
    }

    function validatePlaintext(text, definition, definitionHash) {
        const data = parse(text);
        if (data == null || typeof data !== "object")
            return { valid: false, reason: "kein gültiges JSON" };
        if (data.v !== 1)
            return { valid: false, reason: "unbekannte Version" };
        if (data.ballot !== definition.id)
            return { valid: false, reason: "falscher Wahlgang" };
        if (data.def !== definitionHash)
            return { valid: false, reason: "falsche Wahlgang-Definition" };
        if (!hasValidIndices(data.choice, definition.options.length))
            return { valid: false, reason: "ungültige Auswahl" };
        if (definition.type !== "approval" && data.choice.length > 1)
            return { valid: false, reason: "mehr als eine Auswahl" };
        return { valid: true, choice: data.choice };
    }

    function approvalOutcome(counts, seats, base) {
        const majority = counts
            .map((count, index) => ({ index, count }))
            .filter(entry => entry.count * 2 > base)
            .sort((a, b) => b.count - a.count || a.index - b.index);

        if (majority.length <= seats)
            return { base, elected: majority.map(e => e.index), tied: [], seatsUnfilled: seats - majority.length };

        const cutoff = majority[seats - 1].count;
        if (majority[seats].count < cutoff)
            return { base, elected: majority.slice(0, seats).map(e => e.index), tied: [], seatsUnfilled: 0 };

        const above = majority.filter(e => e.count > cutoff).map(e => e.index);
        const tied = majority.filter(e => e.count === cutoff).map(e => e.index);
        return { base, elected: above, tied, seatsUnfilled: seats - above.length };
    }

    function singleOutcome(counts, noneOptionIndex, base) {
        const winner = counts.findIndex(count => count * 2 > base);
        if (winner < 0 || winner === noneOptionIndex)
            return { base, elected: [], tied: [], seatsUnfilled: 1 };
        return { base, elected: [winner], tied: [], seatsUnfilled: 0 };
    }

    function yesNoOutcome(counts, base) {
        if (counts[0] > counts[1])
            return { base, elected: [0], tied: [], seatsUnfilled: 0 };
        return { base, elected: [], tied: [], seatsUnfilled: 1 };
    }

    function outcome(definition, counts, base) {
        if (definition.type === "approval")
            return approvalOutcome(counts, definition.seats, base);
        if (definition.type === "single")
            return singleOutcome(counts, definition.noneOptionIndex, base);
        return yesNoOutcome(counts, base);
    }

    function tally(definition, definitionHash, plaintextTexts, ciphertextCount) {
        const counts = definition.options.map(() => 0);
        const invalidReasons = [];
        let validCount = 0;
        let emptyCount = 0;

        for (const text of plaintextTexts) {
            const check = validatePlaintext(text, definition, definitionHash);
            if (!check.valid) {
                invalidReasons.push(check.reason);
                continue;
            }

            validCount++;
            if (check.choice.length === 0)
                emptyCount++;
            for (const index of check.choice)
                counts[index]++;
        }

        return {
            ciphertextCount,
            validCount,
            invalidCount: ciphertextCount - validCount,
            emptyCount,
            counts,
            invalidReasons,
            withEmpty: outcome(definition, counts, validCount),
            withoutEmpty: outcome(definition, counts, validCount - emptyCount)
        };
    }

    function outcomeDocument(value) {
        return { base: value.base, elected: value.elected, tied: value.tied, seatsUnfilled: value.seatsUnfilled };
    }

    function buildResultDocument(input) {
        const t = input.tally;
        return JSON.stringify({
            v: 1,
            ballot: input.ballotId,
            title: input.title,
            definitionHash: input.definitionHash,
            bundleHash: input.bundleHash,
            combinedFingerprint: input.combinedFingerprint,
            voterCount: input.voterCount,
            ciphertextCount: t.ciphertextCount,
            validCount: t.validCount,
            invalidCount: t.invalidCount,
            emptyCount: t.emptyCount,
            counts: t.counts,
            withEmpty: outcomeDocument(t.withEmpty),
            withoutEmpty: outcomeDocument(t.withoutEmpty)
        });
    }

    const api = { validatePlaintext, tally, buildResultDocument };

    if (typeof module !== "undefined" && module.exports)
        module.exports = api;
    else
        root.BallotTally = api;
})(globalThis);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /media/SMB/SecretBallot && node --test tests-js/`
Expected: all tests PASS.

---

### Task 3: Server election state

**Files:**
- Create: `SecretBallot.Server/Election/BallotType.cs`, `BallotStatus.cs`, `CastOutcome.cs`, `RuleResult.cs`, `KeyHolder.cs`, `Ballot.cs`, `ElectionViews.cs` (pure data records), `CryptoFormats.cs`, `BallotDefinitionWriter.cs`, `BundleWriter.cs`, `ElectionState.cs`
- Create: `SecretBallot.Server/Program.cs` (temporary minimal `var app = WebApplication.CreateBuilder(args).Build(); app.Run(); public partial class Program { }` so the project compiles; Task 4 replaces it)
- Create: `SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`
- Test: `SecretBallot.Server.Tests/Election/ElectionStateTests.cs`, `SecretBallot.Server.Tests/Election/TestKeys.cs`

**Interfaces:**
- Produces (namespace `SecretBallot.Server.Election`):
  - `enum BallotType { Approval, Single, YesNo }`, `enum BallotStatus { Draft, Open, Closed, Finished }`, `enum CastOutcome { Accepted, NotOpen, AlreadyVoted, Malformed }`
  - `record RuleResult(bool Ok, string? Error)` with `Success`, `Fail(string)`
  - `record KeyHolderAssignment(string Role, string Subject, string Username, bool Leads)`
  - `record KeyHolderView(int Position, string Role, string Username, bool Leads, string? EncryptionKey, string? SigningKey, string? EncryptionFingerprint, string? SigningFingerprint, bool Confirmed)` (keys base64)
  - `record BallotDraft(string Title, BallotType Type, IReadOnlyList<string> Options, int Seats)`
  - `record PublicKeyEntry(int Position, string Role, string EncryptionKey, string SigningKey)`
  - `record OpenBallotView(Guid Id, string Title, string DefinitionJson, IReadOnlyList<PublicKeyEntry> KeyHolders, string CombinedFingerprint)`
  - `record BallotSummary(Guid Id, string Title, BallotStatus Status, int VoteCount, int KeyHolderCount, int LayerCount, bool HasResult, int SignatureCount, string? CombinedFingerprint, int MyPosition, bool ILead, bool ISigned)`
  - `record BulletinView(Guid Id, string Title, int VoterCount, int CiphertextCount, IReadOnlyList<string> Receipts)`
  - `record ClosedBallotView(Guid Id, string Title, string DefinitionJson, string BundleJson, string CombinedFingerprint, int VoterCount, IReadOnlyList<PublicKeyEntry> KeyHolders, string? ResultDocument, IReadOnlyList<string?> Signatures)`
  - `record PublicationView(Guid Id, string Title, string DefinitionJson, string BundleJson, string CombinedFingerprint, int VoterCount, IReadOnlyList<PublicKeyEntry> KeyHolders, IReadOnlyList<IReadOnlyList<string>> Layers, string ResultDocument, IReadOnlyList<string> Signatures)`
  - `ElectionState` methods: `GetKeyHolders()`, `FindKeyHolder(string subject)`, `ReplaceKeyHolders(IReadOnlyList<KeyHolderAssignment>)`, `RegisterKeys(string subject, byte[] encryptionKey, byte[] signingKey)`, `ConfirmKeys(string subject, string encryptionFingerprint, string signingFingerprint)`, `CreateBallot(BallotDraft draft, out Guid id)`, `GetBallots(string? subject)`, `GetCurrent()`, `HasVoted(Guid id, string subject)`, `Open(Guid id, string subject)`, `Close(Guid id, string subject, bool isAdmin)`, `Cast(Guid id, string subject, byte[] ciphertext)`, `GetBulletin(Guid id)`, `GetClosed(Guid id, string subject)`, `GetLayer(Guid id, int index, string subject)`, `PutLayer(Guid id, int index, string subject, List<byte[]> items)`, `PutResult(Guid id, string subject, string document)`, `PutSignature(Guid id, string subject, byte[] signature)`, `GetPublication(Guid id)`.
  - `CryptoFormats`: `Version`, `PlaintextSize`, `LayerOverhead`, `CiphertextSize(int)`, `Sha256Hex(byte[])`, `Fingerprint(byte[])`, `CombinedFingerprint(Guid, IEnumerable<byte[]>)`, `SortByHash(IEnumerable<byte[]>)`, `IsValidP256PublicKey(byte[])`, `VerifySignature(byte[] publicKey, string document, byte[] signature)`.

- [ ] **Step 1: Test project**

`SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`:
```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="TUnit" Version="1.72.16" />
  </ItemGroup>
  <ItemGroup>
    <ProjectReference Include="..\SecretBallot.Server\SecretBallot.Server.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Write the failing tests**

`SecretBallot.Server.Tests/Election/TestKeys.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;

namespace SecretBallot.Server.Tests.Election;

public sealed class TestKeys {
    public ECDsa Signing { get; } = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public byte[] EncryptionPublic { get; }
    public byte[] SigningPublic { get; }

    public TestKeys() {
        using var encryption = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        EncryptionPublic = Raw(encryption.ExportParameters(false).Q);
        SigningPublic = Raw(Signing.ExportParameters(false).Q);
    }

    public byte[] Sign(string document) {
        return Signing.SignData(Encoding.UTF8.GetBytes(document), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static byte[] Raw(ECPoint point) {
        var raw = new byte[65];
        raw[0] = 4;
        point.X!.CopyTo(raw, 1);
        point.Y!.CopyTo(raw, 33);
        return raw;
    }
}
```

`SecretBallot.Server.Tests/Election/ElectionStateTests.cs`:
```csharp
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
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cd /media/SMB/SecretBallot && dotnet build -m:1 SecretBallot.slnx`
Expected: FAIL, compile errors (`ElectionState` not found).

- [ ] **Step 4: Implement**

`Election/BallotType.cs`, `Election/BallotStatus.cs`, `Election/CastOutcome.cs`: the enums from the interface block, `namespace SecretBallot.Server.Election;`.

`Election/RuleResult.cs`:
```csharp
namespace SecretBallot.Server.Election;

public sealed record RuleResult(bool Ok, string? Error) {
    public static RuleResult Success { get; } = new(true, null);

    public static RuleResult Fail(string error) => new(false, error);
}
```

`Election/KeyHolder.cs`:
```csharp
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
```

`Election/Ballot.cs`:
```csharp
namespace SecretBallot.Server.Election;

public sealed class Ballot {
    public required Guid Id { get; init; }
    public required string Title { get; init; }
    public required string DefinitionJson { get; init; }
    public BallotStatus Status { get; set; } = BallotStatus.Draft;
    public List<KeyHolderSnapshot> KeyHolders { get; set; } = new();
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
```

`Election/ElectionViews.cs`: all records from the interface block (pure data, one file).

`Election/CryptoFormats.cs`:
```csharp
using System.Security.Cryptography;
using System.Text;

namespace SecretBallot.Server.Election;

public static class CryptoFormats {
    public const byte Version = 1;
    public const int PlaintextSize = 512;
    public const int LayerOverhead = 94;
    private const string KeysDomain = "pp-ballot-keys-v1";

    public static int CiphertextSize(int layerCount) => PlaintextSize + layerCount * LayerOverhead;

    public static string Sha256Hex(byte[] data) => Convert.ToHexStringLower(SHA256.HashData(data));

    public static string Fingerprint(byte[] data) => Format(SHA256.HashData(data));

    public static string CombinedFingerprint(Guid ballotId, IEnumerable<byte[]> keys) {
        var buffer = new List<byte>();
        buffer.AddRange(Encoding.UTF8.GetBytes(KeysDomain));
        buffer.AddRange(Encoding.UTF8.GetBytes(ballotId.ToString()));
        foreach (var key in keys)
            buffer.AddRange(key);
        return Format(SHA256.HashData(buffer.ToArray()));
    }

    public static List<byte[]> SortByHash(IEnumerable<byte[]> items) {
        return items
            .Select(item => (Item: item, Hash: Sha256Hex(item)))
            .OrderBy(entry => entry.Hash, StringComparer.Ordinal)
            .Select(entry => entry.Item)
            .ToList();
    }

    /// <summary>True when <paramref name="raw"/> is an uncompressed P-256 point on the curve.</summary>
    public static bool IsValidP256PublicKey(byte[] raw) {
        if (raw.Length != 65 || raw[0] != 4)
            return false;

        try {
            using var key = ECDsa.Create(ToParameters(raw));
            return true;
        } catch (CryptographicException) {
            return false;
        }
    }

    public static bool VerifySignature(byte[] publicKey, string document, byte[] signature) {
        using var key = ECDsa.Create(ToParameters(publicKey));
        return key.VerifyData(Encoding.UTF8.GetBytes(document), signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    private static ECParameters ToParameters(byte[] raw) {
        return new ECParameters {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint { X = raw[1..33], Y = raw[33..65] }
        };
    }

    private static string Format(byte[] digest) {
        var hex = Convert.ToHexStringLower(digest, 0, 16);
        return string.Join(' ', Enumerable.Range(0, 8).Select(i => hex.Substring(i * 4, 4)));
    }
}
```
Note on the catch: an off-curve point is untrusted input, not a bug, and `ECDsa.Create` has no Try variant; this is the adapter-layer translation the style guide allows. The endpoint logs a rejected key registration (Task 4).

`Election/BallotDefinitionWriter.cs`:
```csharp
using System.Text;
using System.Text.Json;

namespace SecretBallot.Server.Election;

public static class BallotDefinitionWriter {
    public const string NoneOfThemOption = "keinen der Kandidierenden";

    public static string Write(Guid id, BallotDraft draft) {
        var options = OptionsFor(draft);
        var noneIndex = draft.Type == BallotType.Single ? options.Count - 1 : -1;

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) {
            writer.WriteStartObject();
            writer.WriteString("id", id.ToString());
            writer.WriteString("title", draft.Title.Trim());
            writer.WriteString("type", TypeName(draft.Type));
            writer.WriteStartArray("options");
            foreach (var option in options)
                writer.WriteStringValue(option);
            writer.WriteEndArray();
            writer.WriteNumber("seats", draft.Type == BallotType.Approval ? draft.Seats : 1);
            writer.WriteNumber("noneOptionIndex", noneIndex);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static List<string> OptionsFor(BallotDraft draft) {
        if (draft.Type == BallotType.YesNo)
            return new List<string> { "Ja", "Nein" };

        var options = draft.Options.Select(o => o.Trim()).ToList();
        if (draft.Type == BallotType.Single)
            options.Add(NoneOfThemOption);
        return options;
    }

    private static string TypeName(BallotType type) {
        return type switch {
            BallotType.Approval => "approval",
            BallotType.Single => "single",
            _ => "yesno"
        };
    }
}
```

`Election/BundleWriter.cs`:
```csharp
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
```

`Election/ElectionState.cs`:
```csharp
namespace SecretBallot.Server.Election;

/// <summary>All election state. Who voted (<see cref="Ballot.Voted"/>) and what was cast (<see cref="Ballot.Ciphertexts"/>) are kept in separate collections that are never joined.</summary>
public sealed class ElectionState {
    private const int MaxOptions = 50;
    private const int MaxTextLength = 200;
    private const int MaxResultLength = 65536;

    private readonly Lock _lock = new();
    private readonly List<KeyHolder> _keyHolders = new();
    private readonly Dictionary<Guid, Ballot> _ballots = new();

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

            holder.EncryptionKey = encryptionKey;
            holder.SigningKey = signingKey;
            holder.Confirmed = false;
            return RuleResult.Success;
        }
    }

    public RuleResult ConfirmKeys(string subject, string encryptionFingerprint, string signingFingerprint) {
        lock (_lock) {
            var holder = _keyHolders.Find(k => k.Subject == subject);
            if (holder == null || holder.EncryptionKey == null || holder.SigningKey == null)
                return RuleResult.Fail("Es sind noch keine Schlüssel registriert.");
            if (CryptoFormats.Fingerprint(holder.EncryptionKey) != encryptionFingerprint || CryptoFormats.Fingerprint(holder.SigningKey) != signingFingerprint)
                return RuleResult.Fail("Die Fingerabdrücke stimmen nicht überein. Bitte sofort die Wahlleitung und die Verwaltung informieren.");

            holder.Confirmed = true;
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

            ballot.Ciphertexts.Add(ciphertext);
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
            if (index < 1 || index > holderCount || ballot.Layers.Count != index)
                return RuleResult.Fail("Diese Schicht ist nicht an der Reihe oder wurde bereits hochgeladen.");
            if (ballot.KeyHolders[index - 1].Subject != subject)
                return RuleResult.Fail("Diese Schicht gehört einer anderen Person.");
            if (items.Count > ballot.Layers[index - 1].Count)
                return RuleResult.Fail("Die Schicht enthält mehr Einträge als die vorherige.");
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
            if (!_ballots.TryGetValue(id, out var ballot) || ballot.ResultDocument == null || ballot.Status != BallotStatus.Closed)
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
        if (draft.Type == BallotType.Approval && (draft.Seats < 1 || draft.Seats > options.Count))
            return "Die Zahl der Sitze muss zwischen 1 und der Zahl der Optionen liegen.";
        return null;
    }
}
```

`ToView` is used as a method group with `Select` (index overload), so its signature `(KeyHolder, int)` must stay in that order.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /media/SMB/SecretBallot && dotnet build -m:1 SecretBallot.slnx && dotnet run --no-build --project SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`
Expected: all tests PASS.

---

### Task 4: Hosting, login, Keycloak eligibility, endpoints

**Files:**
- Create: `SecretBallot.Server/SecretBallotSettings.cs`
- Create: `SecretBallot.Server/Auth/AuthSetup.cs`, `SecretBallot.Server/Auth/ClaimsPrincipalExtensions.cs`
- Create: `SecretBallot.Server/Keycloak/Eligibility.cs`, `IKeycloakDirectory.cs`, `KeycloakDirectory.cs`, `KeycloakTokenProvider.cs`
- Create: `SecretBallot.Server/Endpoints/ApiDtos.cs`, `ApiResults.cs`, `PublicEndpoints.cs`, `VoterEndpoints.cs`, `KeyHolderEndpoints.cs`, `AdminEndpoints.cs`
- Create: `SecretBallot.Server/SecurityHeaders.cs`
- Create: `SecretBallot.Server/appsettings.json`, `appsettings.Development.json`
- Modify: `SecretBallot.Server/Program.cs` (replace)
- Test: `SecretBallot.Server.Tests/Keycloak/KeycloakDirectoryTests.cs`

**Interfaces:**
- Consumes: `ElectionState` and views from Task 3.
- Produces HTTP API (all JSON, errors `{ "error": "<German message>" }`):
  - `GET /login?returnUrl=/...`, `GET /logout`
  - `GET /api/me` -> `{ loggedIn, name, username, isAdmin, eligible: true|false|null, keyHolder: KeyHolderView|null }`
  - `GET /api/ballots` -> `BallotSummary[]` (with `myPosition`/`iLead`/`iSigned` for the caller)
  - `GET /api/ballots/current` -> `{ ballot: OpenBallotView|null, hasVoted }`
  - `POST /api/ballots/{id}/votes` body `{ ciphertext }` -> 204 | 401 | 403 | 409 | 503
  - `GET /api/ballots/{id}/bulletin` -> `BulletinView` | 404
  - `GET /api/ballots/{id}/publication` -> `PublicationView` | 404
  - `GET /api/keyholder/ballots/{id}` -> `ClosedBallotView` | 404
  - `GET /api/keyholder/ballots/{id}/layers/{index}` -> `{ items: string[] }`
  - `PUT /api/keyholder/ballots/{id}/layers/{index}` body `{ items: string[] }`
  - `PUT /api/keyholder/ballots/{id}/result` body `{ document }`
  - `PUT /api/keyholder/ballots/{id}/signature` body `{ signature }`
  - `PUT /api/keyholder/keys` body `{ encryptionKey, signingKey }`, `POST /api/keyholder/confirm` body `{ encryptionFingerprint, signingFingerprint }`
  - `POST /api/keyholder/ballots/{id}/open`, `POST /api/keyholder/ballots/{id}/close` (admin may also call close)
  - `GET /api/admin/keyholders` -> `KeyHolderView[]`, `PUT /api/admin/keyholders` body `[{ role, username, leads }]`, `POST /api/admin/ballots` body `{ title, type: "approval"|"single"|"yesno", options: string[], seats }`

- [ ] **Step 1: Write the failing Keycloak tests**

`SecretBallot.Server.Tests/Keycloak/KeycloakDirectoryTests.cs`:
```csharp
using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using SecretBallot.Server;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Tests.Keycloak;

public class KeycloakDirectoryTests {
    private static readonly SecretBallotSettings Settings = new() {
        KeycloakBaseUrl = "https://sso.example",
        Realm = "Piraten",
        ClientId = "ballot",
        ClientSecret = "secret"
    };

    private static KeycloakDirectory Create(Func<HttpRequestMessage, HttpResponseMessage> userResponse) {
        var http = new HttpClient(new StubHandler(userResponse));
        return new KeycloakDirectory(http, Settings, new KeycloakTokenProvider(), NullLogger<KeycloakDirectory>.Instance);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string json) {
        return new HttpResponseMessage(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
    }

    [Test]
    public async Task Eligible_when_attribute_true() {
        var directory = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true,\"attributes\":{\"ekklesia_eligible\":[\"true\"]}}"));
        await Assert.That(await directory.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Eligible);
    }

    [Test]
    public async Task Not_eligible_when_attribute_false_missing_or_disabled() {
        var falseAttr = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true,\"attributes\":{\"ekklesia_eligible\":[\"false\"]}}"));
        var missing = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":true}"));
        var disabled = Create(_ => Json(HttpStatusCode.OK, "{\"enabled\":false,\"attributes\":{\"ekklesia_eligible\":[\"true\"]}}"));
        await Assert.That(await falseAttr.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
        await Assert.That(await missing.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
        await Assert.That(await disabled.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
    }

    [Test]
    public async Task Unknown_when_keycloak_fails() {
        var serverError = Create(_ => Json(HttpStatusCode.InternalServerError, "{}"));
        var unreachable = Create(_ => throw new HttpRequestException("down"));
        await Assert.That(await serverError.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Unknown);
        await Assert.That(await unreachable.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.Unknown);
    }

    [Test]
    public async Task Not_eligible_when_user_unknown() {
        var directory = Create(_ => Json(HttpStatusCode.NotFound, "{}"));
        await Assert.That(await directory.GetEligibilityAsync("sub", CancellationToken.None)).IsEqualTo(Eligibility.NotEligible);
    }

    private sealed class StubHandler : HttpMessageHandler {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _userResponse;

        public StubHandler(Func<HttpRequestMessage, HttpResponseMessage> userResponse) {
            _userResponse = userResponse;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) {
            if (request.RequestUri!.AbsolutePath.EndsWith("/token"))
                return Task.FromResult(Json(HttpStatusCode.OK, "{\"access_token\":\"t\",\"expires_in\":60}"));
            return Task.FromResult(_userResponse(request));
        }
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /media/SMB/SecretBallot && dotnet build -m:1 SecretBallot.slnx`
Expected: FAIL, `KeycloakDirectory` not found.

- [ ] **Step 3: Implement settings and Keycloak**

`SecretBallotSettings.cs`:
```csharp
namespace SecretBallot.Server;

public sealed class SecretBallotSettings {
    public string Authority { get; init; } = "";
    public string ClientId { get; init; } = "";
    public string ClientSecret { get; init; } = "";
    public string KeycloakBaseUrl { get; init; } = "";
    public string Realm { get; init; } = "";
    public string EligibilityAttribute { get; init; } = "ekklesia_eligible";
    public string[] AdminUsernames { get; init; } = Array.Empty<string>();

    public bool IsAdmin(string? username) {
        if (string.IsNullOrEmpty(username))
            return false;
        return AdminUsernames.Contains(username, StringComparer.OrdinalIgnoreCase);
    }
}
```

`Keycloak/Eligibility.cs`: `public enum Eligibility { Eligible, NotEligible, Unknown }`.

`Keycloak/IKeycloakDirectory.cs`:
```csharp
namespace SecretBallot.Server.Keycloak;

public interface IKeycloakDirectory {
    Task<Eligibility> GetEligibilityAsync(string subject, CancellationToken ct);
    Task<DirectoryUser?> FindByUsernameAsync(string username, CancellationToken ct);
}

public sealed record DirectoryUser(string Id, string Username);
```

`Keycloak/KeycloakTokenProvider.cs`:
```csharp
using System.Text.Json;

namespace SecretBallot.Server.Keycloak;

/// <summary>Caches one client-credentials token until shortly before it expires.</summary>
public sealed class KeycloakTokenProvider {
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(10);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private string? token;
    private DateTimeOffset expiresAt;

    public async Task<string> GetTokenAsync(HttpClient http, SecretBallotSettings settings, CancellationToken ct) {
        await _gate.WaitAsync(ct);
        try {
            if (token != null && DateTimeOffset.UtcNow + RefreshMargin < expiresAt)
                return token;

            var url = $"{settings.KeycloakBaseUrl.TrimEnd('/')}/realms/{Uri.EscapeDataString(settings.Realm)}/protocol/openid-connect/token";
            using var form = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "client_credentials",
                ["client_id"] = settings.ClientId,
                ["client_secret"] = settings.ClientSecret
            });
            using var response = await http.PostAsync(url, form, ct);
            response.EnsureSuccessStatusCode();
            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            token = doc.RootElement.GetProperty("access_token").GetString()!;
            expiresAt = DateTimeOffset.UtcNow + TimeSpan.FromSeconds(doc.RootElement.GetProperty("expires_in").GetInt32());
            return token;
        } finally {
            _gate.Release();
        }
    }
}
```

`Keycloak/KeycloakDirectory.cs`:
```csharp
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace SecretBallot.Server.Keycloak;

public sealed class KeycloakDirectory : IKeycloakDirectory {
    private readonly HttpClient _http;
    private readonly SecretBallotSettings _settings;
    private readonly KeycloakTokenProvider _tokens;
    private readonly ILogger<KeycloakDirectory> _logger;

    private string AdminBase => $"{_settings.KeycloakBaseUrl.TrimEnd('/')}/admin/realms/{Uri.EscapeDataString(_settings.Realm)}";

    public KeycloakDirectory(HttpClient http, SecretBallotSettings settings, KeycloakTokenProvider tokens, ILogger<KeycloakDirectory> logger) {
        _http = http;
        _settings = settings;
        _tokens = tokens;
        _logger = logger;
    }

    public async Task<Eligibility> GetEligibilityAsync(string subject, CancellationToken ct) {
        try {
            using var response = await GetAsync($"{AdminBase}/users/{Uri.EscapeDataString(subject)}", ct);
            if (response.StatusCode == HttpStatusCode.NotFound)
                return Eligibility.NotEligible;
            if (!response.IsSuccessStatusCode) {
                _logger.LogWarning("Eligibility lookup returned HTTP {Status}", (int)response.StatusCode);
                return Eligibility.Unknown;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
            return ReadEligibility(doc.RootElement);
        } catch (Exception ex) when (ex is HttpRequestException || ex is JsonException || ex is TaskCanceledException || ex is KeyNotFoundException || ex is InvalidOperationException) {
            _logger.LogWarning("Eligibility lookup failed: {Exception}", ex);
            return Eligibility.Unknown;
        }
    }

    public async Task<DirectoryUser?> FindByUsernameAsync(string username, CancellationToken ct) {
        using var response = await GetAsync($"{AdminBase}/users?username={Uri.EscapeDataString(username)}&exact=true", ct);
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        foreach (var user in doc.RootElement.EnumerateArray()) {
            var name = user.GetProperty("username").GetString() ?? "";
            if (string.Equals(name, username, StringComparison.OrdinalIgnoreCase))
                return new DirectoryUser(user.GetProperty("id").GetString()!, name);
        }
        return null;
    }

    private async Task<HttpResponseMessage> GetAsync(string url, CancellationToken ct) {
        var token = await _tokens.GetTokenAsync(_http, _settings, ct);
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _http.SendAsync(request, ct);
    }

    private Eligibility ReadEligibility(JsonElement user) {
        if (user.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.False)
            return Eligibility.NotEligible;
        if (!user.TryGetProperty("attributes", out var attributes))
            return Eligibility.NotEligible;
        if (!attributes.TryGetProperty(_settings.EligibilityAttribute, out var values) || values.GetArrayLength() == 0)
            return Eligibility.NotEligible;
        return string.Equals(values[0].GetString(), "true", StringComparison.OrdinalIgnoreCase) ? Eligibility.Eligible : Eligibility.NotEligible;
    }
}
```

- [ ] **Step 4: Implement auth, endpoints, Program**

`Auth/ClaimsPrincipalExtensions.cs`:
```csharp
using System.Security.Claims;

namespace SecretBallot.Server.Auth;

public static class ClaimsPrincipalExtensions {
    extension(ClaimsPrincipal user) {
        public string Subject => user.FindFirstValue("sub") ?? throw new InvalidOperationException("Authenticated user without sub claim");
        public string? Username => user.FindFirstValue("preferred_username");
        public string DisplayName => user.FindFirstValue("name") ?? user.FindFirstValue("preferred_username") ?? "";
        public bool IsLoggedIn => user.Identity?.IsAuthenticated == true;
    }
}
```

`Auth/AuthSetup.cs`:
```csharp
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace SecretBallot.Server.Auth;

public static class AuthSetup {
    public const string OidcScheme = "oidc";

    public static void AddBallotAuthentication(this IServiceCollection services, SecretBallotSettings settings) {
        services
            .AddAuthentication(options => {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
            .AddCookie(options => {
                options.Cookie.Name = "sb_session";
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.ExpireTimeSpan = TimeSpan.FromHours(14);
                options.Events.OnRedirectToLogin = context => {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                };
                options.Events.OnRedirectToAccessDenied = context => {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                };
            })
            .AddOpenIdConnect(OidcScheme, options => {
                options.Authority = settings.Authority;
                options.ClientId = settings.ClientId;
                options.ClientSecret = settings.ClientSecret;
                options.ResponseType = "code";
                options.UsePkce = true;
                options.MapInboundClaims = false;
                options.SaveTokens = false;
                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("profile");
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.TokenValidationParameters.NameClaimType = "preferred_username";
            });
        services.AddAuthorization();
    }

    public static void MapAuthEndpoints(this WebApplication app) {
        app.MapGet("/login", (string? returnUrl) => {
            var target = IsLocalUrl(returnUrl) ? returnUrl! : "/";
            return Results.Challenge(new AuthenticationProperties { RedirectUri = target }, new[] { OidcScheme });
        });
        app.MapGet("/logout", async (HttpContext context) => {
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.Redirect("/");
        });
    }

    private static bool IsLocalUrl(string? url) {
        if (string.IsNullOrEmpty(url) || url[0] != '/')
            return false;
        return url.Length == 1 || (url[1] != '/' && url[1] != '\\');
    }
}
```

`Endpoints/ApiDtos.cs` (pure data):
```csharp
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
```

`Endpoints/ApiResults.cs`:
```csharp
using SecretBallot.Server.Election;

namespace SecretBallot.Server.Endpoints;

public static class ApiResults {
    public static IResult Error(string message, int status) => Results.Json(new ErrorResponse(message), statusCode: status);

    public static IResult From(RuleResult result) => result.Ok ? Results.NoContent() : Error(result.Error!, StatusCodes.Status409Conflict);

    public static byte[]? DecodeBase64(string? text) {
        if (string.IsNullOrEmpty(text))
            return null;
        var buffer = new byte[text.Length];
        return Convert.TryFromBase64String(text, buffer, out var written) ? buffer[..written] : null;
    }
}
```

`Endpoints/PublicEndpoints.cs`:
```csharp
using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class PublicEndpoints {
    public static void MapPublicEndpoints(this WebApplication app) {
        app.MapGet("/api/me", async (ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings, IKeycloakDirectory directory, CancellationToken ct) => {
            if (!user.IsLoggedIn)
                return Results.Json(new MeResponse(false, "", null, false, null, null));

            var eligibility = await directory.GetEligibilityAsync(user.Subject, ct);
            bool? eligible = eligibility == Eligibility.Unknown ? null : eligibility == Eligibility.Eligible;
            return Results.Json(new MeResponse(true, user.DisplayName, user.Username, settings.IsAdmin(user.Username), eligible, state.FindKeyHolder(user.Subject)));
        });

        app.MapGet("/api/ballots", (ClaimsPrincipal user, ElectionState state) =>
            Results.Json(state.GetBallots(user.IsLoggedIn ? user.Subject : null)));

        app.MapGet("/api/ballots/current", (ClaimsPrincipal user, ElectionState state) => {
            var current = state.GetCurrent();
            var hasVoted = current != null && user.IsLoggedIn && state.HasVoted(current.Id, user.Subject);
            return Results.Json(new CurrentBallotResponse(current, hasVoted));
        });

        app.MapGet("/api/ballots/{id:guid}/bulletin", (Guid id, ElectionState state) => {
            var bulletin = state.GetBulletin(id);
            return bulletin == null ? ApiResults.Error("Für diesen Wahlgang gibt es noch keine öffentliche Liste.", 404) : Results.Json(bulletin);
        });

        app.MapGet("/api/ballots/{id:guid}/publication", (Guid id, ElectionState state) => {
            var publication = state.GetPublication(id);
            return publication == null ? ApiResults.Error("Dieser Wahlgang ist noch nicht abgeschlossen.", 404) : Results.Json(publication);
        });
    }
}
```

`Endpoints/VoterEndpoints.cs`:
```csharp
using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class VoterEndpoints {
    public static void MapVoterEndpoints(this WebApplication app) {
        app.MapPost("/api/ballots/{id:guid}/votes", async (Guid id, VoteRequest request, ClaimsPrincipal user, ElectionState state, IKeycloakDirectory directory, CancellationToken ct) => {
            var eligibility = await directory.GetEligibilityAsync(user.Subject, ct);
            if (eligibility == Eligibility.Unknown)
                return ApiResults.Error("Die Stimmberechtigung konnte gerade nicht geprüft werden. Bitte versuche es gleich noch einmal.", 503);
            if (eligibility == Eligibility.NotEligible)
                return ApiResults.Error("Laut Piratenlogin bist du nicht stimmberechtigt (Beiträge gezahlt). Bei Fragen hilft piratenlogin@piratenpartei.de.", 403);

            var ciphertext = ApiResults.DecodeBase64(request.Ciphertext);
            if (ciphertext == null)
                return ApiResults.Error("Der Stimmzettel ist beschädigt.", 400);

            return state.Cast(id, user.Subject, ciphertext) switch {
                CastOutcome.Accepted => Results.NoContent(),
                CastOutcome.AlreadyVoted => ApiResults.Error("Du hast in diesem Wahlgang bereits abgestimmt.", 409),
                CastOutcome.Malformed => ApiResults.Error("Der Stimmzettel ist beschädigt.", 400),
                _ => ApiResults.Error("Dieser Wahlgang ist nicht geöffnet.", 409)
            };
        }).RequireAuthorization();
    }
}
```

`Endpoints/KeyHolderEndpoints.cs`:
```csharp
using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;

namespace SecretBallot.Server.Endpoints;

public static class KeyHolderEndpoints {
    public static void MapKeyHolderEndpoints(this WebApplication app) {
        var group = app.MapGroup("/api/keyholder").RequireAuthorization();

        group.MapPut("/keys", (RegisterKeysRequest request, ClaimsPrincipal user, ElectionState state, ILogger<ElectionState> logger) => {
            var encryption = ApiResults.DecodeBase64(request.EncryptionKey);
            var signing = ApiResults.DecodeBase64(request.SigningKey);
            if (encryption == null || signing == null)
                return ApiResults.Error("Die Schlüssel haben kein gültiges Format.", 400);

            var result = state.RegisterKeys(user.Subject, encryption, signing);
            if (!result.Ok)
                logger.LogWarning("Key registration rejected: {Reason}", result.Error);
            return ApiResults.From(result);
        });

        group.MapPost("/confirm", (ConfirmKeysRequest request, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.ConfirmKeys(user.Subject, request.EncryptionFingerprint, request.SigningFingerprint)));

        group.MapPost("/ballots/{id:guid}/open", (Guid id, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.Open(id, user.Subject)));

        group.MapPost("/ballots/{id:guid}/close", (Guid id, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) =>
            ApiResults.From(state.Close(id, user.Subject, settings.IsAdmin(user.Username))));

        group.MapGet("/ballots/{id:guid}", (Guid id, ClaimsPrincipal user, ElectionState state) => {
            var closed = state.GetClosed(id, user.Subject);
            return closed == null ? ApiResults.Error("Kein geschlossener Wahlgang mit deiner Beteiligung.", 404) : Results.Json(closed);
        });

        group.MapGet("/ballots/{id:guid}/layers/{index:int}", (Guid id, int index, ClaimsPrincipal user, ElectionState state) => {
            var items = state.GetLayer(id, index, user.Subject);
            return items == null ? ApiResults.Error("Diese Schicht liegt nicht vor.", 404) : Results.Json(new LayerItems(items.ToList()));
        });

        group.MapPut("/ballots/{id:guid}/layers/{index:int}", (Guid id, int index, LayerItems request, ClaimsPrincipal user, ElectionState state) => {
            var decoded = request.Items.Select(ApiResults.DecodeBase64).ToList();
            if (decoded.Any(item => item == null))
                return ApiResults.Error("Die Schicht enthält beschädigte Einträge.", 400);
            return ApiResults.From(state.PutLayer(id, index, user.Subject, decoded.Select(item => item!).ToList()));
        });

        group.MapPut("/ballots/{id:guid}/result", (Guid id, ResultRequest request, ClaimsPrincipal user, ElectionState state) =>
            ApiResults.From(state.PutResult(id, user.Subject, request.Document)));

        group.MapPut("/ballots/{id:guid}/signature", (Guid id, SignatureRequest request, ClaimsPrincipal user, ElectionState state) => {
            var signature = ApiResults.DecodeBase64(request.Signature);
            if (signature == null)
                return ApiResults.Error("Die Unterschrift hat kein gültiges Format.", 400);
            return ApiResults.From(state.PutSignature(id, user.Subject, signature));
        });
    }
}
```

`Endpoints/AdminEndpoints.cs`:
```csharp
using System.Security.Claims;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Keycloak;

namespace SecretBallot.Server.Endpoints;

public static class AdminEndpoints {
    public static void MapAdminEndpoints(this WebApplication app) {
        var group = app.MapGroup("/api/admin").RequireAuthorization();

        group.MapGet("/keyholders", (ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);
            return Results.Json(state.GetKeyHolders());
        });

        group.MapPut("/keyholders", async (List<KeyHolderEntryRequest> entries, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings,
            IKeycloakDirectory directory, ILogger<ElectionState> logger, CancellationToken ct) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);

            var assignments = new List<KeyHolderAssignment>();
            foreach (var entry in entries) {
                DirectoryUser? found;
                try {
                    found = await directory.FindByUsernameAsync(entry.Username.Trim(), ct);
                } catch (Exception ex) {
                    logger.LogWarning("Keycloak username lookup failed: {Exception}", ex);
                    return ApiResults.Error("Das Piratenlogin ist gerade nicht erreichbar.", 502);
                }
                if (found == null)
                    return ApiResults.Error($"Benutzername „{entry.Username}“ wurde im Piratenlogin nicht gefunden.", 400);
                assignments.Add(new KeyHolderAssignment(entry.Role, found.Id, found.Username, entry.Leads));
            }
            return ApiResults.From(state.ReplaceKeyHolders(assignments));
        });

        group.MapPost("/ballots", (CreateBallotRequest request, ClaimsPrincipal user, ElectionState state, SecretBallotSettings settings) => {
            if (!settings.IsAdmin(user.Username))
                return ApiResults.Error("Nur für die Verwaltung.", 403);

            BallotType? type = request.Type switch {
                "approval" => BallotType.Approval,
                "single" => BallotType.Single,
                "yesno" => BallotType.YesNo,
                _ => null
            };
            if (type == null)
                return ApiResults.Error("Unbekannte Wahlart.", 400);

            var result = state.CreateBallot(new BallotDraft(request.Title, type.Value, request.Options, request.Seats), out var id);
            return result.Ok ? Results.Json(new CreatedResponse(id)) : ApiResults.From(result);
        });
    }
}
```

`SecurityHeaders.cs`:
```csharp
namespace SecretBallot.Server;

public static class SecurityHeaders {
    private const string ContentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

    public static void UseSecurityHeaders(this WebApplication app) {
        app.Use(async (context, next) => {
            var headers = context.Response.Headers;
            headers.ContentSecurityPolicy = ContentSecurityPolicy;
            headers.XContentTypeOptions = "nosniff";
            headers["Referrer-Policy"] = "no-referrer";
            headers.CacheControl = "no-store";
            await next();
        });
    }
}
```

`Program.cs`:
```csharp
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using SecretBallot.Server;
using SecretBallot.Server.Auth;
using SecretBallot.Server.Election;
using SecretBallot.Server.Endpoints;
using SecretBallot.Server.Keycloak;

var builder = WebApplication.CreateBuilder(args);
var settings = builder.Configuration.GetSection("SecretBallot").Get<SecretBallotSettings>() ?? new SecretBallotSettings();

builder.Services.AddSingleton(settings);
builder.Services.ConfigureHttpJsonOptions(options => options.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));
builder.Services.AddSingleton<ElectionState>();
builder.Services.AddSingleton<KeycloakTokenProvider>();
builder.Services.AddHttpClient<IKeycloakDirectory, KeycloakDirectory>();
builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
builder.Services.AddBallotAuthentication(settings);
builder.Services.Configure<ForwardedHeadersOptions>(options => {
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});

var app = builder.Build();

app.UseForwardedHeaders();
if (!app.Environment.IsDevelopment())
    app.UseHsts();
app.UseSecurityHeaders();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();
app.MapPublicEndpoints();
app.MapVoterEndpoints();
app.MapKeyHolderEndpoints();
app.MapAdminEndpoints();

app.Run();

public partial class Program { }
```

`appsettings.json`:
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning",
      "System.Net.Http.HttpClient": "Warning"
    }
  },
  "AllowedHosts": "*",
  "SecretBallot": {
    "Authority": "https://sso.piratenpartei.de/realms/Piratenpartei",
    "ClientId": "secret-ballot",
    "ClientSecret": "",
    "KeycloakBaseUrl": "https://sso.piratenpartei.de",
    "Realm": "Piratenpartei",
    "EligibilityAttribute": "ekklesia_eligible",
    "AdminUsernames": []
  }
}
```
Realm name: verify against the realm used by Quartermaster's live config before deploying; the secret is set via environment variable `SecretBallot__ClientSecret`, never committed.

`appsettings.Development.json`: `{ "Logging": { "LogLevel": { "Default": "Debug", "Microsoft.AspNetCore": "Warning" } } }`.

- [ ] **Step 5: Build and run tests**

Run: `cd /media/SMB/SecretBallot && dotnet build -m:1 SecretBallot.slnx && dotnet run --no-build --project SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`
Expected: build succeeds with 0 warnings from our code, all tests PASS.

- [ ] **Step 6: Smoke the API**

Run: `cd /media/SMB/SecretBallot && (dotnet run --no-build --project SecretBallot.Server --urls http://127.0.0.1:5180 &) ; sleep 1 4; curl -s http://127.0.0.1:5180/api/me; curl -s http://127.0.0.1:5180/api/ballots/current; curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d '{"ciphertext":"AA=="}' http://127.0.0.1:5180/api/ballots/00000000-0000-0000-0000-000000000000/votes; pkill -f "SecretBallot.Server"`
Expected: `{"loggedIn":false,...}`, `{"ballot":null,"hasVoted":false}`, `401`.

---

### Task 5: Shared page shell

**Files:**
- Create: `wwwroot/css/app.css`, `wwwroot/js/dom.js`, `wwwroot/js/api.js`, `wwwroot/js/shell.js`

**Interfaces:**
- Produces: `BallotDom.el(tag, attributes, ...children)`, `BallotDom.clear(node)`, `BallotDom.download(filename, text)`, `BallotDom.readFile(input) -> Promise<string>`; `BallotApi.get(url)`, `BallotApi.getText(url)`, `BallotApi.send(method, url, body)`, `BallotApi.ApiError`; `BallotShell.init(activePage) -> Promise<me>` renders the header nav, login/logout and returns the `/api/me` response; `BallotShell.message(container, kind, text)` where kind is `"ok"|"warn"|"error"|"info"`.

- [ ] **Step 1: Implement `dom.js`**

```js
(function (root) {
    "use strict";

    function el(tag, attributes, ...children) {
        const node = document.createElement(tag);
        for (const [name, value] of Object.entries(attributes || {})) {
            if (value == null || value === false)
                continue;
            if (name === "class") {
                node.className = value;
            } else if (name.startsWith("on")) {
                node.addEventListener(name.substring(2), value);
            } else if (value === true) {
                node.setAttribute(name, "");
            } else {
                node.setAttribute(name, value);
            }
        }
        for (const child of children.flat()) {
            if (child == null || child === false)
                continue;
            node.append(child instanceof Node ? child : String(child));
        }
        return node;
    }

    function clear(node) {
        while (node.firstChild)
            node.removeChild(node.firstChild);
    }

    function download(filename, text) {
        const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
        const link = el("a", { href: url, download: filename });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function readFile(input) {
        const file = input.files && input.files[0];
        if (!file)
            return Promise.reject(new Error("Bitte eine Datei auswählen."));
        return file.text();
    }

    root.BallotDom = { el, clear, download, readFile };
})(globalThis);
```

- [ ] **Step 2: Implement `api.js`**

```js
(function (root) {
    "use strict";

    class ApiError extends Error {
        constructor(status, message) {
            super(message);
            this.status = status;
        }
    }

    async function errorFrom(response) {
        if (response.status === 401)
            return new ApiError(401, "Bitte zuerst mit dem Piratenlogin anmelden.");
        try {
            const data = await response.json();
            if (data && data.error)
                return new ApiError(response.status, data.error);
        } catch (error) {
            return new ApiError(response.status, "Unerwartete Antwort vom Server (" + response.status + ").");
        }
        return new ApiError(response.status, "Unerwartete Antwort vom Server (" + response.status + ").");
    }

    async function send(method, url, body) {
        const options = { method, credentials: "same-origin", headers: { "Accept": "application/json" } };
        if (body !== undefined) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(body);
        }
        const response = await fetch(url, options);
        if (!response.ok)
            throw await errorFrom(response);
        if (response.status === 204)
            return null;
        return response.json();
    }

    function get(url) {
        return send("GET", url);
    }

    async function getText(url) {
        const response = await fetch(url, { credentials: "same-origin" });
        if (!response.ok)
            throw await errorFrom(response);
        return response.text();
    }

    root.BallotApi = { ApiError, send, get, getText };
})(globalThis);
```

- [ ] **Step 3: Implement `shell.js`**

```js
(function (root) {
    "use strict";
    const { el, clear } = root.BallotDom;

    const pages = [
        { id: "abstimmen", href: "/", label: "Abstimmen" },
        { id: "bulletin", href: "/bulletin.html", label: "Öffentliche Liste" },
        { id: "schluessel", href: "/schluessel.html", label: "Schlüsselverwaltung", needs: me => me.keyHolder != null },
        { id: "admin", href: "/admin.html", label: "Verwaltung", needs: me => me.isAdmin },
        { id: "pruefen", href: "/pruefen.html", label: "Prüfen" }
    ];

    function message(container, kind, text) {
        container.append(el("p", { class: "message " + kind }, text));
    }

    async function loadMe() {
        try {
            return await root.BallotApi.get("/api/me");
        } catch (error) {
            return { loggedIn: false, isAdmin: false, keyHolder: null, error: error.message };
        }
    }

    async function init(activePage) {
        const me = await loadMe();
        const header = document.querySelector("header");
        clear(header);
        const nav = el("nav", {}, pages
            .filter(page => !page.needs || page.needs(me))
            .map(page => el("a", { href: page.href, class: page.id === activePage ? "active" : null }, page.label)));
        const returnUrl = encodeURIComponent(location.pathname);
        const account = me.loggedIn
            ? el("span", { class: "account" }, me.name + " · ", el("a", { href: "/logout" }, "Abmelden"))
            : el("span", { class: "account" }, el("a", { href: "/login?returnUrl=" + returnUrl, class: "button" }, "Mit Piratenlogin anmelden"));
        header.append(el("strong", { class: "brand" }, "Geheime Wahl"), nav, account);
        return me;
    }

    root.BallotShell = { init, message };
})(globalThis);
```

- [ ] **Step 4: Implement `app.css`**

```css
:root {
    --bg: #ffffff;
    --fg: #1d1d1f;
    --muted: #5f6368;
    --accent: #ff8800;
    --accent-fg: #000000;
    --border: #d0d3d7;
    --ok: #1e7b34;
    --warn: #8a5a00;
    --error: #b3261e;
    --panel: #f5f6f7;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg: #16171a;
        --fg: #ececf0;
        --muted: #a0a4ab;
        --border: #3a3d43;
        --ok: #6fd18a;
        --warn: #f0c060;
        --error: #ff8a80;
        --panel: #202227;
    }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 16px/1.5 system-ui, sans-serif; }
header { display: flex; flex-wrap: wrap; gap: 12px 24px; align-items: center; padding: 12px 16px; border-bottom: 1px solid var(--border); }
header nav { display: flex; flex-wrap: wrap; gap: 12px; flex: 1; }
header nav a { color: var(--fg); text-decoration: none; }
header nav a.active { border-bottom: 2px solid var(--accent); }
main { max-width: 860px; margin: 0 auto; padding: 16px; }
section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin: 16px 0; }
h1 { font-size: 1.5rem; }
h2 { font-size: 1.2rem; margin-top: 0; }
button, .button { display: inline-block; font: inherit; padding: 8px 16px; border-radius: 6px; border: 1px solid var(--border); background: var(--bg); color: var(--fg); cursor: pointer; text-decoration: none; }
button.primary, .button { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
button:disabled { opacity: 0.5; cursor: not-allowed; }
input[type=text], input[type=password], input[type=number], select, textarea { font: inherit; width: 100%; padding: 6px 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); color: var(--fg); }
label { display: block; margin: 8px 0; }
label.choice { display: flex; gap: 8px; align-items: center; padding: 8px; border: 1px solid var(--border); border-radius: 6px; background: var(--bg); }
.fingerprint { font-family: ui-monospace, monospace; font-size: 1.3rem; letter-spacing: 0.05em; word-break: break-word; }
.mono { font-family: ui-monospace, monospace; word-break: break-all; }
.message { padding: 8px 12px; border-radius: 6px; border-left: 4px solid var(--muted); background: var(--bg); }
.message.ok { border-color: var(--ok); }
.message.warn { border-color: var(--warn); }
.message.error { border-color: var(--error); }
.muted { color: var(--muted); }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
ul.plain { list-style: none; padding: 0; }
ul.receipts { font-family: ui-monospace, monospace; font-size: 0.85rem; columns: 2 280px; padding-left: 0; list-style: none; }
.found { background: var(--accent); color: var(--accent-fg); }
```

- [ ] **Step 5: Verify syntax**

Run: `cd /media/SMB/SecretBallot && for f in SecretBallot.Server/wwwroot/js/*.js; do node --check "$f" || echo "FAIL $f"; done`
Expected: no output.

---

### Task 6: Voting page and bulletin

**Files:**
- Create: `wwwroot/index.html`, `wwwroot/js/abstimmen.js`, `wwwroot/bulletin.html`, `wwwroot/js/bulletin.js`

**Interfaces:**
- Consumes: `BallotCrypto`, `BallotDom`, `BallotApi`, `BallotShell`; `GET /api/ballots/current`, `POST /api/ballots/{id}/votes`, `GET /api/ballots`, `GET /api/ballots/{id}/bulletin`.

- [ ] **Step 1: `index.html`**

```html
<!doctype html>
<html lang="de">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Geheime Wahl</title>
    <link rel="stylesheet" href="/css/app.css">
</head>
<body>
    <header></header>
    <main>
        <h1>Abstimmen</h1>
        <div id="content"><p class="muted">Lädt …</p></div>
    </main>
    <script src="/js/dom.js"></script>
    <script src="/js/api.js"></script>
    <script src="/js/shell.js"></script>
    <script src="/js/ballot-crypto.js"></script>
    <script src="/js/abstimmen.js"></script>
</body>
</html>
```

- [ ] **Step 2: `abstimmen.js`**

```js
(function () {
    "use strict";
    const { el, clear } = BallotDom;
    const content = document.getElementById("content");
    let pollTimer = null;
    let me = null;

    function choiceSummary(definition, choice) {
        if (choice.length === 0)
            return "Leerer Stimmzettel (keine Auswahl)";
        return choice.map(index => definition.options[index]).join(", ");
    }

    function readChoice(form) {
        return Array.from(form.querySelectorAll("input[name=choice]:checked")).map(input => Number(input.value));
    }

    function hint(definition) {
        if (definition.type === "approval")
            return "Du kannst beliebig viele Kandidierende ankreuzen, auch alle oder keine. Gewählt ist, wer mehr als die Hälfte der gültigen Stimmen erhält (" + definition.seats + " Sitze).";
        if (definition.type === "single")
            return "Kreuze genau eine Option an oder gib einen leeren Stimmzettel ab.";
        return "Kreuze Ja oder Nein an oder gib einen leeren Stimmzettel ab (Enthaltung).";
    }

    function renderOptions(definition) {
        const inputType = definition.type === "approval" ? "checkbox" : "radio";
        return definition.options.map((option, index) =>
            el("label", { class: "choice" }, el("input", { type: inputType, name: "choice", value: String(index) }), option));
    }

    function renderReceipt(receipt, note) {
        clear(content);
        const section = el("section", {},
            el("h2", {}, "Deine Stimme wurde abgegeben"),
            note ? el("p", { class: "message warn" }, note) : null,
            el("p", {}, "Deine Quittung (bitte aufheben):"),
            el("p", { class: "fingerprint" }, receipt.substring(0, 16)),
            el("p", { class: "mono muted" }, receipt),
            el("div", { class: "row" },
                el("button", { onclick: () => navigator.clipboard.writeText(receipt) }, "Quittung kopieren")),
            el("p", {}, "Nach dem Schließen des Wahlgangs erscheint deine Quittung auf der ", el("a", { href: "/bulletin.html" }, "öffentlichen Liste"),
                ". Fehlt sie dort, melde dich sofort bei der Wahlleitung."));
        content.append(section);
    }

    async function cast(current, definition, definitionHash, choice, status, button) {
        button.disabled = true;
        clear(status);
        BallotShell.message(status, "info", "Stimmzettel wird verschlüsselt …");
        let receipt = null;
        try {
            const keys = await Promise.all(current.keyHolders.map(k => BallotCrypto.importEncryptionPublicKey(BallotCrypto.fromBase64(k.encryptionKey))));
            const plaintext = BallotCrypto.buildPlaintext(current.id, definitionHash, choice);
            const envelope = await BallotCrypto.encryptBallot(keys, current.id, plaintext);
            receipt = await BallotCrypto.sha256Hex(envelope);
            await BallotApi.send("POST", "/api/ballots/" + current.id + "/votes", { ciphertext: BallotCrypto.toBase64(envelope) });
            renderReceipt(receipt, null);
        } catch (error) {
            if (receipt != null && error.status === 409 && /bereits abgestimmt/.test(error.message)) {
                renderReceipt(receipt, "Der Server meldet, dass du bereits abgestimmt hast. Falls du eben ohne Antwort abgebrochen wurdest, ist dies die Quittung deines letzten Versuchs; prüfe sie nach dem Schließen auf der öffentlichen Liste.");
                return;
            }
            clear(status);
            BallotShell.message(status, "error", error.message);
            button.disabled = false;
        }
    }

    function renderConfirm(current, definition, definitionHash, choice, form) {
        const status = el("div");
        const back = el("button", { type: "button", onclick: () => render() }, "Zurück");
        const submit = el("button", { type: "button", class: "primary" }, "Jetzt verbindlich abgeben");
        submit.addEventListener("click", () => cast(current, definition, definitionHash, choice, status, submit));
        clear(form);
        form.append(
            el("h2", {}, "Bitte prüfen"),
            el("p", {}, "Deine Auswahl: ", el("strong", {}, choiceSummary(definition, choice))),
            el("p", { class: "muted" }, "Die Stimme kann danach nicht mehr geändert werden."),
            el("div", { class: "row" }, back, submit),
            status);
    }

    async function renderBallot(current) {
        const definition = JSON.parse(current.definitionJson);
        const definitionHash = await BallotCrypto.sha256Hex(BallotCrypto.utf8(current.definitionJson));
        const rawKeys = current.keyHolders.map(k => BallotCrypto.fromBase64(k.encryptionKey));
        const localFingerprint = await BallotCrypto.combinedFingerprint(current.id, rawKeys);

        clear(content);
        if (localFingerprint !== current.combinedFingerprint) {
            BallotShell.message(content, "error", "Der Fingerabdruck stimmt nicht mit den Schlüsseln überein. Bitte NICHT abstimmen und sofort die Wahlleitung informieren.");
            return;
        }

        const form = el("section");
        const status = el("div");
        const next = el("button", { type: "button", class: "primary" }, "Weiter");
        next.addEventListener("click", () => renderConfirm(current, definition, definitionHash, readChoice(form), form));
        form.append(
            el("h2", {}, definition.title),
            el("p", { class: "muted" }, hint(definition)),
            renderOptions(definition),
            el("p", {}, "Fingerabdruck dieses Wahlgangs:"),
            el("p", { class: "fingerprint" }, localFingerprint),
            el("p", { class: "muted" }, "Vergleiche ihn mit dem Fingerabdruck, den die Wahlleitung in Mumble und im Stream vorliest. Weicht er ab, stimme nicht ab."),
            el("div", { class: "row" }, next),
            status);
        content.append(form);
    }

    async function render() {
        clearTimeout(pollTimer);
        let response;
        try {
            response = await BallotApi.get("/api/ballots/current");
        } catch (error) {
            clear(content);
            BallotShell.message(content, "error", error.message);
            pollTimer = setTimeout(render, 5000);
            return;
        }

        clear(content);
        if (!me.loggedIn) {
            BallotShell.message(content, "info", "Bitte melde dich oben mit deinem Piratenlogin an.");
            return;
        }
        if (me.eligible === false) {
            BallotShell.message(content, "warn", "Laut Piratenlogin bist du derzeit nicht stimmberechtigt (Beiträge gezahlt). Nach einer Zahlung kann die Akkreditierung das sofort ändern; lade die Seite danach neu.");
        }
        if (response.ballot == null) {
            BallotShell.message(content, "info", "Zurzeit läuft kein Wahlgang. Diese Seite aktualisiert sich automatisch.");
            pollTimer = setTimeout(render, 5000);
            return;
        }
        if (response.hasVoted) {
            BallotShell.message(content, "ok", "Du hast in diesem Wahlgang bereits abgestimmt.");
            pollTimer = setTimeout(render, 5000);
            return;
        }
        await renderBallot(response.ballot);
    }

    BallotShell.init("abstimmen").then(result => {
        me = result;
        render();
    });
})();
```

- [ ] **Step 3: `bulletin.html`**

Same skeleton as `index.html` with title `Öffentliche Liste`, `<h1>Öffentliche Liste</h1>`, scripts `dom.js`, `api.js`, `shell.js`, `bulletin.js` (no crypto).

- [ ] **Step 4: `bulletin.js`**

```js
(function () {
    "use strict";
    const { el, clear } = BallotDom;
    const content = document.getElementById("content");

    function renderBulletin(container, bulletin) {
        clear(container);
        const matches = bulletin.voterCount === bulletin.ciphertextCount;
        const list = el("ul", { class: "receipts" }, bulletin.receipts.map(r => el("li", { "data-receipt": r }, r)));
        const search = el("input", { type: "text", placeholder: "Quittung (die ersten 16 Zeichen genügen)" });
        const result = el("p");
        search.addEventListener("input", () => {
            const value = search.value.trim().toLowerCase().replace(/\s+/g, "");
            clear(result);
            for (const item of list.children)
                item.classList.toggle("found", value.length >= 8 && item.dataset.receipt.startsWith(value));
            if (value.length < 8)
                return;
            const found = bulletin.receipts.some(r => r.startsWith(value));
            result.append(found ? "Deine Quittung ist enthalten." : "Diese Quittung ist NICHT enthalten. Bitte sofort die Wahlleitung informieren.");
            result.className = "message " + (found ? "ok" : "error");
        });
        container.append(
            el("h2", {}, bulletin.title),
            el("p", {}, "Abgegebene Stimmen (Personen): ", el("strong", {}, String(bulletin.voterCount)),
                " · Stimmzettel: ", el("strong", {}, String(bulletin.ciphertextCount))),
            matches ? null : el("p", { class: "message error" }, "Die Zahl der Stimmzettel stimmt nicht mit der Zahl der Abstimmenden überein. Der Wahlgang ist ungültig."),
            el("label", {}, "Eigene Quittung suchen", search),
            result,
            list);
    }

    async function render() {
        let ballots;
        try {
            ballots = await BallotApi.get("/api/ballots");
        } catch (error) {
            clear(content);
            BallotShell.message(content, "error", error.message);
            return;
        }

        clear(content);
        const closed = ballots.filter(b => b.status === "Closed" || b.status === "Finished");
        if (closed.length === 0) {
            BallotShell.message(content, "info", "Es wurde noch kein Wahlgang geschlossen.");
            return;
        }
        for (const ballot of closed) {
            const section = el("section", {}, el("p", { class: "muted" }, "Lädt …"));
            content.append(section);
            BallotApi.get("/api/ballots/" + ballot.id + "/bulletin")
                .then(bulletin => renderBulletin(section, bulletin))
                .catch(error => {
                    clear(section);
                    BallotShell.message(section, "error", error.message);
                });
        }
    }

    BallotShell.init("bulletin").then(render);
})();
```

Enums arrive as strings (`"Closed"`) because Task 4 registers `JsonStringEnumConverter`.

- [ ] **Step 5: Verify syntax and serving**

Run: `node --check` on the new scripts; start the server as in Task 4 Step 6 and `curl -s http://127.0.0.1:5180/ | head -5` and `curl -sI http://127.0.0.1:5180/js/abstimmen.js | grep -i content-security`.
Expected: HTML served, CSP header present.

---

### Task 7: Key holder page: keys, backup, register, confirm, open/close

**Files:**
- Create: `wwwroot/schluessel.html`, `wwwroot/js/schluessel.js`

**Interfaces:**
- Consumes: `/api/me` (`keyHolder`), `PUT /api/keyholder/keys`, `POST /api/keyholder/confirm`, `GET /api/ballots`, `POST /api/keyholder/ballots/{id}/open|close`.
- Produces: in-page `loaded` object `{ content, encryptionKey: CryptoKey, signingKey: CryptoKey, encryptionRaw, signingRaw }` used by Task 9's functions in the same file; global function hook `renderBallotTasks(container, ballots)` filled by Task 9.

- [ ] **Step 1: `schluessel.html`**

Skeleton as `index.html`, title `Schlüsselverwaltung`, `<h1>Schlüsselverwaltung</h1>`, `<div id="content">`, scripts `dom.js`, `api.js`, `shell.js`, `ballot-crypto.js`, `ballot-tally.js`, `schluessel.js`.

- [ ] **Step 2: `schluessel.js` key part**

```js
(function () {
    "use strict";
    const { el, clear, download, readFile } = BallotDom;
    const content = document.getElementById("content");
    const MIN_PASSWORD_LENGTH = 12;
    let me = null;
    let loaded = null;

    async function loadContent(backupContent) {
        const encryptionKey = await BallotCrypto.importEncryptionPrivateJwk(backupContent.encryptionPrivateKey);
        const signingKey = await BallotCrypto.importSigningPrivateJwk(backupContent.signingPrivateKey);
        const encryptionRaw = await BallotCrypto.publicRawFromPrivateJwk(backupContent.encryptionPrivateKey);
        const signingRaw = await BallotCrypto.publicRawFromPrivateJwk(backupContent.signingPrivateKey);
        return { content: backupContent, encryptionKey, signingKey, encryptionRaw, signingRaw };
    }

    function serverHasKeys(keys) {
        const holder = me.keyHolder;
        if (holder.encryptionKey == null || holder.signingKey == null)
            return false;
        if (holder.encryptionKey !== BallotCrypto.toBase64(keys.encryptionRaw))
            return false;
        return holder.signingKey === BallotCrypto.toBase64(keys.signingRaw);
    }

    async function refreshMe() {
        me = await BallotApi.get("/api/me");
    }

    async function registerAndConfirm(keys, status) {
        clear(status);
        await BallotApi.send("PUT", "/api/keyholder/keys", {
            encryptionKey: BallotCrypto.toBase64(keys.encryptionRaw),
            signingKey: BallotCrypto.toBase64(keys.signingRaw)
        });
        await refreshMe();
        render();
    }

    function passwordFields() {
        const first = el("input", { type: "password", autocomplete: "new-password" });
        const second = el("input", { type: "password", autocomplete: "new-password" });
        return { first, second, nodes: [el("label", {}, "Passwort für die Sicherung (mindestens 12 Zeichen)", first), el("label", {}, "Passwort wiederholen", second)] };
    }

    function renderGenerate(section) {
        const status = el("div");
        const passwords = passwordFields();
        const button = el("button", { class: "primary" }, "Schlüssel erzeugen und Sicherung herunterladen");
        button.addEventListener("click", async () => {
            clear(status);
            if (passwords.first.value.length < MIN_PASSWORD_LENGTH || passwords.first.value !== passwords.second.value) {
                BallotShell.message(status, "error", "Die Passwörter sind zu kurz oder stimmen nicht überein.");
                return;
            }
            button.disabled = true;
            try {
                const encryption = await BallotCrypto.generateEncryptionKeyPair();
                const signing = await BallotCrypto.generateSigningKeyPair();
                const backupContent = {
                    role: me.keyHolder.role,
                    encryptionPrivateKey: await BallotCrypto.exportPrivateJwk(encryption.privateKey),
                    signingPrivateKey: await BallotCrypto.exportPrivateJwk(signing.privateKey)
                };
                const file = await BallotCrypto.createBackup(passwords.first.value, backupContent);
                download("schluessel-" + me.keyHolder.role.replace(/[^A-Za-z0-9]+/g, "-") + ".json", file);
                renderVerifyBackup(section, backupContent);
            } catch (error) {
                BallotShell.message(status, "error", "Erzeugen fehlgeschlagen: " + error.message);
                button.disabled = false;
            }
        });
        section.append(
            el("h2", {}, "Schritt 1: Schlüssel erzeugen"),
            el("p", {}, "Die Schlüssel entstehen nur in diesem Browser. Der private Teil verlässt ihn ausschließlich als passwortgeschützte Sicherungsdatei. Ohne diese Datei kann der Wahlgang nicht ausgezählt werden."),
            passwords.nodes, el("div", { class: "row" }, button), status);
    }

    function renderVerifyBackup(section, backupContent) {
        clear(section);
        const status = el("div");
        const file = el("input", { type: "file", accept: ".json,application/json" });
        const password = el("input", { type: "password", autocomplete: "current-password" });
        const button = el("button", { class: "primary" }, "Sicherung prüfen und Schlüssel registrieren");
        button.addEventListener("click", async () => {
            clear(status);
            button.disabled = true;
            try {
                const restored = await BallotCrypto.openBackup(password.value, await readFile(file));
                if (!BallotCrypto.backupMatches(backupContent, restored))
                    throw new Error("Die ausgewählte Datei enthält andere Schlüssel.");
                loaded = await loadContent(restored);
                await registerAndConfirm(loaded, status);
            } catch (error) {
                BallotShell.message(status, "error", "Prüfung fehlgeschlagen: " + error.message + " Bitte die eben heruntergeladene Datei wählen und das Passwort erneut eingeben.");
                button.disabled = false;
            }
        });
        section.append(
            el("h2", {}, "Schritt 2: Sicherung prüfen"),
            el("p", {}, "Die Sicherungsdatei wurde heruntergeladen. Lege sie an einem sicheren Ort ab (zusätzlich z. B. auf einem USB-Stick). Wähle sie jetzt erneut aus und gib das Passwort ein. Erst danach werden die öffentlichen Schlüssel registriert."),
            el("label", {}, "Sicherungsdatei", file),
            el("label", {}, "Passwort", password),
            el("div", { class: "row" }, button), status);
    }

    function renderLoadBackup(section, purpose) {
        const status = el("div");
        const file = el("input", { type: "file", accept: ".json,application/json" });
        const password = el("input", { type: "password", autocomplete: "current-password" });
        const button = el("button", { class: "primary" }, "Sicherung laden");
        button.addEventListener("click", async () => {
            clear(status);
            button.disabled = true;
            try {
                const keys = await loadContent(await BallotCrypto.openBackup(password.value, await readFile(file)));
                loaded = keys;
                if (!serverHasKeys(keys)) {
                    await registerAndConfirm(keys, status);
                    return;
                }
                render();
            } catch (error) {
                BallotShell.message(status, "error", "Laden fehlgeschlagen: " + error.message);
                button.disabled = false;
            }
        });
        section.append(
            el("h2", {}, "Sicherung laden"),
            el("p", {}, purpose),
            el("label", {}, "Sicherungsdatei", file),
            el("label", {}, "Passwort", password),
            el("div", { class: "row" }, button), status);
    }

    function renderConfirm(section) {
        const holder = me.keyHolder;
        const status = el("div");
        const localEncryption = el("span", { class: "mono" }, "…");
        const localSigning = el("span", { class: "mono" }, "…");
        const button = el("button", { class: "primary", disabled: true }, "Fingerabdrücke stimmen überein, bestätigen");
        Promise.all([BallotCrypto.fingerprint(loaded.encryptionRaw), BallotCrypto.fingerprint(loaded.signingRaw)]).then(([encryption, signing]) => {
            localEncryption.textContent = encryption;
            localSigning.textContent = signing;
            const matches = encryption === holder.encryptionFingerprint && signing === holder.signingFingerprint;
            button.disabled = !matches;
            if (!matches)
                BallotShell.message(status, "error", "Die Fingerabdrücke auf dem Server weichen ab. NICHT bestätigen, sofort die Wahlleitung und die Verwaltung informieren.");
            button.addEventListener("click", async () => {
                try {
                    await BallotApi.send("POST", "/api/keyholder/confirm", { encryptionFingerprint: encryption, signingFingerprint: signing });
                    await refreshMe();
                    render();
                } catch (error) {
                    BallotShell.message(status, "error", error.message);
                }
            });
        });
        section.append(
            el("h2", {}, "Schritt 3: Fingerabdrücke vergleichen"),
            el("p", {}, "Verschlüsselung, auf dem Server: ", el("span", { class: "mono" }, holder.encryptionFingerprint)),
            el("p", {}, "Verschlüsselung, in diesem Browser: ", localEncryption),
            el("p", {}, "Signatur, auf dem Server: ", el("span", { class: "mono" }, holder.signingFingerprint)),
            el("p", {}, "Signatur, in diesem Browser: ", localSigning),
            el("div", { class: "row" }, button), status);
    }

    function renderKeySection() {
        const holder = me.keyHolder;
        const section = el("section");
        content.append(section);
        if (holder.encryptionKey == null && loaded == null) {
            renderGenerate(section);
            content.append(el("section", {}, renderLoadBackupInto("Nach einem Neustart des Servers: vorhandene Sicherung laden, um die Schlüssel erneut zu registrieren.")));
            return;
        }
        if (loaded == null) {
            renderLoadBackup(section, holder.confirmed
                ? "Deine Schlüssel sind registriert und bestätigt. Zum Öffnen der Auszählung, Entschlüsseln und Unterschreiben bitte die Sicherung laden."
                : "Deine Schlüssel sind registriert, aber noch nicht bestätigt. Bitte die Sicherung laden, um die Fingerabdrücke zu vergleichen.");
            return;
        }
        if (!holder.confirmed) {
            renderConfirm(section);
            return;
        }
        section.append(el("h2", {}, "Schlüssel"), el("p", { class: "message ok" }, "Schlüssel registriert, bestätigt und in diesem Browser geladen."));
    }

    function renderLoadBackupInto(purpose) {
        const wrapper = el("div");
        renderLoadBackup(wrapper, purpose);
        return wrapper;
    }

    function renderHeader() {
        const holder = me.keyHolder;
        content.append(el("section", {},
            el("h2", {}, "Deine Rolle: " + holder.role),
            el("p", {}, "Position " + (holder.position + 1) + " in der Reihenfolge der Entschlüsselung." + (holder.leads ? " Du leitest die Wahl und öffnest und schließt die Wahlgänge." : ""))));
    }

    function ballotActions(ballot) {
        const status = el("div");
        const actions = el("div", { class: "row" });
        if (ballot.iLead && ballot.status === "Draft") {
            actions.append(el("button", { class: "primary", onclick: () => act("open", ballot, status) }, "Wahlgang öffnen"));
        }
        if (ballot.iLead && ballot.status === "Open") {
            actions.append(el("button", { class: "primary", onclick: () => act("close", ballot, status) }, "Wahlgang schließen"));
        }
        return [actions, status];
    }

    async function act(action, ballot, status) {
        clear(status);
        try {
            await BallotApi.send("POST", "/api/keyholder/ballots/" + ballot.id + "/" + action);
            render();
        } catch (error) {
            BallotShell.message(status, "error", error.message);
        }
    }

    function statusLabel(status) {
        return { Draft: "vorbereitet", Open: "geöffnet", Closed: "geschlossen", Finished: "abgeschlossen" }[status] || status;
    }

    async function renderBallots() {
        const ballots = await BallotApi.get("/api/ballots");
        const section = el("section", {}, el("h2", {}, "Wahlgänge"));
        content.append(section);
        if (ballots.length === 0) {
            section.append(el("p", { class: "muted" }, "Noch keine Wahlgänge angelegt."));
            return;
        }
        for (const ballot of ballots) {
            const item = el("div", { class: "ballot" },
                el("h3", {}, ballot.title + " (" + statusLabel(ballot.status) + ")"),
                el("p", {}, "Stimmen: " + ballot.voteCount),
                ballot.combinedFingerprint ? el("p", {}, "Fingerabdruck zum Vorlesen: ", el("span", { class: "fingerprint" }, ballot.combinedFingerprint)) : null,
                ballotActions(ballot));
            section.append(item);
            if (ballot.status === "Closed" || ballot.status === "Finished")
                renderTallyTasks(item, ballot);
        }
    }

    function renderTallyTasks(item, ballot) {
        if (ballot.myPosition >= 0)
            item.append(el("p", { class: "muted" }, "Auszählung folgt in Task 9."));
    }

    async function render() {
        clear(content);
        if (!me.loggedIn) {
            BallotShell.message(content, "info", "Bitte oben mit dem Piratenlogin anmelden.");
            return;
        }
        if (me.keyHolder == null) {
            BallotShell.message(content, "info", "Du bist nicht als schlüsselhaltende Person eingetragen.");
            return;
        }
        renderHeader();
        renderKeySection();
        try {
            await renderBallots();
        } catch (error) {
            BallotShell.message(content, "error", error.message);
        }
    }

    BallotShell.init("schluessel").then(result => {
        me = result;
        render();
    });
})();
```

`renderTallyTasks` is the placeholder seam that Task 9 replaces in place; it must not ship in this form. `n = 1` warning: when `ballots[0].keyHolderCount === 1` show `BallotShell.message(section, "warn", "Es gibt nur eine schlüsselhaltende Person. Sie kann alle Stimmzettel lesen, aber nicht zuordnen.")` at the top of the Wahlgänge section.

- [ ] **Step 3: Verify syntax**

Run: `node --check SecretBallot.Server/wwwroot/js/schluessel.js`
Expected: no output.

---

### Task 8: Admin page

**Files:**
- Create: `wwwroot/admin.html`, `wwwroot/js/admin.js`

**Interfaces:**
- Consumes: `GET/PUT /api/admin/keyholders`, `POST /api/admin/ballots`, `GET /api/ballots`, `POST /api/keyholder/ballots/{id}/close` (admin fallback).

- [ ] **Step 1: `admin.html`**

Skeleton as `index.html`, title `Verwaltung`, `<h1>Verwaltung</h1>`, scripts `dom.js`, `api.js`, `shell.js`, `admin.js`.

- [ ] **Step 2: `admin.js`**

```js
(function () {
    "use strict";
    const { el, clear } = BallotDom;
    const content = document.getElementById("content");

    function holderRow(entry, rows) {
        const role = el("input", { type: "text", value: entry.role || "", placeholder: "Rolle, z. B. Wahlleitung" });
        const username = el("input", { type: "text", value: entry.username || "", placeholder: "Benutzername im Piratenlogin" });
        const leads = el("input", { type: "radio", name: "leads", checked: entry.leads === true });
        const state = entry.encryptionFingerprint
            ? (entry.confirmed ? "bestätigt" : "registriert, nicht bestätigt")
            : "keine Schlüssel";
        const row = el("div", { class: "row holder" }, role, username, el("label", { class: "choice" }, leads, "leitet"), el("span", { class: "muted" }, state));
        const remove = el("button", { type: "button", onclick: () => row.remove() }, "Entfernen");
        row.append(remove);
        row.read = () => ({ role: role.value.trim(), username: username.value.trim(), leads: leads.checked });
        rows.append(row);
    }

    async function renderKeyHolders() {
        const holders = await BallotApi.get("/api/admin/keyholders");
        const section = el("section", {}, el("h2", {}, "Schlüsselhaltende Personen"),
            el("p", { class: "muted" }, "Reihenfolge = Reihenfolge der Entschlüsselung. Wer den Server betreibt, darf hier nicht stehen. Wird eine Person ersetzt, verfallen ihre Schlüssel."));
        const rows = el("div");
        holders.forEach(h => holderRow(h, rows));
        if (holders.length === 0)
            holderRow({ leads: true }, rows);
        const status = el("div");
        const add = el("button", { type: "button", onclick: () => holderRow({}, rows) }, "Person hinzufügen");
        const save = el("button", { type: "button", class: "primary" }, "Speichern");
        save.addEventListener("click", async () => {
            clear(status);
            try {
                await BallotApi.send("PUT", "/api/admin/keyholders", Array.from(rows.children).map(row => row.read()));
                render();
            } catch (error) {
                BallotShell.message(status, "error", error.message);
            }
        });
        if (holders.length === 1)
            BallotShell.message(section, "warn", "Mit nur einer schlüsselhaltenden Person kann diese alle Stimmzettel lesen (aber nicht zuordnen).");
        section.append(rows, el("div", { class: "row" }, add, save), status);
        content.append(section);
    }

    function renderCreateBallot() {
        const title = el("input", { type: "text", placeholder: "z. B. Wahl von zwei Beisitzern" });
        const type = el("select", {},
            el("option", { value: "approval" }, "Akzeptanzwahl (mehrere Kreuze)"),
            el("option", { value: "single" }, "Einzelwahl / Stichwahl (ein Kreuz, mit „keinen der Kandidierenden“)"),
            el("option", { value: "yesno" }, "Ja/Nein"));
        const options = el("textarea", { rows: "5", placeholder: "Eine Option pro Zeile" });
        const seats = el("input", { type: "number", min: "1", value: "1" });
        const status = el("div");
        const create = el("button", { type: "button", class: "primary" }, "Wahlgang anlegen");
        create.addEventListener("click", async () => {
            clear(status);
            try {
                await BallotApi.send("POST", "/api/admin/ballots", {
                    title: title.value,
                    type: type.value,
                    options: options.value.split("\n").map(o => o.trim()).filter(o => o.length > 0),
                    seats: Number(seats.value)
                });
                render();
            } catch (error) {
                BallotShell.message(status, "error", error.message);
            }
        });
        content.append(el("section", {}, el("h2", {}, "Wahlgang anlegen"),
            el("label", {}, "Titel", title), el("label", {}, "Wahlart", type),
            el("label", {}, "Optionen (bei Ja/Nein leer lassen)", options), el("label", {}, "Sitze (nur Akzeptanzwahl)", seats),
            el("div", { class: "row" }, create), status));
    }

    async function renderBallots() {
        const ballots = await BallotApi.get("/api/ballots");
        const section = el("section", {}, el("h2", {}, "Wahlgänge"));
        for (const ballot of ballots) {
            const status = el("div");
            const row = el("div", {}, el("p", {}, ballot.title + " · " + ballot.status + " · Stimmen: " + ballot.voteCount));
            if (ballot.status === "Open") {
                row.append(el("button", {
                    type: "button",
                    onclick: async () => {
                        try {
                            await BallotApi.send("POST", "/api/keyholder/ballots/" + ballot.id + "/close");
                            render();
                        } catch (error) {
                            BallotShell.message(status, "error", error.message);
                        }
                    }
                }, "Notfall: Wahlgang schließen"));
            }
            row.append(status);
            section.append(row);
        }
        content.append(section);
    }

    async function render() {
        clear(content);
        try {
            await renderKeyHolders();
            renderCreateBallot();
            await renderBallots();
        } catch (error) {
            BallotShell.message(content, "error", error.message);
        }
    }

    BallotShell.init("admin").then(me => {
        if (!me.isAdmin) {
            clear(content);
            BallotShell.message(content, "info", "Nur für die Verwaltung.");
            return;
        }
        render();
    });
})();
```

- [ ] **Step 3: Verify syntax**

Run: `node --check SecretBallot.Server/wwwroot/js/admin.js`
Expected: no output.

---

### Task 9: Decryption, tally, result and signature in the key holder page

**Files:**
- Modify: `wwwroot/js/schluessel.js` (replace `renderTallyTasks`, add export of the private encryption key)

**Interfaces:**
- Consumes: `GET /api/keyholder/ballots/{id}` (`ClosedBallotView`), `GET/PUT /api/keyholder/ballots/{id}/layers/{index}`, `PUT .../result`, `PUT .../signature`; `BallotTally.tally`, `BallotTally.buildResultDocument`.

- [ ] **Step 1: Replace `renderTallyTasks`**

```js
    function optionLabel(definition, indices) {
        return indices.length === 0 ? "niemand" : indices.map(i => definition.options[i]).join(", ");
    }

    function renderOutcome(definition, label, outcome) {
        return el("div", {},
            el("h4", {}, label + " (Basis " + outcome.base + ")"),
            el("p", {}, "Gewählt bzw. angenommen: ", el("strong", {}, optionLabel(definition, outcome.elected))),
            outcome.tied.length > 0 ? el("p", { class: "message warn" }, "Gleichstand: " + optionLabel(definition, outcome.tied) + ". Stichwahl nach GO nötig.") : null,
            outcome.seatsUnfilled > 0 ? el("p", { class: "message warn" }, "Unbesetzte Sitze: " + outcome.seatsUnfilled + ". Weiterer Wahlgang nach GO nötig.") : null);
    }

    function renderTally(definition, result) {
        return el("div", {},
            el("p", {}, "Stimmzettel: " + result.ciphertextCount + " · gültig: " + result.validCount + " · ungültig: " + result.invalidCount + " · leer: " + result.emptyCount),
            el("ul", {}, definition.options.map((option, i) => el("li", {}, option + ": " + result.counts[i]))),
            result.invalidReasons.length > 0 ? el("p", { class: "muted" }, "Ungültig wegen: " + result.invalidReasons.join(", ")) : null,
            renderOutcome(definition, "Leere Stimmzettel in der Basis", result.withEmpty),
            renderOutcome(definition, "Leere Stimmzettel nicht in der Basis", result.withoutEmpty));
    }

    async function computeResult(closed) {
        const definition = JSON.parse(closed.definitionJson);
        const definitionHash = await BallotCrypto.sha256Hex(BallotCrypto.utf8(closed.definitionJson));
        const bundleHash = await BallotCrypto.sha256Hex(BallotCrypto.utf8(closed.bundleJson));
        const finalLayer = await BallotApi.get("/api/keyholder/ballots/" + closed.id + "/layers/" + closed.keyHolders.length);
        const texts = finalLayer.items.map(item => {
            try {
                return BallotCrypto.decodePlaintext(BallotCrypto.fromBase64(item));
            } catch (error) {
                return "";
            }
        });
        const bundle = JSON.parse(closed.bundleJson);
        const result = BallotTally.tally(definition, definitionHash, texts, bundle.ciphertexts.length);
        const document = BallotTally.buildResultDocument({
            ballotId: closed.id, title: closed.title, definitionHash, bundleHash,
            combinedFingerprint: closed.combinedFingerprint, voterCount: closed.voterCount, tally: result
        });
        return { definition, result, document };
    }

    async function decryptMyLayer(ballot, status) {
        clear(status);
        if (loaded == null) {
            BallotShell.message(status, "error", "Bitte zuerst oben die Sicherung laden.");
            return;
        }
        try {
            const previous = await BallotApi.get("/api/keyholder/ballots/" + ballot.id + "/layers/" + ballot.myPosition);
            const envelopes = previous.items.map(BallotCrypto.fromBase64);
            const { outputs, failed } = await BallotCrypto.decryptLayerList(loaded.encryptionKey, ballot.id, envelopes);
            await BallotApi.send("PUT", "/api/keyholder/ballots/" + ballot.id + "/layers/" + (ballot.myPosition + 1), { items: outputs.map(BallotCrypto.toBase64) });
            render();
            if (failed > 0)
                BallotShell.message(status, "warn", failed + " Stimmzettel ließen sich nicht entschlüsseln und zählen als ungültig.");
        } catch (error) {
            BallotShell.message(status, "error", error.message);
        }
    }

    async function renderTallyTasks(item, ballot) {
        if (ballot.myPosition < 0)
            return;

        const status = el("div");
        const box = el("div");
        item.append(box, status);
        const holderCount = ballot.keyHolderCount;
        const closed = await BallotApi.get("/api/keyholder/ballots/" + ballot.id);
        const bundle = JSON.parse(closed.bundleJson);

        if (bundle.ciphertexts.length !== closed.voterCount)
            BallotShell.message(box, "error", "Zahl der Stimmzettel (" + bundle.ciphertexts.length + ") ≠ Zahl der Abstimmenden (" + closed.voterCount + "). Der Wahlgang ist ungültig.");

        if (ballot.layerCount <= ballot.myPosition) {
            box.append(el("p", { class: "muted" }, "Warte auf die Entschlüsselung durch " + closed.keyHolders[ballot.layerCount - 1].role + "."));
            return;
        }
        if (ballot.layerCount === ballot.myPosition + 1) {
            box.append(el("button", { class: "primary", onclick: () => decryptMyLayer(ballot, status) }, "Meine Schicht entschlüsseln"));
            return;
        }
        if (ballot.layerCount < holderCount + 1) {
            box.append(el("p", { class: "message ok" }, "Deine Schicht ist entschlüsselt. Warte auf die übrigen Personen."));
            return;
        }

        const computed = await computeResult(closed);
        box.append(renderTally(computed.definition, computed.result));

        if (closed.resultDocument == null) {
            if (ballot.myPosition === holderCount - 1) {
                box.append(el("button", {
                    class: "primary",
                    onclick: async () => {
                        try {
                            await BallotApi.send("PUT", "/api/keyholder/ballots/" + ballot.id + "/result", { document: computed.document });
                            render();
                        } catch (error) {
                            BallotShell.message(status, "error", error.message);
                        }
                    }
                }, "Ergebnis festschreiben"));
            } else {
                box.append(el("p", { class: "muted" }, "Warte darauf, dass " + closed.keyHolders[holderCount - 1].role + " das Ergebnis festschreibt."));
            }
            return;
        }

        if (closed.resultDocument !== computed.document) {
            BallotShell.message(box, "error", "Das festgeschriebene Ergebnis weicht von deiner eigenen Auszählung ab. NICHT unterschreiben.");
            return;
        }
        if (!ballot.iSigned) {
            box.append(el("button", {
                class: "primary",
                onclick: async () => {
                    clear(status);
                    if (loaded == null) {
                        BallotShell.message(status, "error", "Bitte zuerst oben die Sicherung laden.");
                        return;
                    }
                    try {
                        const signature = await BallotCrypto.sign(loaded.signingKey, closed.resultDocument);
                        await BallotApi.send("PUT", "/api/keyholder/ballots/" + ballot.id + "/signature", { signature });
                        render();
                    } catch (error) {
                        BallotShell.message(status, "error", error.message);
                    }
                }
            }, "Ergebnis prüfen und unterschreiben"));
            return;
        }

        box.append(el("p", { class: "message ok" }, "Du hast unterschrieben (" + ballot.signatureCount + " von " + holderCount + ")."));
        if (ballot.status === "Finished") {
            box.append(
                el("p", {}, "Nach Bekanntgabe des Ergebnisses: Veröffentlichungspaket und privaten Entschlüsselungsschlüssel herunterladen und an die Wahlleitung zur Veröffentlichung geben."),
                el("div", { class: "row" },
                    el("a", { class: "button", href: "/api/ballots/" + ballot.id + "/publication", download: "veroeffentlichung-" + ballot.id + ".json" }, "Veröffentlichungspaket"),
                    el("button", { onclick: () => exportDecryptionKey(status) }, "Privaten Entschlüsselungsschlüssel exportieren")));
        }
    }

    function exportDecryptionKey(status) {
        clear(status);
        if (loaded == null) {
            BallotShell.message(status, "error", "Bitte zuerst oben die Sicherung laden.");
            return;
        }
        const file = JSON.stringify({ format: "pp-ballot-decryption-key-v1", role: loaded.content.role, position: me.keyHolder.position, encryptionPrivateKey: loaded.content.encryptionPrivateKey });
        download("entschluesselung-" + loaded.content.role.replace(/[^A-Za-z0-9]+/g, "-") + ".json", file);
    }
```

In `renderBallots`, call `renderTallyTasks(item, ballot).catch(error => BallotShell.message(item, "error", error.message));` since it is now async.

Keys are a per-day set: `myPosition` and `keyHolderCount` come from the ballot snapshot, so a later change of the key holder list does not affect closed ballots.

- [ ] **Step 2: Verify syntax**

Run: `node --check SecretBallot.Server/wwwroot/js/schluessel.js`
Expected: no output.

---

### Task 10: Offline verifier

**Files:**
- Create: `wwwroot/pruefen.html`, `wwwroot/js/pruefen.js`, `wwwroot/js/verify.js`
- Test: `tests-js/verify.test.js`

**Interfaces:**
- Produces (global `BallotVerify`): `verifyPublication(publication, decryptionKeyFiles[]) -> Promise<{ checks: [{ label, ok, detail }], tally }>`, `findReceipt(publication, receipt) -> Promise<bool>`.

- [ ] **Step 1: Write the failing test**

`tests-js/verify.test.js` builds a complete publication in memory: generates 2 key holders (encryption + signing), encrypts 3 ballots against a definition, decrypts layer by layer with `decryptLayerList`, tallies, builds the result document, signs it with both signing keys, and assembles `{ id, title, definitionJson, bundleJson, combinedFingerprint, voterCount, keyHolders, layers, resultDocument, signatures }` exactly as `PublicationView` serializes (camelCase). Assertions:
```js
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
    return { publication, keyFiles, receipt: await C.sha256Hex(envelopes[0]) };
}

test("valid publication passes every check", async () => {
    const { publication, keyFiles } = await buildPublication();
    const report = await BallotVerify.verifyPublication(publication, keyFiles);
    assert.ok(report.checks.every(c => c.ok), JSON.stringify(report.checks.filter(c => !c.ok)));
    assert.deepEqual(report.tally.counts, [2, 1]);
});

test("tampered ciphertext is flagged", async () => {
    const { publication, keyFiles } = await buildPublication();
    const bytes = C.fromBase64(publication.layers[0][0]);
    bytes[300] ^= 1;
    publication.layers[0][0] = C.toBase64(bytes);
    const report = await BallotVerify.verifyPublication(publication, keyFiles);
    assert.ok(report.checks.some(c => !c.ok));
});

test("a missing signature fails", async () => {
    const { publication, keyFiles } = await buildPublication();
    publication.signatures[1] = publication.signatures[0];
    const report = await BallotVerify.verifyPublication(publication, keyFiles);
    assert.ok(report.checks.some(c => !c.ok && c.label.startsWith("Unterschrift")));
});

test("receipt lookup", async () => {
    const { publication, receipt } = await buildPublication();
    assert.ok(await BallotVerify.findReceipt(publication, receipt.substring(0, 16)));
    assert.equal(await BallotVerify.findReceipt(publication, "0000000000000000"), false);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test tests-js/`
Expected: FAIL, `Cannot find module '../SecretBallot.Server/wwwroot/js/verify.js'`.

- [ ] **Step 3: Implement `verify.js`**

```js
(function (root) {
    "use strict";

    function check(label, ok, detail) {
        return { label, ok, detail: detail || "" };
    }

    async function hashSet(items) {
        const hashes = await Promise.all(items.map(root.BallotCrypto.sha256Hex));
        return hashes.sort().join(",");
    }

    async function verifyLayers(publication, keyFiles, checks) {
        const C = root.BallotCrypto;
        const keys = keyFiles.map(text => JSON.parse(text));
        for (const holder of publication.keyHolders) {
            const file = keys.find(k => k.position === holder.position);
            if (!file) {
                checks.push(check("Schicht " + (holder.position + 1) + " (" + holder.role + ")", false, "privater Schlüssel fehlt"));
                continue;
            }
            const raw = await C.publicRawFromPrivateJwk(file.encryptionPrivateKey);
            if (C.toBase64(raw) !== holder.encryptionKey) {
                checks.push(check("Schicht " + (holder.position + 1) + " (" + holder.role + ")", false, "privater Schlüssel passt nicht zum registrierten öffentlichen Schlüssel"));
                continue;
            }
            const privateKey = await C.importEncryptionPrivateJwk(file.encryptionPrivateKey);
            const input = publication.layers[holder.position].map(C.fromBase64);
            const { outputs, failed } = await C.decryptLayerList(privateKey, publication.id, input);
            const expected = publication.layers[holder.position + 1].map(C.fromBase64);
            const same = await hashSet(outputs) === await hashSet(expected);
            checks.push(check("Schicht " + (holder.position + 1) + " (" + holder.role + ")", same && failed === 0,
                same ? (failed === 0 ? "nachgerechnet" : failed + " Einträge nicht entschlüsselbar") : "Ergebnis der Entschlüsselung weicht ab"));
        }
    }

    async function verifyPublication(publication, keyFiles) {
        const C = root.BallotCrypto;
        const T = root.BallotTally;
        const checks = [];
        const definition = JSON.parse(publication.definitionJson);
        const bundle = JSON.parse(publication.bundleJson);
        const definitionHash = await C.sha256Hex(C.utf8(publication.definitionJson));
        const bundleHash = await C.sha256Hex(C.utf8(publication.bundleJson));
        const rawKeys = publication.keyHolders.map(k => C.fromBase64(k.encryptionKey));

        checks.push(check("Fingerabdruck", await C.combinedFingerprint(publication.id, rawKeys) === publication.combinedFingerprint, publication.combinedFingerprint));
        checks.push(check("Paket gehört zum Wahlgang", bundle.ballot === publication.id && bundle.definition === publication.definitionJson));
        const bundleCiphertexts = await hashSet(bundle.ciphertexts.map(C.fromBase64));
        checks.push(check("Paket und Schicht 0 identisch", bundleCiphertexts === await hashSet(publication.layers[0].map(C.fromBase64))));
        checks.push(check("Stimmzettel = Abstimmende", bundle.ciphertexts.length === publication.voterCount, bundle.ciphertexts.length + " / " + publication.voterCount));
        const expectedSize = C.ciphertextSize(publication.keyHolders.length);
        checks.push(check("Einheitliche Größe der Stimmzettel", publication.layers[0].every(item => C.fromBase64(item).length === expectedSize), expectedSize + " Bytes"));

        await verifyLayers(publication, keyFiles, checks);

        const finalLayer = publication.layers[publication.keyHolders.length];
        const texts = finalLayer.map(item => {
            try {
                return C.decodePlaintext(C.fromBase64(item));
            } catch (error) {
                return "";
            }
        });
        const tally = T.tally(definition, definitionHash, texts, bundle.ciphertexts.length);
        const document = T.buildResultDocument({
            ballotId: publication.id, title: publication.title, definitionHash, bundleHash,
            combinedFingerprint: publication.combinedFingerprint, voterCount: publication.voterCount, tally
        });
        checks.push(check("Auszählung nachgerechnet", document === publication.resultDocument));

        for (const holder of publication.keyHolders) {
            const signature = publication.signatures[holder.position];
            const ok = signature != null && await C.verify(C.fromBase64(holder.signingKey), publication.resultDocument, signature);
            checks.push(check("Unterschrift " + holder.role, ok));
        }
        return { checks, tally, definition };
    }

    async function findReceipt(publication, receipt) {
        const C = root.BallotCrypto;
        const value = receipt.trim().toLowerCase().replace(/\s+/g, "");
        if (value.length < 8)
            return false;
        const hashes = await Promise.all(publication.layers[0].map(item => C.sha256Hex(C.fromBase64(item))));
        return hashes.some(hash => hash.startsWith(value));
    }

    const api = { verifyPublication, findReceipt };

    if (typeof module !== "undefined" && module.exports)
        module.exports = api;
    else
        root.BallotVerify = api;
})(globalThis);
```

The signed result document does not include the signing public keys; they are bound by the server's registration and confirmation step and published with the bundle. The verifier checks each signature against the published signing key of that position.

- [ ] **Step 4: Run tests**

Run: `node --test tests-js/`
Expected: all PASS.

- [ ] **Step 5: `pruefen.html` and `pruefen.js`**

`pruefen.html`: skeleton as `index.html`, title `Offline-Prüfung`, `<h1>Ergebnis prüfen</h1>`, a short intro paragraph ("Diese Seite funktioniert auch ohne Server: Ordner wwwroot aus dem Quellcode herunterladen und pruefen.html im Browser öffnen."), `<div id="content">`; scripts with RELATIVE paths `js/dom.js`, `js/ballot-crypto.js`, `js/ballot-tally.js`, `js/verify.js`, `js/pruefen.js` (no `api.js`/`shell.js`, so it works from `file://`). The `<link>` uses `css/app.css`.

`pruefen.js`:
```js
(function () {
    "use strict";
    const { el, clear, readFile } = BallotDom;
    const content = document.getElementById("content");
    const publicationInput = el("input", { type: "file", accept: ".json,application/json" });
    const keyInput = el("input", { type: "file", accept: ".json,application/json", multiple: true });
    const receiptInput = el("input", { type: "text", placeholder: "Quittung (optional)" });
    const output = el("div");
    const run = el("button", { class: "primary" }, "Prüfen");

    function optionList(definition, indices) {
        return indices.length === 0 ? "niemand" : indices.map(i => definition.options[i]).join(", ");
    }

    run.addEventListener("click", async () => {
        clear(output);
        run.disabled = true;
        try {
            const publication = JSON.parse(await readFile(publicationInput));
            const keyFiles = await Promise.all(Array.from(keyInput.files).map(file => file.text()));
            const report = await BallotVerify.verifyPublication(publication, keyFiles);
            output.append(el("ul", { class: "plain" }, report.checks.map(c =>
                el("li", { class: "message " + (c.ok ? "ok" : "error") }, (c.ok ? "OK: " : "FEHLER: ") + c.label + (c.detail ? " (" + c.detail + ")" : "")))));
            const t = report.tally;
            output.append(el("section", {}, el("h2", {}, publication.title),
                el("p", {}, "gültig " + t.validCount + " · ungültig " + t.invalidCount + " · leer " + t.emptyCount),
                el("ul", {}, report.definition.options.map((o, i) => el("li", {}, o + ": " + t.counts[i]))),
                el("p", {}, "Mit leeren Stimmzetteln in der Basis: " + optionList(report.definition, t.withEmpty.elected)),
                el("p", {}, "Ohne leere Stimmzettel in der Basis: " + optionList(report.definition, t.withoutEmpty.elected))));
            if (receiptInput.value.trim().length > 0) {
                const found = await BallotVerify.findReceipt(publication, receiptInput.value);
                output.append(el("p", { class: "message " + (found ? "ok" : "error") }, found ? "Quittung gefunden." : "Quittung NICHT gefunden."));
            }
            if (keyFiles.length === 0)
                output.append(el("p", { class: "message warn" }, "Ohne private Schlüssel wurden die Entschlüsselungsschichten nicht nachgerechnet."));
        } catch (error) {
            output.append(el("p", { class: "message error" }, "Prüfung fehlgeschlagen: " + error.message));
        }
        run.disabled = false;
    });

    content.append(el("section", {},
        el("label", {}, "Veröffentlichungspaket (veroeffentlichung-….json)", publicationInput),
        el("label", {}, "Private Entschlüsselungsschlüssel (alle entschluesselung-….json)", keyInput),
        el("label", {}, "Eigene Quittung", receiptInput),
        el("div", { class: "row" }, run)), output);
})();
```

- [ ] **Step 6: Verify**

Run: `node --test tests-js/ && node --check SecretBallot.Server/wwwroot/js/pruefen.js`
Expected: all PASS, no syntax output.

---

### Task 11: Cross-language fingerprint check

**Files:**
- Create: `SecretBallot.Server.Tests/Election/CrossLanguageTests.cs`

This exercises the real browser code path (crypto + tally + verify) against the real server state machine without OIDC, by driving `ElectionState` through TUnit and the JS through Node. Both halves already have tests; this task adds the one cross-language check that matters: the server's bundle JSON and combined fingerprint agree with the JS side.

- [ ] **Step 1: TUnit test emitting a fixture**

Add `SecretBallot.Server.Tests/Election/CrossLanguageTests.cs`:
```csharp
using SecretBallot.Server.Election;

namespace SecretBallot.Server.Tests.Election;

public class CrossLanguageTests {
    [Test]
    public async Task Combined_fingerprint_matches_known_vector() {
        var key = Convert.FromBase64String("BGsX0fLhLEJH+Lzm5WOkQPJ3A+eTiAoO4zXDOfbVhqDXgSeGG7nrdV5FkJVmXFWnSXkm7Ca/ptQIsjPbpuRHxGc=");
        var id = Guid.Parse("6f0c3c1e-6c55-4b0e-9a57-1f2f9a0c9d11");
        await Assert.That(CryptoFormats.CombinedFingerprint(id, new[] { key })).IsEqualTo(ExpectedCombined);
    }
}
```
with `Expected.CombinedFingerprint` replaced by a `private const string ExpectedCombined` holding the value printed by:
`node -e 'const C=require("./SecretBallot.Server/wwwroot/js/ballot-crypto.js");C.combinedFingerprint("6f0c3c1e-6c55-4b0e-9a57-1f2f9a0c9d11",[C.fromBase64("BGsX0fLhLEJH+Lzm5WOkQPJ3A+eTiAoO4zXDOfbVhqDXgSeGG7nrdV5FkJVmXFWnSXkm7Ca/ptQIsjPbpuRHxGc=")]).then(console.log)'`
Also assert `CryptoFormats.Fingerprint(key)` equals the output of `C.fingerprint(...)` the same way.

- [ ] **Step 2: Run both**

Run: `node --test tests-js/ && dotnet build -m:1 SecretBallot.slnx && dotnet run --no-build --project SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj`
Expected: all PASS.

---

### Task 12: Documentation and deployment notes

**Files:**
- Create: `docs/how-it-works.md` (English), `docs/schluesselhalter.md` (German), `docs/pruefen.md` (German), `docs/deployment.md` (English)
- Create: `tools/wwwroot-hashes.sh`

Markdown rules: one paragraph per line, no hard wraps, no em or en dashes, no tables (aligned plain text in code blocks instead).

- [ ] **Step 1: `tools/wwwroot-hashes.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../SecretBallot.Server/wwwroot"
find . -type f | LC_ALL=C sort | xargs sha256sum
```
`chmod +x tools/wwwroot-hashes.sh`

- [ ] **Step 2: `docs/how-it-works.md`** with sections: Purpose; Roles (admin, key holders 1..N with the leader flag, voters, server operator, observers) and the separation-of-duties rule; What each party learns (from spec section 4, generalized to N); Cryptography (constants from Global Constraints, layer order, sizes `512 + N * 94`, fingerprints, receipts, backup); Data flow step by step (setup, key registration and confirmation, opening and fingerprint read-out, casting with the separate `voted` set and `ciphertexts` list naming `ElectionState.Cast`, closing and hash sort naming `ElectionState.Close`, bulletin, layer-by-layer decryption, tally rules including both majority bases, result document and signatures, publication); Why secrecy holds (server never sees plaintext; key holders never see identities; publishing private keys is safe because no voter link exists); Restart behaviour (everything lost, open ballot void, key holders re-register from backup); Residual risks (spec section 11, plus N = 1 note); File map (which file does what, both C# and JS).

- [ ] **Step 3: `docs/schluesselhalter.md`** (German, du-form) with: Vorbereitung (eigener Rechner, aktueller Browser, sicherer Ort für die Sicherungsdatei, starkes Passwort, nicht Serverbetrieb); Schritt für Schritt: anmelden, Schlüssel erzeugen, Sicherung prüfen, Fingerabdrücke vergleichen und bestätigen; Nach einem Server-Neustart: Sicherung laden; Für die Wahlleitung: Fingerabdruck vorlesen, öffnen, schließen, öffentliche Liste ansagen, Einspruchsfrist (10 Minuten); Auszählung: Sicherung laden, eigene Schicht entschlüsseln (Reihenfolge), Ergebnis prüfen, letzte Person schreibt fest, alle unterschreiben; Veröffentlichung: Paket und privaten Entschlüsselungsschlüssel an die Wahlleitung; Was tun wenn: Fingerabdruck weicht ab, Zahl der Stimmzettel weicht ab, Quittung fehlt, Sicherung verloren (Wahlgang ungültig).

- [ ] **Step 4: `docs/pruefen.md`** (German) with: Quittung aufheben und auf der öffentlichen Liste suchen; Fingerabdruck vor dem Abstimmen vergleichen; Ergebnis nachrechnen mit `pruefen.html` (online oder offline aus dem Quellcode), welche Dateien man braucht, was jede Prüfzeile bedeutet; Prüfsummen der ausgelieferten Dateien mit der veröffentlichten Liste vergleichen (`sha256sum`).

- [ ] **Step 5: `docs/deployment.md`** (English) with: Keycloak client (confidential, standard flow, redirect URI `https://<host>/signin-oidc`, service account with realm-management `view-users`, scope `profile`); configuration keys and `SecretBallot__ClientSecret` env var; `AdminUsernames`; build and publish (`dotnet publish SecretBallot.Server -c Release -o /opt/secret-ballot`); systemd unit (`DynamicUser=yes`, `LimitCORE=0`, `MemoryDenyWriteExecute` not set because of the JIT, `PrivateTmp=yes`, `ProtectSystem=strict`, `Environment=ASPNETCORE_URLS=http://127.0.0.1:5180`); nginx snippet with TLS, HSTS, `proxy_set_header X-Forwarded-Proto $scheme`, `location ~ ^/api/ballots/.*/votes$ { access_log off; proxy_pass ... }` and `error_log` level `crit` for that location, request body logging disabled; swap off (`swapoff -a`) on the host for the event; publishing the hash list (`tools/wwwroot-hashes.sh`) and the source before the event; the separation-of-duties rule for operators; test checklist from spec section 13 adapted to N.

- [ ] **Step 6: Sweep**

Re-read every file in the diff against the Global Constraints: comments, `if` formatting, German UI strings, no em/en dashes in docs (`grep -rnP '\x{2013}|\x{2014}' docs SecretBallot.Server/wwwroot` must be empty), no hard wraps in Markdown.

---

## Self-review notes

- Spec coverage: eligibility live check (Task 4), one vote per subject (Task 3), N key holders with leader flag (Task 3/7/8), browser key generation with verified backup before registration (Task 7), per-holder confirmation and combined fingerprint (Task 3/6/7), fixed size padding and layered encryption (Task 1), receipt (Task 6), separate collections and hash-sorted export (Task 3), voter count check (Task 3/6/9/10), bulletin (Task 6), async layer decryption (Task 9), § 7 tally with both bases (Task 2), signed result document (Task 3/9), offline verifier (Task 10), hardening (Task 4 headers + Task 12 deployment), documentation (Task 12).
- Not covered on purpose: a CLI verifier (spec says optional), server-signed bundle (spec "later").
