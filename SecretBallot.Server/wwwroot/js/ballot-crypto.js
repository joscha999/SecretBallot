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
