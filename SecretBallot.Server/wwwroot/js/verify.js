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
        const keys = await Promise.all(keyFiles.map(async text => {
            const file = JSON.parse(text);
            return { file, publicKey: C.toBase64(await C.publicRawFromPrivateJwk(file.encryptionPrivateKey)) };
        }));
        for (const holder of publication.keyHolders) {
            const match = keys.find(k => k.publicKey === holder.encryptionKey);
            if (!match) {
                checks.push(check("Schicht " + (holder.position + 1) + " (" + holder.role + ")", false, "passender privater Schlüssel fehlt"));
                continue;
            }
            const file = match.file;
            const privateKey = await C.importEncryptionPrivateJwk(file.encryptionPrivateKey);
            const input = publication.layers[holder.position].map(C.fromBase64);
            const { outputs, failed } = await C.decryptLayerList(privateKey, publication.id, input);
            const expected = publication.layers[holder.position + 1].map(C.fromBase64);
            const same = await hashSet(outputs) === await hashSet(expected);
            checks.push(check("Schicht " + (holder.position + 1) + " (" + holder.role + ")", same && failed === 0,
                same ? (failed === 0 ? "nachgerechnet" : failed + " Einträge nicht entschlüsselbar") : "Ergebnis der Entschlüsselung weicht ab"));
        }
    }

    function normalizeFingerprint(text) {
        return (text || "").toLowerCase().replace(/[^0-9a-f]/g, "");
    }

    async function verifyPublication(publication, keyFiles, readOutFingerprint) {
        const C = root.BallotCrypto;
        const T = root.BallotTally;
        const checks = [];
        const definition = JSON.parse(publication.definitionJson);
        const bundle = JSON.parse(publication.bundleJson);
        const definitionHash = await C.sha256Hex(C.utf8(publication.definitionJson));
        const bundleHash = await C.sha256Hex(C.utf8(publication.bundleJson));
        const rawKeys = publication.keyHolders.map(k => C.fromBase64(k.encryptionKey));

        const computedFingerprint = await C.combinedFingerprint(publication.id, rawKeys);
        checks.push(check("Fingerabdruck passt zu den Schlüsseln", computedFingerprint === publication.combinedFingerprint, computedFingerprint));
        const readOut = normalizeFingerprint(readOutFingerprint);
        checks.push(check("Vorgelesener Fingerabdruck", readOut.length > 0 && readOut === normalizeFingerprint(computedFingerprint),
            readOut.length > 0 ? "" : "bitte den vorgelesenen Fingerabdruck aus dem Wahlprotokoll eintragen"));
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
        const resultDocumentHash = await C.sha256Hex(C.utf8(publication.resultDocument));
        const signingFingerprints = await Promise.all(publication.keyHolders.map(async holder =>
            ({ role: holder.role, fingerprint: await C.fingerprint(C.fromBase64(holder.signingKey)) })));
        return { checks, tally, definition, resultDocumentHash, signingFingerprints };
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
