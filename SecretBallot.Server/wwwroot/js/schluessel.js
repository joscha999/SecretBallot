(function () {
    "use strict";
    const { el, clear, download, readFile } = BallotDom;
    const content = document.getElementById("content");
    const MIN_PASSWORD_LENGTH = 12;
    let me = null;
    let loaded = null;
    let notice = null;

    function notify(kind, text) {
        notice = { kind, text };
    }

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
                if (me.keyHolder != null && me.keyHolder.encryptionKey == null) {
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

    function renderReRegister(section) {
        const status = el("div");
        const button = el("button", { class: "primary" }, "Geladene Schlüssel erneut registrieren");
        button.addEventListener("click", async () => {
            try {
                await registerAndConfirm(loaded, status);
            } catch (error) {
                BallotShell.message(status, "error", error.message);
            }
        });
        section.append(
            el("h2", {}, "Schlüssel nicht registriert"),
            el("p", {}, "Der Server kennt deine Schlüssel nicht (mehr), zum Beispiel nach einem Neustart. Die Schlüssel aus der geladenen Sicherung können erneut registriert werden."),
            el("div", { class: "row" }, button), status);
    }

    function renderKeySection() {
        const holder = me.keyHolder;
        const section = el("section");
        content.append(section);
        if (holder.encryptionKey == null) {
            if (loaded != null) {
                renderReRegister(section);
                return;
            }
            renderGenerate(section);
            content.append(el("section", {}, renderLoadBackupInto("Nach einem Neustart des Servers: vorhandene Sicherung laden, um die Schlüssel erneut zu registrieren.")));
            return;
        }
        if (loaded != null && !serverHasKeys(loaded)) {
            BallotShell.message(section, "warn", "Die geladene Sicherung passt nicht zu den auf dem Server registrierten Schlüsseln. Bitte die richtige Sicherungsdatei laden.");
            loaded = null;
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
        const section = el("section", {}, el("h2", {}, "Wahlgänge"),
            el("div", { class: "row" }, el("button", { onclick: () => render() }, "Aktualisieren")));
        content.append(section);
        if (ballots.some(b => b.keyHolderCount === 1))
            BallotShell.message(section, "warn", "Es gibt nur eine schlüsselhaltende Person. Sie kann alle Stimmzettel lesen, aber nicht zuordnen.");
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
                renderTallyTasks(item, ballot).catch(error => BallotShell.message(item, "error", error.message));
        }
    }

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

    async function uploadLayer(ballot, outputs, failed, status) {
        try {
            await BallotApi.send("PUT", "/api/keyholder/ballots/" + ballot.id + "/layers/" + (ballot.myPosition + 1), { items: outputs.map(BallotCrypto.toBase64) });
            if (failed > 0)
                notify("warn", failed + " Stimmzettel ließen sich nicht entschlüsseln und zählen als ungültig.");
            render();
        } catch (error) {
            BallotShell.message(status, "error", error.message);
        }
    }

    async function decryptMyLayer(ballot, expectedKey, status, button) {
        clear(status);
        if (loaded == null) {
            BallotShell.message(status, "error", "Bitte zuerst oben die Sicherung laden.");
            return;
        }
        if (BallotCrypto.toBase64(loaded.encryptionRaw) !== expectedKey) {
            BallotShell.message(status, "error", "Die geladene Sicherung gehört nicht zu den Schlüsseln, mit denen dieser Wahlgang verschlüsselt wurde. Bitte die richtige Sicherungsdatei laden.");
            return;
        }
        button.disabled = true;
        try {
            const previous = await BallotApi.get("/api/keyholder/ballots/" + ballot.id + "/layers/" + ballot.myPosition);
            const envelopes = previous.items.map(BallotCrypto.fromBase64);
            const { outputs, failed } = await BallotCrypto.decryptLayerList(loaded.encryptionKey, ballot.id, envelopes);
            if (failed === 0) {
                await uploadLayer(ballot, outputs, failed, status);
                return;
            }
            BallotShell.message(status, "warn", failed + " von " + envelopes.length + " Stimmzetteln ließen sich nicht entschlüsseln. Sie zählen als ungültig. Das Hochladen kann nicht rückgängig gemacht werden; bei mehr als einzelnen Fällen erst mit der Wahlleitung sprechen.");
            status.append(el("button", { onclick: () => uploadLayer(ballot, outputs, failed, status) }, "Trotzdem hochladen"));
        } catch (error) {
            BallotShell.message(status, "error", error.message);
            button.disabled = false;
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
            const decrypt = el("button", { class: "primary" }, "Meine Schicht entschlüsseln");
            decrypt.addEventListener("click", () => decryptMyLayer(ballot, closed.keyHolders[ballot.myPosition].encryptionKey, status, decrypt));
            box.append(decrypt);
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
                el("p", { class: "message warn" }, "Exportiere deinen privaten Schlüssel erst, wenn heute kein weiterer Wahlgang mit diesen Schlüsseln mehr kommt (z. B. eine Stichwahl). Beim Export werden deine Schlüssel stillgelegt; für weitere Wahlgänge brauchst du neue Schlüssel und eine neue Sicherung."),
                el("div", { class: "row" },
                    el("a", { class: "button", href: "/api/ballots/" + ballot.id + "/publication", download: "veroeffentlichung-" + ballot.id + ".json" }, "Veröffentlichungspaket"),
                    el("button", { onclick: () => exportDecryptionKey(ballot, closed.keyHolders[ballot.myPosition].encryptionKey, status) }, "Privaten Schlüssel exportieren und stilllegen")));
        }
    }

    async function exportDecryptionKey(ballot, expectedKey, status) {
        clear(status);
        if (loaded == null || BallotCrypto.toBase64(loaded.encryptionRaw) !== expectedKey) {
            BallotShell.message(status, "error", "Bitte zuerst oben die Sicherung mit den Schlüsseln dieses Wahlgangs laden.");
            return;
        }
        if (me.keyHolder != null && me.keyHolder.encryptionKey === expectedKey) {
            try {
                await BallotApi.send("POST", "/api/keyholder/retire");
            } catch (error) {
                BallotShell.message(status, "error", error.message);
                return;
            }
        }
        const file = JSON.stringify({ format: "pp-ballot-decryption-key-v1", role: loaded.content.role, position: ballot.myPosition, encryptionPrivateKey: loaded.content.encryptionPrivateKey });
        download("entschluesselung-" + loaded.content.role.replace(/[^A-Za-z0-9]+/g, "-") + ".json", file);
        loaded = null;
        notify("ok", "Privater Schlüssel exportiert und stillgelegt. Verwende die alte Sicherungsdatei nicht mehr; für weitere Wahlgänge neue Schlüssel erzeugen.");
        render();
    }

    async function render() {
        try {
            await refreshMe();
        } catch (error) {
            BallotShell.message(content, "error", error.message);
            return;
        }
        clear(content);
        if (notice != null) {
            BallotShell.message(content, notice.kind, notice.text);
            notice = null;
        }
        if (!me.loggedIn) {
            BallotShell.message(content, "info", "Bitte oben mit dem Piratenlogin anmelden.");
            return;
        }
        if (me.keyHolder == null) {
            BallotShell.message(content, "info", "Du bist derzeit nicht als schlüsselhaltende Person eingetragen. Wahlgänge, an denen du beteiligt warst, kannst du unten weiter bearbeiten.");
            if (loaded == null)
                content.append(el("section", {}, renderLoadBackupInto("Für Entschlüsseln und Unterschreiben bitte die Sicherung laden.")));
        } else {
            renderHeader();
            renderKeySection();
        }
        try {
            await renderBallots();
        } catch (error) {
            BallotShell.message(content, "error", error.message);
        }
    }

    BallotShell.init("schluessel").then(render);
})();
