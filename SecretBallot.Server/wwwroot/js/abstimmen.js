(function () {
    "use strict";
    const { el, clear } = BallotDom;
    const content = document.getElementById("content");
    const PENDING_PREFIX = "sb-stimmzettel-";
    let pollTimer = null;
    let me = null;

    // Only the encrypted envelope and the receipt are stored, never the choice; a retry must resend the very same envelope or the receipt would not match the bulletin.
    function loadPending(ballotId) {
        try {
            const text = localStorage.getItem(PENDING_PREFIX + ballotId);
            return text ? JSON.parse(text) : null;
        } catch (error) {
            return null;
        }
    }

    function savePending(pending) {
        try {
            localStorage.setItem(PENDING_PREFIX + pending.ballotId, JSON.stringify(pending));
        } catch (error) {
            return;
        }
    }

    function forgetPending(ballotId) {
        try {
            localStorage.removeItem(PENDING_PREFIX + ballotId);
        } catch (error) {
            return;
        }
    }

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
        clearTimeout(pollTimer);
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
        pollTimer = setTimeout(render, 5000);
    }

    async function send(pending, status, button) {
        button.disabled = true;
        clear(status);
        BallotShell.message(status, "info", "Stimmzettel wird gesendet …");
        try {
            await BallotApi.send("POST", "/api/ballots/" + pending.ballotId + "/votes", { ciphertext: pending.envelope });
            renderReceipt(pending.receipt, null);
        } catch (error) {
            if (error.status === 409 && /bereits abgestimmt/.test(error.message)) {
                renderReceipt(pending.receipt, "Der Server meldet, dass deine Stimme bereits angekommen ist. Dies ist die Quittung des gesendeten Stimmzettels.");
                return;
            }
            if (error.status === 409) {
                renderReceipt(pending.receipt, "Der Wahlgang ist nicht mehr geöffnet. Prüfe auf der öffentlichen Liste, ob diese Quittung enthalten ist; nur dann wurde deine Stimme gezählt.");
                return;
            }
            if (error.status === 400 || error.status === 403) {
                forgetPending(pending.ballotId);
                clear(status);
                BallotShell.message(status, "error", error.message);
                status.append(el("button", { type: "button", onclick: () => render() }, "Zurück zum Stimmzettel"));
                return;
            }
            renderRetry(pending, error.message);
        }
    }

    function renderRetry(pending, errorText) {
        clearTimeout(pollTimer);
        clear(content);
        const status = el("div");
        const button = el("button", { type: "button", class: "primary" }, "Erneut senden");
        button.addEventListener("click", () => send(pending, status, button));
        content.append(el("section", {},
            el("h2", {}, "Abgabe noch nicht bestätigt"),
            errorText ? el("p", { class: "message error" }, errorText) : null,
            el("p", {}, "Dein Stimmzettel ist verschlüsselt, aber der Server hat die Abgabe noch nicht bestätigt. Sende denselben Stimmzettel erneut; deine Auswahl lässt sich dabei nicht mehr ändern."),
            el("p", {}, "Quittung: ", el("span", { class: "mono" }, pending.receipt)),
            el("div", { class: "row" }, button),
            status));
    }

    async function cast(current, definitionHash, choice, status, button) {
        button.disabled = true;
        clear(status);
        BallotShell.message(status, "info", "Stimmzettel wird verschlüsselt …");
        let pending;
        try {
            const keys = await Promise.all(current.keyHolders.map(k => BallotCrypto.importEncryptionPublicKey(BallotCrypto.fromBase64(k.encryptionKey))));
            const plaintext = BallotCrypto.buildPlaintext(current.id, definitionHash, choice);
            const envelope = await BallotCrypto.encryptBallot(keys, current.id, plaintext);
            pending = { ballotId: current.id, envelope: BallotCrypto.toBase64(envelope), receipt: await BallotCrypto.sha256Hex(envelope) };
        } catch (error) {
            clear(status);
            BallotShell.message(status, "error", "Verschlüsseln fehlgeschlagen: " + error.message);
            button.disabled = false;
            return;
        }
        savePending(pending);
        await send(pending, status, button);
    }

    function renderConfirm(current, definition, definitionHash, choice, form) {
        const status = el("div");
        const back = el("button", { type: "button", onclick: () => render() }, "Zurück");
        const submit = el("button", { type: "button", class: "primary" }, "Jetzt verbindlich abgeben");
        submit.addEventListener("click", () => cast(current, definitionHash, choice, status, submit));
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
        const pending = loadPending(response.ballot.id);
        if (response.hasVoted && pending != null) {
            renderReceipt(pending.receipt, "Du hast in diesem Wahlgang bereits abgestimmt.");
            return;
        }
        if (response.hasVoted) {
            BallotShell.message(content, "ok", "Du hast in diesem Wahlgang bereits abgestimmt. Die Quittung ist in diesem Browser nicht gespeichert.");
            pollTimer = setTimeout(render, 5000);
            return;
        }
        if (pending != null) {
            renderRetry(pending, null);
            return;
        }
        await renderBallot(response.ballot);
    }

    BallotShell.init("abstimmen").then(result => {
        me = result;
        render();
    });
})();
