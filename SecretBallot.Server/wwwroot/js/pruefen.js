(function () {
    "use strict";
    const { el, clear, readFile } = BallotDom;
    const content = document.getElementById("content");
    const publicationInput = el("input", { type: "file", accept: ".json,application/json" });
    const keyInput = el("input", { type: "file", accept: ".json,application/json", multiple: true });
    const receiptInput = el("input", { type: "text", placeholder: "Quittung (optional)" });
    const fingerprintInput = el("input", { type: "text", placeholder: "z. B. 0bef 8ab0 4984 f198 9f06 e5ec 8538 4f4b" });
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
            const report = await BallotVerify.verifyPublication(publication, keyFiles, fingerprintInput.value);
            output.append(el("ul", { class: "plain" }, report.checks.map(c =>
                el("li", { class: "message " + (c.ok ? "ok" : "error") }, (c.ok ? "OK: " : "FEHLER: ") + c.label + (c.detail ? " (" + c.detail + ")" : "")))));
            output.append(el("section", {}, el("h2", {}, "Mit dem Wahlprotokoll vergleichen"),
                el("p", {}, "Prüfsumme des Ergebnisdokuments: ", el("span", { class: "mono" }, report.resultDocumentHash)),
                el("ul", {}, report.signingFingerprints.map(f => el("li", {}, "Signaturschlüssel " + f.role + ": ", el("span", { class: "mono" }, f.fingerprint))))));
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
        el("label", {}, "Vorgelesener Fingerabdruck des Wahlgangs (aus Stream, Mumble oder Wahlprotokoll)", fingerprintInput),
        el("label", {}, "Eigene Quittung", receiptInput),
        el("div", { class: "row" }, run)), output);
})();
