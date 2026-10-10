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
