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
