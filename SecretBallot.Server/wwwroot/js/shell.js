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
