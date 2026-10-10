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
        const options = { method, credentials: "same-origin", headers: { "Accept": "application/json", "X-Secret-Ballot": "1" } };
        if (body !== undefined) {
            options.headers["Content-Type"] = "application/json";
            options.body = JSON.stringify(body);
        }
        let response;
        try {
            response = await fetch(url, options);
        } catch (error) {
            throw new ApiError(0, "Keine Verbindung zum Server. Bitte gleich noch einmal versuchen.");
        }
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
