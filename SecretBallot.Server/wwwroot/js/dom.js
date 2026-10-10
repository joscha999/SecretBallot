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
