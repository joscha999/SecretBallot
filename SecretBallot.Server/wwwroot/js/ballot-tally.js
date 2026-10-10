(function (root) {
    "use strict";

    function parse(text) {
        try {
            return JSON.parse(text);
        } catch (error) {
            return null;
        }
    }

    function hasValidIndices(choice, optionCount) {
        if (!Array.isArray(choice))
            return false;
        if (!choice.every(index => Number.isInteger(index) && index >= 0 && index < optionCount))
            return false;
        return new Set(choice).size === choice.length;
    }

    function validatePlaintext(text, definition, definitionHash) {
        const data = parse(text);
        if (data == null || typeof data !== "object")
            return { valid: false, reason: "kein gültiges JSON" };
        if (data.v !== 1)
            return { valid: false, reason: "unbekannte Version" };
        if (data.ballot !== definition.id)
            return { valid: false, reason: "falscher Wahlgang" };
        if (data.def !== definitionHash)
            return { valid: false, reason: "falsche Wahlgang-Definition" };
        if (!hasValidIndices(data.choice, definition.options.length))
            return { valid: false, reason: "ungültige Auswahl" };
        if (definition.type !== "approval" && data.choice.length > 1)
            return { valid: false, reason: "mehr als eine Auswahl" };
        return { valid: true, choice: data.choice };
    }

    function approvalOutcome(counts, seats, base) {
        const majority = counts
            .map((count, index) => ({ index, count }))
            .filter(entry => entry.count * 2 > base)
            .sort((a, b) => b.count - a.count || a.index - b.index);

        if (majority.length <= seats)
            return { base, elected: majority.map(e => e.index), tied: [], seatsUnfilled: seats - majority.length };

        const cutoff = majority[seats - 1].count;
        if (majority[seats].count < cutoff)
            return { base, elected: majority.slice(0, seats).map(e => e.index), tied: [], seatsUnfilled: 0 };

        const above = majority.filter(e => e.count > cutoff).map(e => e.index);
        const tied = majority.filter(e => e.count === cutoff).map(e => e.index);
        return { base, elected: above, tied, seatsUnfilled: seats - above.length };
    }

    function singleOutcome(counts, noneOptionIndex, base) {
        const winner = counts.findIndex(count => count * 2 > base);
        if (winner < 0 || winner === noneOptionIndex)
            return { base, elected: [], tied: [], seatsUnfilled: 1 };
        return { base, elected: [winner], tied: [], seatsUnfilled: 0 };
    }

    function yesNoOutcome(counts, base) {
        if (counts[0] > counts[1])
            return { base, elected: [0], tied: [], seatsUnfilled: 0 };
        return { base, elected: [], tied: [], seatsUnfilled: 1 };
    }

    function outcome(definition, counts, base) {
        if (definition.type === "approval")
            return approvalOutcome(counts, definition.seats, base);
        if (definition.type === "single")
            return singleOutcome(counts, definition.noneOptionIndex, base);
        return yesNoOutcome(counts, base);
    }

    function tally(definition, definitionHash, plaintextTexts, ciphertextCount) {
        const counts = definition.options.map(() => 0);
        const invalidReasons = [];
        let validCount = 0;
        let emptyCount = 0;

        for (const text of plaintextTexts) {
            const check = validatePlaintext(text, definition, definitionHash);
            if (!check.valid) {
                invalidReasons.push(check.reason);
                continue;
            }

            validCount++;
            if (check.choice.length === 0)
                emptyCount++;
            for (const index of check.choice)
                counts[index]++;
        }

        return {
            ciphertextCount,
            validCount,
            invalidCount: ciphertextCount - validCount,
            emptyCount,
            counts,
            invalidReasons,
            withEmpty: outcome(definition, counts, validCount),
            withoutEmpty: outcome(definition, counts, validCount - emptyCount)
        };
    }

    function outcomeDocument(value) {
        return { base: value.base, elected: value.elected, tied: value.tied, seatsUnfilled: value.seatsUnfilled };
    }

    function buildResultDocument(input) {
        const t = input.tally;
        return JSON.stringify({
            v: 1,
            ballot: input.ballotId,
            title: input.title,
            definitionHash: input.definitionHash,
            bundleHash: input.bundleHash,
            combinedFingerprint: input.combinedFingerprint,
            voterCount: input.voterCount,
            ciphertextCount: t.ciphertextCount,
            validCount: t.validCount,
            invalidCount: t.invalidCount,
            emptyCount: t.emptyCount,
            counts: t.counts,
            withEmpty: outcomeDocument(t.withEmpty),
            withoutEmpty: outcomeDocument(t.withoutEmpty)
        });
    }

    const api = { validatePlaintext, tally, buildResultDocument };

    if (typeof module !== "undefined" && module.exports)
        module.exports = api;
    else
        root.BallotTally = api;
})(globalThis);
