"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const BallotTally = require("../SecretBallot.Server/wwwroot/js/ballot-tally.js");

const approval = { id: "b1", title: "Beisitzer", type: "approval", options: ["Anna", "Bert", "Cem"], seats: 2, noneOptionIndex: -1 };
const single = { id: "b2", title: "Stichwahl", type: "single", options: ["Anna", "Bert", "keinen der Kandidierenden"], seats: 1, noneOptionIndex: 2 };
const yesNo = { id: "b3", title: "Frage", type: "yesno", options: ["Ja", "Nein"], seats: 1, noneOptionIndex: -1 };

function ballot(definition, choice, overrides) {
    return JSON.stringify(Object.assign({ v: 1, ballot: definition.id, def: "h", choice, nonce: "00" }, overrides || {}));
}

function run(definition, choices) {
    const texts = choices.map(c => ballot(definition, c));
    return BallotTally.tally(definition, "h", texts, texts.length);
}

test("two seats filled by absolute majority in order of approvals", () => {
    const result = run(approval, [[0, 1], [0, 1], [0], [1, 2]]);
    assert.deepEqual(result.counts, [3, 3, 1]);
    assert.deepEqual(result.withEmpty.elected, [0, 1]);
    assert.equal(result.withEmpty.seatsUnfilled, 0);
});

test("one seat filled, second unfilled", () => {
    const result = run(approval, [[0], [0], [0, 1], [2]]);
    assert.deepEqual(result.withEmpty.elected, [0]);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("tie at the cut-off is reported, not decided", () => {
    const result = run(approval, [[0, 1, 2], [0, 1, 2], [0, 1, 2], [0]]);
    assert.deepEqual(result.withEmpty.elected, [0]);
    assert.deepEqual(result.withEmpty.tied, [1, 2]);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("nobody reaches a majority", () => {
    const result = run(approval, [[0], [1], [2], []]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.equal(result.withEmpty.seatsUnfilled, 2);
});

test("all ballots empty elects nobody in both bases", () => {
    const result = run(approval, [[], [], []]);
    assert.equal(result.emptyCount, 3);
    assert.equal(result.withoutEmpty.base, 0);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.deepEqual(result.withoutEmpty.elected, []);
});

test("empty ballots change the majority base", () => {
    const result = run(approval, [[0], [0], [], []]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.deepEqual(result.withoutEmpty.elected, [0]);
});

test("single choice won by none-of-them elects nobody", () => {
    const result = run(single, [[2], [2], [0]]);
    assert.deepEqual(result.withEmpty.elected, []);
    assert.equal(result.withEmpty.seatsUnfilled, 1);
});

test("single choice winner with majority", () => {
    const result = run(single, [[1], [1], [0]]);
    assert.deepEqual(result.withEmpty.elected, [1]);
});

test("yes/no accepted when yes beats no", () => {
    const result = run(yesNo, [[0], [0], [1], []]);
    assert.deepEqual(result.withEmpty.elected, [0]);
});

test("invalid plaintexts are counted with reasons", () => {
    const texts = [
        ballot(approval, [0]),
        ballot(approval, [0], { ballot: "other" }),
        ballot(approval, [0], { def: "x" }),
        ballot(approval, [5]),
        ballot(approval, [0, 0]),
        "{kaputt",
        ballot(single, [0, 1])
    ];
    const result = BallotTally.tally(approval, "h", texts, texts.length + 1);
    assert.equal(result.validCount, 1);
    assert.equal(result.invalidCount, 7);
    assert.equal(result.invalidReasons.length, 6);
});

test("single choice with two marks is invalid", () => {
    const check = BallotTally.validatePlaintext(ballot(single, [0, 1]), single, "h");
    assert.equal(check.valid, false);
});

test("result document is deterministic", () => {
    const tallyResult = run(approval, [[0]]);
    const input = { ballotId: "b1", title: "Beisitzer", definitionHash: "h", bundleHash: "bh", combinedFingerprint: "fp", voterCount: 1, tally: tallyResult };
    assert.equal(BallotTally.buildResultDocument(input), BallotTally.buildResultDocument(input));
    assert.equal(JSON.parse(BallotTally.buildResultDocument(input)).ballot, "b1");
});
