# SecretBallot: Design

Status: approved in conversation 2026-10-09, target first use at the online Bundesparteitag 2026.1 on 10.10.2026 (TOP5). If the MVP is not built and tested by the evening of 09.10.2026, TOP5 is postponed.

Base specification: `/media/SMB/TODO/obpt-2026-10-10/secret-ballot-tool-spec.md` (called "the spec" below). Everything in the spec applies unless this document changes it. This document records the deviations and the implementation decisions.

## 1. Deviations from the spec

### 1.1 Variable number of key holders

The spec fixes four slots (VL/WH3, WL, WH1, WH2). Different assemblies need different numbers, so the tool supports 1 to N key holders out of the box.

- The admin maintains an ordered list of key holders. Each entry has a role label (free text, e.g. "Wahlleitung", "Wahlhelfer 1"), the SSO subject of the person, and its position in the list.
- Exactly one entry carries the flag "leitet die Wahl". That person opens and closes ballots (the WL role of the spec).
- Layered encryption generalizes to N layers: the client encrypts with the key of the last entry first and with the key of the first entry last. Decryption happens in list order; the output of the last key holder is the plaintext.
- Ciphertext size is `512 + N * 94` bytes. All ciphertexts of one ballot have the same size, because N is frozen when the ballot opens.
- Combined fingerprint: first 16 bytes of SHA-256 over `"pp-ballot-keys-v1" || ballot id || K1 || ... || KN`.
- With N = 1 that single person can read all ballots (never who cast them). The admin and key holder views state this plainly.
- Reassigning or removing an entry clears that entry's keys and its confirmation.

### 1.2 Keys per day, not per ballot

Key holders register their keys once and they are reused for every ballot of the assembly. Opening a ballot snapshots the current list (roles, order, public keys). The combined fingerprint still differs per ballot because the ballot id is part of it.

Because nothing is persisted, a server restart clears the registered keys too. Key holders re-register by loading their backup file in the key holder view; the backup therefore serves both disaster recovery and restart recovery.

### 1.3 Runtime dependencies

The deployed tool is the .NET server plus static files. Node.js is a development dependency only, used to run the tests of the JavaScript crypto module (`node --test`). Browsers do all cryptography through the Web Crypto API.

### 1.4 Operations for 10.10.2026

The Bundes-IT hosts the tool; Joscha operates it and is therefore not a key holder (separation of duties, spec section 3).

## 2. Architecture

Flat layout under `/media/SMB/SecretBallot`:

- `SecretBallot.slnx`
- `SecretBallot.Server`: .NET 10 minimal API, serves `wwwroot` as static files. No database, no file writes.
- `SecretBallot.Server.Tests`: TUnit tests for the server.
- `SecretBallot.Server/wwwroot`: plain ES modules, no framework, no build step, no CDN. The files reviewed are the files served.
- `SecretBallot.Server/wwwroot/js/ballot-crypto.js`: the only crypto code, shared by the voting page, the key holder page and the offline verifier. Also contains the tally so client and verifier compute identically.
- `tests-js/`: `node --test` tests for `ballot-crypto.js` and the tally.
- `docs/`: user and reviewer documentation (section 7). No README.

Rejected: Blazor WASM (crypto would still go through Web Crypto via interop; large bundle, hard to pin with SRI and hard to review).

### 2.1 Authentication and authorization

- OIDC cookie login against Keycloak (`sso.piratenpartei.de`) with a dedicated confidential client. The voter identity is the OIDC `sub`.
- Eligibility is checked on every cast through the Keycloak admin API (`ekklesia_eligible` user attribute), using the same client's service account with `view-users`. A failing lookup rejects the cast with a clear German message; it never defaults to eligible.
- Admins: list of OIDC subjects in configuration.
- Key holder rights: derived from the key holder list (the session `sub` matches an entry).

## 3. Server state

Everything lives in one in-memory store guarded by a single `System.Threading.Lock`.

- Key holder list: entries with role label, subject, position, "leitet die Wahl" flag, public encryption key, public signing key, confirmed flag.
- Ballots: id (random UUID), definition, status (`Draft`, `Open`, `Closed`, `Finished`), snapshot of key holders taken at opening.
- Per open ballot: a `voted` set of subjects and a `ciphertexts` list. These are two independent collections; no type in the code ever holds a subject and a ciphertext together.
- After closing: the bundle (definition, snapshot of public keys, voter count, ciphertexts sorted by SHA-256), intermediate layers in list order (each re-sorted by SHA-256 on upload), final plaintexts, the result document and signatures. The `voted` set is dropped at closing; only its count remains.
- Only one ballot can be open at a time. Opening requires every entry to be registered and confirmed.
- Casting, in one critical section: ballot is open, subject not in `voted`, ciphertext has the expected version byte and size; then add the subject to `voted` and the ciphertext to `ciphertexts`.
- Request logging is disabled for the vote endpoint; no code path logs request bodies.

## 4. Endpoints

All JSON. Errors carry a German message for display.

- `GET /api/me`: login state, display name, roles (voter eligibility, admin, key holder entry).
- `GET /api/ballots/current`: the open ballot (definition, snapshot of public encryption keys in order, combined fingerprint) or none.
- `POST /api/ballots/{id}/votes`: body = base64 ciphertext. 204 on success.
- `GET /api/ballots/{id}/status`: status and vote count.
- `GET /api/ballots/{id}/bulletin`: after closing, receipt hashes (sorted), voter count, ciphertext count.
- `GET /api/ballots/{id}/bundle`: after closing, the bundle JSON.
- Key holder: `GET/PUT /api/keyholders/me/keys` (register public keys), `POST /api/keyholders/me/confirm`, `GET /api/ballots/{id}/layers/{index}`, `PUT /api/ballots/{id}/layers/{index}` (only the entry at that position, only when the previous layer exists), `PUT /api/ballots/{id}/signatures` (own signature over the result document).
- Leader: `POST /api/ballots/{id}/open`, `POST /api/ballots/{id}/close`.
- Admin: `GET/PUT /api/keyholders` (list maintenance), `POST /api/ballots` (create definition), `GET /api/ballots`.
- `GET /api/ballots/{id}/publication`: after all signatures, the full publication bundle for the offline verifier (bundle, all layers, plaintexts, result document, public signing keys, signatures). Private keys are added by the key holders themselves (section 5.4).

## 5. Client

### 5.1 Pages (German UI)

- `/` "Abstimmen": current ballot, options per type, combined fingerprint next to the vote button with the instruction to compare it with the one read out, receipt after casting (first 16 hex digits prominent, full value copyable).
- `/bulletin.html` "Öffentliche Liste": receipt hashes, voter count, ciphertext count, mismatch warning; search field for one's own receipt.
- `/schluessel.html` "Schlüsselverwaltung": generate keys, backup file with verified re-import, register, compare fingerprints and confirm; restore from backup after a restart; per closed ballot: download previous layer, decrypt own layer, upload; for the last position: validation, tally view, result document; sign.
- `/admin.html` "Verwaltung": key holder list, ballot creation, overview.
- `/pruefen.html` "Offline-Prüfung": standalone, works from `file://`; loads a publication bundle plus private keys and recomputes everything.

### 5.2 Crypto

As spec section 6.1, generalized to N layers. Plaintext is the JSON of spec section 7.5 padded with spaces to 512 bytes. Choices are option indices.

### 5.3 Backup file

PBKDF2-SHA-256 (600 000 iterations, random salt) + AES-256-GCM over a JSON with both private keys (JWK) and the role label. The client only registers public keys after the user re-selects the downloaded file, re-enters the password, and the decrypted keys match.

### 5.4 Publication of private keys

After the result is announced, each key holder exports their private encryption key from the key holder view as a JWK file; these are published together with the publication bundle. The signing keys are never exported in this form.

## 6. Ballot types and tally

- Approval with seats (MVP): any subset of options; empty ballot = rejection of all. An option needs more than half of the valid ballots; elected in order of approvals until seats are filled. Ties at the cut-off or unfilled seats are reported as "Stichwahl/neuer Wahlgang nötig" with the affected options; the tool does not decide them.
- Single choice (MVP): options plus fixed "keinen der Kandidierenden"; exactly one choice or empty.
- Yes/No (only if time allows).
- The tally view always shows both majority bases (empty ballots counted in and excluded), spec section 14.
- Invalid plaintexts (wrong ballot id, wrong definition hash, broken JSON, inconsistent choices, decryption failure) are counted and listed.

## 7. Documentation

The code follows the usual style (minimal comments). Explanations live in `docs/`, German for participants, English for reviewers:

- `docs/how-it-works.md` (English): architecture, crypto, data flow, why secrecy holds, threat model and residual risks.
- `docs/schluesselhalter.md` (German): step-by-step procedure for key holders.
- `docs/pruefen.md` (German): how voters check their receipt and how anyone recounts with the offline verifier.
- `docs/deployment.md` (English): Keycloak client setup, configuration, hardening checklist (spec section 9), bundle hash publication.

## 8. Build order for 09.10.2026

1. Crypto module and its tests; server skeleton with OIDC, eligibility check, casting, receipt.
2. Key holder list, key generation, backup with re-import check, registration, confirmation, restore.
3. Closing, bulletin, layer-by-layer decryption, tally.
4. Signed result document, offline verifier.
5. Documentation.
6. Deployment notes and hardening.

If time runs short: drop Yes/No and verifier polish, never the crypto or the separation of who and what.

## 9. Testing

- `node --test tests-js/`: layered encryption for N = 1 and N = 4, fixed ciphertext size, randomized output for identical choices, tamper and replay detection, fewer than N keys cannot decrypt, backup round trip, tally cases from spec section 13.
- TUnit: one vote per subject, rejection of wrong size/version, sort order of the bundle, open/close preconditions, layer upload order and ownership, voted set dropped at close.
- Manual end-to-end test ballot by Joscha with real accounts on the evening of 09.10.2026.
