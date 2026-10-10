# How SecretBallot works

SecretBallot is a small web tool for secret elections at online assemblies of the Piratenpartei. It separates the two pieces of knowledge needed to break ballot secrecy: the server knows **who** voted, the key holders together know **what** was voted, and nobody holds both. After the count, anyone can recount the published result.

## Roles

- **Admin:** maintains the list of key holders and creates ballots. Listed by Keycloak username in the configuration (`SecretBallot:AdminUsernames`). May be the server operator.
- **Key holders:** an ordered list of 1 to N people, each with a free-text role (for example "Wahlleitung", "Wahlhelfer 1"). Each holds one encryption key pair and one signing key pair, generated in their own browser. Exactly one key holder is flagged as leading the election; that person opens and closes ballots. The order of the list is the order of decryption.
- **Voters:** any Piratenlogin account whose eligibility attribute (`ekklesia_eligible`, shown as "Beiträge gezahlt") is true at the moment of casting.
- **Server operator:** anyone with shell, container, hypervisor or memory access to the machine.
- **Observers:** anyone; they can check a published result with the offline verifier.

Separation of duties is a hard rule: **no key holder may operate the server.** Secrecy holds unless the server operator and all key holders collude.

## What each party learns

- The server learns who voted and when, the encrypted ballot of each request while it is processed, and the totals. It never sees a plaintext ballot.
- The key holders, only all of them together, learn every plaintext ballot after closing, in an order unrelated to submission order, and the number of voters. They never learn who cast which ballot.
- Observers learn, after publication, all ciphertexts, all decryption layers, the private decryption keys, all plaintext ballots, the voter count and the result.

With only one key holder, that person can read every ballot alone (still without knowing who cast it). The admin and key holder pages say so.

## Cryptography

All cryptography runs in the browser through the Web Crypto API. The server only checks sizes and signatures.

- Key agreement: ECDH on P-256. Each key holder has a static key pair; every encryption layer uses a fresh ephemeral key pair.
- Key derivation: HKDF-SHA-256 over the shared secret, salt = ephemeral public key, info = `"pp-ballot-v1"` followed by the ballot id.
- Encryption: AES-256-GCM, random 96-bit IV, ballot id as additional authenticated data.
- Envelope per layer: version byte `0x01`, ephemeral public key (65 bytes), IV (12 bytes), ciphertext plus tag. Each layer adds 94 bytes.
- Plaintext: the JSON `{"v":1,"ballot":"<id>","def":"<definition hash>","choice":[...],"nonce":"<128 bit hex>"}`, padded with spaces to exactly 512 bytes. Choices are option indices, so every ballot has the same length.
- Layers: the voter's browser encrypts with the key of the last key holder first and with the key of the first key holder last. Every final ciphertext of a ballot has exactly `512 + N * 94` bytes.
- Fingerprint of a key: the first 16 bytes of SHA-256 over the raw public key, shown as 8 groups of 4 hex digits.
- Combined fingerprint of a ballot: the same format over `"pp-ballot-keys-v1"`, the ballot id and all public encryption keys in list order. It changes with every ballot and is read out before opening.
- Receipt: SHA-256 over the complete ciphertext as sent.
- Signing: ECDSA P-256 with SHA-256, a separate key pair per key holder. Signing keys are never published.
- Backup file: both private keys as JWK, encrypted with AES-256-GCM under a key derived by PBKDF2-SHA-256 (600 000 iterations, random salt) from a password.

Encryption is randomized, so two identical choices produce different ciphertexts. A ciphertext cannot be moved to another ballot: the ballot id is bound into the key derivation, the authenticated data and the plaintext.

## Data flow

**Setup.** The admin enters the key holders by Piratenlogin username; the server resolves each one to the stable account id (OIDC `sub`). Each key holder opens the "Schlüsselverwaltung" page, generates both key pairs, downloads the password-protected backup file, selects it again and re-enters the password. Only when that backup decrypts to the same keys does the page upload the public keys. The page then shows the fingerprints stored on the server next to the ones computed locally, and the key holder confirms that they match. Keys are registered once per day and reused for every ballot.

**Opening.** The admin creates a ballot (title, type, options, seats). Before opening, the leader reads the combined fingerprint aloud on Mumble and in the stream. The ballot can only be opened when every key holder is registered and confirmed, and only one ballot can be open at a time. Opening freezes the definition and takes a fixed copy of the key holder list and keys.

**Casting.** The voting page loads the ballot, recomputes the combined fingerprint from the keys and shows it next to the button. The voter's browser builds and pads the plaintext, encrypts it in N layers, computes the receipt and sends only the ciphertext. The server checks eligibility live against Keycloak on every cast (a failed lookup rejects the vote, it never counts as eligible), then in one critical section (`ElectionState.Cast`) checks that the ballot is open, that the size and version byte are right, and that the account has not voted yet. It adds the account id to the `Voted` set and inserts the ciphertext at a random position of the `Ciphertexts` list, so the memory order of the two collections does not line up. No data structure ever contains a voter and a ciphertext together, and no code path logs request bodies. The voting page encrypts once per ballot and keeps the encrypted envelope and its receipt (never the choice) in the browser's local storage, so a retry after a lost response resends the same envelope and the receipt stays valid.

**Closing.** The leader closes the ballot (an admin can close it as a fallback). `ElectionState.Close` records the number of voters, sorts all ciphertexts by their SHA-256 (which is unrelated to submission order), clears both collections and writes the bundle: definition, key holder list with public encryption keys, voter count and sorted ciphertexts. The voter list is not part of the bundle and no longer exists after closing.

**Bulletin.** The public page "Öffentliche Liste" shows all receipts, the voter count and the ciphertext count. The two counts must match, otherwise the ballot is void. Voters search for their own receipt; a confirmed missing receipt voids the ballot.

**Decryption.** Each key holder loads their backup file, downloads the previous layer, removes their own layer in the browser and uploads the result. The server only accepts the layer from the person whose turn it is, checks the sizes and re-sorts by hash. The decryption does not have to happen in one session. Intermediate layers stay encrypted for the remaining key holders.

**Count.** After the last layer the plaintexts are counted by `ballot-tally.js`, the same code the offline verifier uses. Invalid plaintexts (wrong ballot, wrong definition, broken JSON, invalid choice) count as invalid ballots. Supported types:

- Approval (Akzeptanzwahl): any subset of options; an empty ballot rejects everyone. An option needs more than half of the valid ballots; the options with such a majority are elected in order of approvals until the seats are filled. A tie at the last seat and unfilled seats are reported as "Stichwahl/neuer Wahlgang nötig"; the tool does not decide them.
- Single choice (runoff): exactly one option or an empty ballot, including the fixed option "keinen der Kandidierenden". A win of that option elects nobody.
- Yes/No: accepted when Yes has more votes than No.

The count is always shown twice: with empty ballots in the majority base and without, because the GO and the Satzung count empty ballots differently. The Wahlleitung announces which reading applies before the ballot opens.

**Result and signatures.** The last key holder writes the result document (a JSON string with a fixed key order containing ballot id, definition hash, bundle hash, combined fingerprint, all counts and both outcomes). Every key holder recomputes it independently in their own browser, compares it with the stored one and signs it. The server verifies each signature against the registered signing key. When all signatures are present, the ballot is finished.

**Publication.** After the announcement, the key holders download the publication bundle (bundle, all layers, result document, public keys, signatures) and export their private decryption key. Both are published. Publishing the private keys is safe because the server never stored a link between voters and ciphertexts. Exporting retires the key (`ElectionState.RetireKeys`): it is cleared from the key holder list, the server refuses to register it again, and no further ballot can open until that key holder has generated, backed up and confirmed fresh keys. Retiring is refused while any ballot using the key is still open or not fully signed. The list of retired keys lives in memory too, so after a restart key holders must not load an exported backup again. Keys should therefore be exported only after the last ballot of the day.

## Verification

`pruefen.html` loads the publication bundle and the private decryption keys and checks: that the published keys give the combined fingerprint that was read out before opening (entered by the user; this is what ties the file to the real ballot, since every other check only shows the file is consistent with itself), that bundle and first layer are identical, that the ciphertext count equals the voter count, that all ciphertexts have the same size, that every layer decrypts with the published key to exactly the next published layer, that the recount gives the same result document, and that all signatures are valid. It matches key files to layers by public key. It also shows the SHA-256 of the result document and the fingerprints of the signing keys for comparison with the Wahlprotokoll, and it can look up a receipt. It works offline from a copy of `wwwroot`.

## Restarts and failures

Nothing is written to disk. A restart of the server loses everything: registered keys, ballots and sessions. An open ballot is void and has to be repeated. After a restart the admin re-enters the key holders and each key holder registers again by loading their backup file. A lost backup file makes a closed ballot impossible to count; that ballot is void.

## Residual risks

- Collusion between the server operator and all key holders breaks secrecy.
- A compromised server can deliver manipulated scripts that leak or alter votes. The published hash list of all served files (`tools/wwwroot-hashes.sh`) lets attentive members detect this.
- A compromised voter device can leak or alter that voter's vote.
- There is no protection against coercion or vote selling.
- The server operator learns who participated, not how.
- A crash voids the running ballot; a lost private key voids a closed one.

## File map

- `SecretBallot.Server/Program.cs`: hosting, security headers, in-memory data protection.
- `SecretBallot.Server/RequestMarker.cs`: every state-changing API request must carry the `X-Secret-Ballot` header. A custom header forces a CORS preflight, which the server never answers, so other sites cannot trigger actions in a logged-in session.
- `SecretBallot.Server/Auth/`: OIDC login against Keycloak, cookie session, validation of the return URL after login.
- `SecretBallot.Server/Keycloak/`: live eligibility lookup and username lookup through the Keycloak admin API.
- `SecretBallot.Server/Election/ElectionState.cs`: all election rules and state, guarded by one lock.
- `SecretBallot.Server/Election/CryptoFormats.cs`: sizes, hashes, fingerprints, signature check.
- `SecretBallot.Server/Election/BallotDefinitionWriter.cs`, `BundleWriter.cs`: the exact JSON that gets hashed.
- `SecretBallot.Server/Endpoints/`: the HTTP API.
- `SecretBallot.Server/wwwroot/js/ballot-crypto.js`: all cryptography.
- `SecretBallot.Server/wwwroot/js/ballot-tally.js`: validation, count and result document.
- `SecretBallot.Server/wwwroot/js/verify.js`: the checks of the offline verifier.
- `SecretBallot.Server/wwwroot/js/abstimmen.js`, `bulletin.js`, `schluessel.js`, `admin.js`, `pruefen.js`: the pages.
- `tests-js/`: Node tests of the scripts; `tests-js/e2e/flow.js` runs a complete election against the real server from `SecretBallot.Server.Tests/EndToEnd`.
