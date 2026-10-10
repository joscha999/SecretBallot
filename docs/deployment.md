# Deployment

SecretBallot is one .NET 10 process serving an API and static files. It keeps all state in memory and writes nothing to disk. Run exactly one instance; a second instance would have its own, separate state.

## Separation of duties

The person operating the host (shell, container, hypervisor, database or memory access) must not be a key holder. Before the event, check the key holder list in "Verwaltung" against the list of people with access to the host.

## Keycloak client

Create a client in realm `Piratenlogin` on `sso.piratenpartei.de`:

- Client type OpenID Connect, client authentication on (confidential), standard flow on, direct access grants off.
- Valid redirect URI: `https://<host>/signin-oidc`. Web origin: `https://<host>`.
- Service account roles on: assign the client role `realm-management` / `view-users`. The server uses it to read the eligibility attribute on every cast and to resolve usernames when the admin enters key holders.
- Default client scopes: `openid`, `basic` (Keycloak 25+ delivers the `sub` claim through it; without it every request fails), `profile` (provides `preferred_username` and `name`).

The eligibility attribute is `ekklesia_eligible` (set by MemberDataImport, adjustable live in Quartermaster). Only the string `true` counts as eligible; a disabled account is never eligible.

## Configuration

`SecretBallot.Server/appsettings.json`, section `SecretBallot`:

```
Authority              https://sso.piratenpartei.de/realms/Piratenlogin
ClientId               secret-ballot
ClientSecret           (environment only, see below)
KeycloakBaseUrl        https://sso.piratenpartei.de
Realm                  Piratenlogin
EligibilityAttribute   ekklesia_eligible
AdminUsernames         ["<username>", ...]
```

Set the secret and the admins through the environment, never in a committed file:

```
SecretBallot__ClientSecret=<secret>
SecretBallot__AdminUsernames__0=<username>
```

## Build and publish

```
cd /media/SMB/SecretBallot
node --test tests-js/*.test.js
dotnet build -m:1 SecretBallot.slnx
dotnet run --no-build --project SecretBallot.Server.Tests/SecretBallot.Server.Tests.csproj
dotnet publish SecretBallot.Server/SecretBallot.Server.csproj -c Release -o /opt/secret-ballot
```

Node is only needed for the tests. The published folder needs the ASP.NET Core 10 runtime.

## systemd unit

```
[Unit]
Description=SecretBallot
After=network-online.target

[Service]
ExecStart=/usr/bin/dotnet /opt/secret-ballot/SecretBallot.Server.dll
WorkingDirectory=/opt/secret-ballot
Environment=ASPNETCORE_URLS=http://127.0.0.1:5180
Environment=ASPNETCORE_ENVIRONMENT=Production
EnvironmentFile=/etc/secret-ballot.env
DynamicUser=yes
LimitCORE=0
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
NoNewPrivileges=yes
Restart=no

[Install]
WantedBy=multi-user.target
```

`Restart=no` is deliberate: a restart loses all state, so a crash must be noticed and announced, not silently papered over. `/etc/secret-ballot.env` holds the two environment variables above and is readable by root only. `journalctl` receives only warnings and errors; no code path logs request bodies, and no log line contains a user id together with ballot data.

## Reverse proxy (nginx)

```
server {
    listen 443 ssl;
    server_name <host>;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location ~ ^/api/ballots/[^/]+/votes$ {
        access_log off;
        error_log /dev/null crit;
        client_max_body_size 16k;
        proxy_pass http://127.0.0.1:5180;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/keyholder/ {
        client_max_body_size 16m;
        proxy_pass http://127.0.0.1:5180;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        proxy_pass http://127.0.0.1:5180;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
    }
}
```

The vote endpoint gets no access log at any layer. Layer uploads by key holders carry every ballot of a round (about 1 KB per ballot with four key holders), so the key holder location needs a larger body limit than nginx's default 1 MB. Disable any APM or request mirroring for the host. The larger proxy buffers avoid failures on the OIDC callback, whose response headers carry large cookies.

## Host hardening for the event

- Turn swap off for the duration (`swapoff -a`), so ballot memory never lands on disk.
- Core dumps are off through `LimitCORE=0`; also check `/proc/sys/kernel/core_pattern` does not pipe to a collector.
- No backups or snapshots of the VM while a ballot is open or before the tally is finished.

## Before the event

- Publish the source code (repository link in the wiki and on the OpenSlides start page).
- Publish the hash list of all files the browser receives: `tools/wwwroot-hashes.sh > wwwroot-hashes.txt`. A changed hash during the event is an incident.
- Run a test ballot with real accounts: one ineligible account, one temporary account with a negative member number, at least two key holders. Restart the server afterwards and check that key holders can register again from their backup files.

## Test checklist

- An account with `ekklesia_eligible` false cannot vote; switching it to true in Quartermaster allows voting without a new login.
- A second vote by the same account is rejected.
- A ballot cannot be opened while a key holder is unregistered or unconfirmed.
- The key holder page does not register keys before the backup check succeeded.
- After closing: voter count equals ciphertext count, every test receipt is on the public list.
- Fewer than all key holders cannot decrypt; all of them in order can, also with a pause between layers.
- All ciphertexts have `512 + N * 94` bytes.
- The offline verifier accepts the publication and reproduces the result; it flags a tampered ciphertext.
- After a restart, no ballot data is left; `journalctl -u secret-ballot` and the nginx logs contain no ciphertexts.

The automated tests cover most of these: `node --test tests-js/*.test.js` (crypto, tally, verifier) and the TUnit project (server rules, Keycloak lookup, and a complete election with 1 and 4 key holders run by `tests-js/e2e/flow.js` against the real endpoints).
