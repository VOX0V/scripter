# Scripter

Scripter is a homelab administration tool for running user-authored shell
scripts across multiple SSH-managed virtual machines.

## Repository layout

```text
scripter_app/
├── scripter/
│   ├── app/
│   ├── deploy/
│   ├── tests/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── VERSION
│   └── wsgi.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── docker-compose.yml
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
└── SECURITY.md
```

The repository root is `scripter_app`. Docker Compose is intentionally located
at the repository root.

## GitHub / Docker deployment

GitHub Actions runs the Python tests and, on pushes to `main` or version tags,
builds and publishes a multi-architecture image to GitHub Container Registry:

- `linux/amd64` for normal PCs and x86 servers
- `linux/arm64` for 64-bit Raspberry Pi systems

Create a local environment file from the example:

```sh
cp .env.example .env
```

Change `SCRIPTER_IMAGE` to the GHCR image for this repository and set the
initial administrator credentials. SSH private keys belong in `./scripter/keys`
and are never committed.

For a clean installation:

```sh
docker compose pull
docker compose up -d
```

To update an existing installation:

```sh
docker compose pull
docker compose up -d
```

The host does not need Python or the project dependencies installed locally.

The deployment directories are deliberately mapped as follows:

```text
./data    -> /usr/src/app/instance   # scripter.db + secret_key
./scripts -> /usr/src/app/data       # user scripts + logs/
./keys    -> /run/scripter/keys      # SSH keys, read-only
```

Before the first start, the container user (`1000:1000`) must be able to write
to `data/` and `scripts/`. Prepare a fresh host with:

```sh
sudo mkdir -p data scripts keys
sudo chown -R 1000:1000 data scripts
sudo chmod 700 data keys
sudo chmod 755 scripts
```

This mapping is intentional: `instance/` is no longer a separate host
directory. The persistent host directory is `data/`, which is the directory
used by the deployment compose file for the SQLite database and `secret_key`.


## Security model

Scripter is an administrative automation tool, not a sandbox. A user who is
authorized to execute scripts on a host with sudo privileges effectively has
administrative access to that host.

For the homelab deployment, use a dedicated SSH automation account and restrict
sudo to the Scripter wrapper rather than granting unrestricted sudo.

Never commit `.env`, SSH private keys, runtime databases, or logs containing
secrets.

## Version

`1.2.0`

## v1.0 hardening

- Concurrent executions per user are capped (`MAX_CONCURRENT_EXECUTIONS_PER_USER`,
  default 3) and total logged/streamed output per execution is capped
  (`MAX_EXECUTION_OUTPUT_BYTES`, default 2 MiB). See `.env.example`.
- A timed-out or output-overflowed execution now also attempts a best-effort
  kill of the remote process; see `SECURITY.md` for the sudo-mode caveat.
- WebSocket terminal sessions re-check session revocation, not just the HTTP
  routes: an admin revoking a user's sessions now also cuts an already-open
  live terminal.
- `socket.io` client is vendored locally (`app/static/js/vendor/`) instead of
  loaded from a CDN, and the Content-Security-Policy no longer allows any
  external script source or a wildcard WebSocket scheme.

## v1.1 hardening

- **Server-level authorization.** A non-admin user can no longer target every
  configured server by default: a server with `SSH_USE_SUDO_n=1` grants root
  on that host, so it's now admin-only unless explicitly opted in via
  `SSH_ALLOWED_USERS_n`. This is an intentional behaviour change — if you
  relied on non-admin accounts running sudo-mode scripts, add them to that
  server's allowlist.
- **Atomic execution quota.** The per-user and new instance-wide
  (`MAX_GLOBAL_CONCURRENT_EXECUTIONS`, default 20) concurrency checks are now
  reserved inside a single `BEGIN IMMEDIATE` SQLite transaction together with
  the row inserts, closing the count-then-insert race a concurrent `/run`
  could previously hit.
- **Startup watchdog for orphaned executions.** Any execution still marked
  "running" from a previous process lifetime (crash, forced restart,
  container kill) is now reconciled to "error" at boot, with a note appended
  to its log, instead of staying stuck "running" forever and quietly eating
  into the owner's quota.
- Fixed `get_scripts_structure()`: hitting `MAX_SCRIPT_COUNT` or
  `MAX_SCRIPT_CONTENT_BYTES` now stops the whole directory scan, not just the
  current folder's file loop.

## v1.2 hardening

- **Privileged remote kill.** `deploy/scripter-run` gained a `--kill <path>`
  mode, run as root through the same sudoers rule already in place. Combined
  with `ssh_runner.py` trying it first on a forced stop, a timed-out or
  output-capped execution launched in sudo mode can now actually be
  terminated, not just best-effort-signalled. **Requires redeploying the
  updated `scripter-run` to each target host** to take effect — until then,
  behaviour degrades cleanly to the v1.0 best-effort pkill.
- **Script snapshot + hash.** A script's bytes are read once at `/run` time,
  hashed (SHA-256, recorded on the `Execution` row and in the log header),
  and copied to a private per-execution file that's what's actually
  uploaded and run — closing the gap where the source script file could be
  edited between validation and use.
- **Per-server concurrency cap** (`MAX_CONCURRENT_EXECUTIONS_PER_SERVER`,
  default 2), checked in the same atomic reservation as the per-user and
  global caps, so several accounts can no longer pile onto one target host
  at once.
- **Capped log reads** (`MAX_LOG_READ_BYTES`, default 5 MiB): `/terminal` and
  `/log/<id>` now tail large logs with a truncation notice instead of
  loading them in full — mainly relevant to logs predating the v1.0 output
  cap.
- **`LoginAttemptLog` retention** (`LOGIN_ATTEMPT_LOG_RETENTION_DAYS`,
  default 30): purged at startup instead of growing forever.
- **Per-account login lockout**, complementing the existing per-IP one, with
  a progressively growing delay (not an indefinite hard lock) so it can't
  itself become a denial-of-service against a legitimate user.
- **Minimum password length (8 chars) for accounts an admin creates** for
  someone else via `/admin`. `DEFAULT_ADMIN_PASS` (your own initial
  credentials) remains deliberately unrestricted — see `SECURITY.md`.


Au premier démarrage d’une base vide, le compte administrateur par défaut est `admin` / `admin`. Les variables `DEFAULT_ADMIN_USER` et `DEFAULT_ADMIN_PASS` permettent de remplacer ces valeurs avant l’initialisation de la base.
