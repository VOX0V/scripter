# Security

## Threat model

Scripter is an administration tool for trusted homelab operators. It can execute
user-authored shell scripts on configured machines and may execute them through
`sudo`. This is intentional functionality, not a sandbox.

Anyone who can create/execute a script for a host with sudo access must therefore
be treated as having administrative access to that host.

## GitHub publication rules

Never commit:
- `.env`
- SSH private keys
- host-specific credentials
- SQLite/runtime databases
- logs containing credentials or command output with secrets

Use `.env.example` as the public configuration template.

## Sudo

Prefer a dedicated automation account on each target VM. Grant it only the
specific wrapper command required by Scripter, with `NOPASSWD`, rather than
granting unrestricted sudo.

The wrapper should use non-interactive sudo (`sudo -n`) so an automation job
cannot hang waiting for a password.

## Network exposure

Do not expose the Scripter web interface directly to the public Internet.
Prefer a private VLAN/VPN/reverse proxy with authentication and TLS.

## Script execution

Scripts are trusted administrative code. Do not allow untrusted users to access
the application or its administrative endpoints.

## Reverse proxy / X-Forwarded-For

`TRUST_PROXY_HEADERS=1` makes the per-IP login lockout trust
`CF-Connecting-IP`/`X-Forwarded-For` instead of the socket's peer address.
Only enable this behind a reverse proxy that unconditionally strips or
overwrites those headers on the way in. If enabled without such a proxy, any
client can spoof a different IP on every request and bypass the lockout
entirely.

## Resource limits (since v1.0)

- `MAX_CONCURRENT_EXECUTIONS_PER_USER` (default 3) caps how many "running"
  executions one account may have at once, across all targets. This limits
  how hard a single (possibly compromised) account can hammer target hosts'
  SSH daemons.
- `MAX_EXECUTION_OUTPUT_BYTES` (default 2 MiB) caps the combined stdout/stderr
  logged and streamed per execution. Past this limit the execution is
  forcibly stopped rather than filling `data/logs` or a browser tab
  indefinitely.

## Password policy: two different trust situations (since v1.2)

`DEFAULT_ADMIN_PASS` (your own initial credentials, set via `.env` before
first start) has no minimum length — that's a deliberate choice: you carry
the risk of a weak choice you made for yourself, knowingly. Accounts created
afterwards via `/admin` for *someone else* are different: that person didn't
see the password get chosen and can't judge its strength before it's already
theirs, so those have an 8-character minimum. `DEFAULT_ADMIN_PASS` is
intentionally exempt from this.

## Server-level authorization (since v1.1)

Non-admin users no longer have implicit access to every configured server.
A server flagged `SSH_USE_SUDO_n=1` grants root on that host — running any
script there is equivalent to full administrative access to that machine —
so such a server is now admin-only unless the operator explicitly opts
specific accounts in via `SSH_ALLOWED_USERS_n`. Treat that allowlist (and
admin status itself) as a privileged grant, not a convenience setting.

## Forced-stop kill is best effort, not a guarantee (since v1.0)

When an execution is stopped by Scripter (timeout or output-limit overflow),
it now also attempts `pkill -f` for the remote script's unique temp path over
a fresh SSH session. In **non-sudo** mode this reliably terminates the
process tree. In **sudo** mode (since v1.2), Scripter first tries a
privileged kill through the `scripter-run --kill <path>` mode, run as root
via the same sudoers rule used to launch the script — this can terminate a
root-owned process that a plain, non-privileged pkill cannot touch. This
requires the target host to be running the v1.2 (or later) `scripter-run`;
until you redeploy it, sudo-mode kills silently fall back to the old
best-effort pkill, which still cannot guarantee termination. Either way, a
script that immediately re-execs into an unrelated, detached process can
still escape the argv-pattern match `pkill -f` relies on — this is a
practical mitigation, not a sandbox.

## Script integrity at execution time (since v1.2)

`/run` reads the target script's bytes exactly once, hashes them
(SHA-256, stored on the `Execution` row and logged in the execution header),
and runs from a private per-execution copy of those exact bytes rather than
re-reading the source file later. This closes the window where the source
script could be edited between validation and use, and gives you an
after-the-fact record of precisely what ran, independent of the source
file's later state.

## Per-account login lockout is progressive, not a hard lock (since v1.2)

In addition to the existing per-IP lockout, repeated failed logins against
the same *username* — regardless of source IP — now add an escalating delay
before that username can be tried again (1 → 5 → 15 → 30 → 60 minutes,
resetting on the next success). This closes the gap where a distributed
attacker rotating IPs was effectively unthrottled against one account. Trade-off,
stated plainly: this can be used to inconvenience a legitimate user by
deliberately failing their username a few times from anywhere — the delay is
bounded and self-clears, which is a better trade than leaving credential
stuffing against a known username completely unthrottled.
