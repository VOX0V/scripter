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
