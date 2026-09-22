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

`0.3.4`


Au premier démarrage d’une base vide, le compte administrateur par défaut est `admin` / `admin`. Les variables `DEFAULT_ADMIN_USER` et `DEFAULT_ADMIN_PASS` permettent de remplacer ces valeurs avant l’initialisation de la base.
