import hashlib
import os
import socket
from collections import Counter
from datetime import datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import text

from app import db, socketio
from app.models import Execution
from app.ssh_runner import get_log_dir, start_interactive_session

main_bp = Blueprint("main", __name__)


def get_configured_servers() -> dict:
    servers = {}
    i = 1
    while True:
        host = os.getenv(f"SSH_HOST_{i}")
        if not host:
            break
        try:
            port = int(os.getenv(f"SSH_PORT_{i}", 22))
        except ValueError:
            raise RuntimeError(f"SSH_PORT_{i} est invalide")
        if not 1 <= port <= 65535:
            raise RuntimeError(f"SSH_PORT_{i} est invalide")
        servers[str(i)] = {
            "host": host,
            "port": port,
            "user": os.getenv(f"SSH_USER_{i}"),
            "pass": os.getenv(f"SSH_PASS_{i}"),
            "key_path": os.getenv(f"SSH_KEY_PATH_{i}"),
            "key_passphrase": os.getenv(f"SSH_KEY_PASSPHRASE_{i}"),
            "use_sudo": os.getenv(f"SSH_USE_SUDO_{i}", "0") == "1",
            "sudo_wrapper": os.getenv(f"SSH_SUDO_WRAPPER_{i}", "/usr/local/sbin/scripter-run"),
            "label": os.getenv(f"SSH_LABEL_{i}", host),
            # v1.1: optional per-server allowlist (comma-separated usernames).
            # None means "no explicit allowlist configured" (see _accessible_servers).
            "allowed_users": (
                frozenset(u.strip() for u in os.getenv(f"SSH_ALLOWED_USERS_{i}", "").split(",") if u.strip())
                or None
            ),
        }
        i += 1
    return servers


def _accessible_servers(user, servers: dict) -> dict:
    """v1.1: restrict which servers a non-admin user may see/target.

    Admins can always target every configured server. SSH_USE_SUDO grants
    root on the target host, so by default a server with SSH_USE_SUDO=1 is
    admin-only unless SSH_ALLOWED_USERS_n explicitly opts specific accounts
    in. A non-sudo server stays open to every authenticated user unless
    SSH_ALLOWED_USERS_n is set for it, which preserves prior behaviour for
    typical (non-sudo) deployments.
    """
    if user.is_admin:
        return dict(servers)
    accessible = {}
    for server_id, srv in servers.items():
        allowed = srv.get("allowed_users")
        if allowed is not None:
            if user.username in allowed:
                accessible[server_id] = srv
            continue
        if srv.get("use_sudo"):
            continue
        accessible[server_id] = srv
    return accessible


def _safe_script_path(data_dir: str, folder: str, script_name: str) -> Path | None:
    root = Path(data_dir).resolve()
    folder_path = root / folder
    script_path = folder_path / script_name
    try:
        if not folder_path.is_dir() or folder_path.is_symlink():
            return None
        if script_path.is_symlink() or not script_path.is_file():
            return None
        resolved = script_path.resolve(strict=True)
        if root not in resolved.parents or resolved.suffix != ".sh":
            return None
        if resolved.stat().st_size > current_app.config["MAX_SCRIPT_SIZE"]:
            abort(413, "Script trop volumineux")
        return resolved
    except OSError:
        return None


def get_scripts_structure(data_dir: str) -> dict:
    structure = {}
    listed = 0
    total_bytes = 0
    root = Path(data_dir)
    if not root.is_dir():
        return structure
    limit_count = current_app.config["MAX_SCRIPT_COUNT"]
    limit_bytes = current_app.config["MAX_SCRIPT_CONTENT_BYTES"]
    try:
        for folder_entry in sorted(root.iterdir(), key=lambda p: p.name):
            # v1.1: check the global caps before opening the next folder at
            # all, not just inside the per-file loop below — otherwise every
            # remaining folder still gets scanned (iterdir + stat calls) even
            # once nothing more will be listed.
            if listed >= limit_count or total_bytes >= limit_bytes:
                break
            if not folder_entry.is_dir() or folder_entry.is_symlink() or folder_entry.name == "logs":
                continue
            scripts = []
            for file in sorted(folder_entry.iterdir(), key=lambda p: p.name):
                if listed >= limit_count or total_bytes >= limit_bytes:
                    break
                if file.is_symlink() or not file.is_file() or file.suffix != ".sh":
                    continue
                try:
                    if file.stat().st_size > current_app.config["MAX_SCRIPT_SIZE"]:
                        continue
                    content = file.read_text(encoding="utf-8", errors="ignore")
                    encoded_size = len(content.encode("utf-8", errors="ignore"))
                    if total_bytes + encoded_size > limit_bytes:
                        break
                except OSError:
                    content = "(impossible de lire le contenu du script)"
                scripts.append({"name": file.name, "content": content})
                listed += 1
                total_bytes += len(content.encode("utf-8", errors="ignore"))
            structure[folder_entry.name] = scripts
    except OSError:
        pass
    return structure


def _check_server_online(srv: dict) -> bool:
    try:
        with socket.create_connection((srv["host"], srv["port"]), timeout=1.2):
            return True
    except OSError:
        return False


def _read_log_capped(path: Path, max_bytes: int) -> str:
    """v1.2: read at most max_bytes from a log file, tailing it if larger.
    Execution output going forward is already bounded (MAX_EXECUTION_OUTPUT_BYTES),
    but this also protects viewing of older, pre-cap logs."""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    try:
        with open(path, "rb") as f:
            if size <= max_bytes:
                return f.read().decode("utf-8", errors="ignore")
            f.seek(size - max_bytes)
            data = f.read()
            prefix = (
                f"*** Log tronqué à l'affichage : {max_bytes} derniers octets "
                f"sur {size} au total. ***\n\n"
            ).encode("utf-8")
            return (prefix + data).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def can_access_execution(execution: Execution) -> bool:
    return current_user.is_authenticated and (
        current_user.is_admin or execution.user_id == current_user.id
    )


def _owned_executions_query():
    if current_user.is_admin:
        return Execution.query
    return Execution.query.filter(Execution.user_id == current_user.id)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    data_dir = current_app.config["DATA_DIR"]
    servers = _accessible_servers(current_user, get_configured_servers())
    for srv in servers.values():
        srv["online"] = _check_server_online(srv)

    executions_by_server = {}
    for server_id in servers:
        executions_by_server[server_id] = (
            _owned_executions_query()
            .filter_by(server_id=server_id)
            .order_by(Execution.started_at.desc())
            .limit(10)
            .all()
        )

    return render_template(
        "dashboard.html", servers=servers,
        structure=get_scripts_structure(data_dir),
        executions_by_server=executions_by_server,
    )


@main_bp.route("/run", methods=["POST"])
@login_required
def run_script():
    server_ids = request.form.getlist("server_ids")
    combined = request.form.get("script", "")
    if not server_ids or "::" not in combined:
        abort(400, "Sélection invalide")

    folder, script_name = combined.split("::", 1)
    if not folder or not script_name or folder != os.path.basename(folder) or script_name != os.path.basename(script_name):
        abort(400, "Script invalide")
    if len(folder) > 64 or len(script_name) > 128 or not script_name.endswith(".sh"):
        abort(400, "Script invalide")

    servers = get_configured_servers()
    accessible_servers = _accessible_servers(current_user, servers)
    script_path = _safe_script_path(current_app.config["DATA_DIR"], folder, script_name)
    if script_path is None:
        abort(400, "Script introuvable ou invalide")

    valid_server_ids = [sid for sid in dict.fromkeys(server_ids) if sid in accessible_servers]
    if not valid_server_ids:
        abort(400, "Aucun serveur valide sélectionné (ou accès non autorisé)")

    # v1.2 (H2): read the script's bytes exactly once, here, and hash them.
    # Every execution created below runs from its own private copy of these
    # exact bytes (see snapshot_path), not by re-reading the source script
    # file later — closing the window where the source file could be edited
    # between this check and the moment ssh_runner actually uploads it.
    try:
        script_bytes = script_path.read_bytes()
    except OSError:
        abort(400, "Script illisible")
    script_sha256 = hashlib.sha256(script_bytes).hexdigest()

    per_user_limit = current_app.config["MAX_CONCURRENT_EXECUTIONS_PER_USER"]
    global_limit = current_app.config["MAX_GLOBAL_CONCURRENT_EXECUTIONS"]
    per_server_limit = current_app.config["MAX_CONCURRENT_EXECUTIONS_PER_SERVER"]
    log_dir = Path(get_log_dir(current_app.config["DATA_DIR"]))
    created = []  # list of (execution_id, srv, log_filename, snapshot_path)

    # v1.1: reserve the quota atomically. "BEGIN IMMEDIATE" takes SQLite's
    # write lock right away, so a concurrent /run (same user, or anyone else
    # for the global/per-server caps) cannot interleave between the COUNTs
    # below and the INSERTs that follow — closing the race a plain
    # "count then insert" would have. Any earlier read in this request (e.g.
    # Flask-Login loading current_user) may have opened an implicit
    # transaction, so end it first.
    db.session.commit()
    db.session.execute(text("BEGIN IMMEDIATE"))
    committed = False
    try:
        running_count = Execution.query.filter_by(user_id=current_user.id, status="running").count()
        if running_count + len(valid_server_ids) > per_user_limit:
            abort(
                429,
                f"Trop d'exécutions en cours ({running_count} en cours, "
                f"{len(valid_server_ids)} demandées, limite {per_user_limit}). "
                "Attends la fin d'une exécution ou réduis le nombre de cibles.",
            )

        global_running_count = Execution.query.filter_by(status="running").count()
        if global_running_count + len(valid_server_ids) > global_limit:
            abort(
                429,
                f"Trop d'exécutions en cours sur l'instance ({global_running_count}/{global_limit}). "
                "Réessaie plus tard ou augmente MAX_GLOBAL_CONCURRENT_EXECUTIONS.",
            )

        # v1.2 (M7): a per-user (or global) cap alone still lets several
        # accounts pile onto the very same target host at once.
        requested_per_server = Counter(valid_server_ids)
        for server_id, requested in requested_per_server.items():
            server_running = Execution.query.filter_by(server_id=server_id, status="running").count()
            if server_running + requested > per_server_limit:
                label = accessible_servers[server_id]["label"]
                abort(
                    429,
                    f"Trop d'exécutions en cours sur {label} ({server_running}/{per_server_limit}). "
                    "Réessaie plus tard ou augmente MAX_CONCURRENT_EXECUTIONS_PER_SERVER.",
                )

        for server_id in valid_server_ids:
            srv = accessible_servers[server_id]
            execution = Execution(
                user_id=current_user.id,
                server_id=server_id,
                server_host=srv["host"],
                category=folder,
                script_name=script_name,
                status="running",
                log_filename="pending",
                triggered_by=current_user.username,
                script_sha256=script_sha256,
            )
            db.session.add(execution)
            db.session.flush()
            log_filename = f"execution_{execution.id}.log"
            execution.log_filename = log_filename
            # v1.2 (H2): private per-execution snapshot, stored alongside logs
            # (already excluded from the script browser). Deleted by
            # ssh_runner once this execution finishes.
            snapshot_path = log_dir / f"execution_{execution.id}.sh.snapshot"
            try:
                snapshot_path.write_bytes(script_bytes)
                os.chmod(snapshot_path, 0o600)
            except OSError:
                abort(500, "Impossible d'enregistrer une copie du script à exécuter")
            created.append((execution.id, srv, log_filename, str(snapshot_path)))
        db.session.commit()
        committed = True
    finally:
        if not committed:
            db.session.rollback()

    if not created:
        abort(400, "Aucun serveur valide sélectionné")

    app_obj = current_app._get_current_object()
    for execution_id, srv, log_filename, snapshot_path in created:
        start_interactive_session(
            app_obj, socketio, execution_id, srv, snapshot_path, str(log_dir / log_filename),
            script_sha256=script_sha256,
        )

    return redirect(url_for("main.terminal", ids=",".join(str(eid) for eid, _, _, _ in created)))


@main_bp.route("/terminal")
@login_required
def terminal():
    ids_param = request.args.get("ids", "")
    raw_ids = ids_param.split(",")
    if len(raw_ids) > 50 or any(i and not i.isdigit() for i in raw_ids):
        abort(400, "Identifiants invalides")
    ids = [int(i) for i in raw_ids if i]
    if not ids:
        abort(400, "Aucune exécution spécifiée")

    executions = _owned_executions_query().filter(Execution.id.in_(ids)).order_by(Execution.id).all()
    if len(executions) != len(set(ids)):
        abort(403)

    servers = get_configured_servers()
    labels = {sid: srv["label"] for sid, srv in servers.items()}
    initial_logs = {}
    log_dir = Path(get_log_dir(current_app.config["DATA_DIR"]))
    for execution in executions:
        log_path = log_dir / execution.log_filename
        try:
            if log_path.name == execution.log_filename and log_path.is_file() and not log_path.is_symlink():
                initial_logs[execution.id] = _read_log_capped(log_path, current_app.config["MAX_LOG_READ_BYTES"])
        except OSError:
            initial_logs[execution.id] = ""
    return render_template(
        "terminal.html",
        executions=executions,
        labels=labels,
        initial_logs=initial_logs,
    )


@main_bp.route("/log/<int:execution_id>")
@login_required
def view_log(execution_id):
    execution = db.session.get(Execution, execution_id)
    if not execution or not can_access_execution(execution):
        abort(404)

    log_path = Path(get_log_dir(current_app.config["DATA_DIR"])) / execution.log_filename
    if log_path.name != execution.log_filename:
        abort(404)
    content = ""
    try:
        if log_path.is_file() and not log_path.is_symlink():
            content = _read_log_capped(log_path, current_app.config["MAX_LOG_READ_BYTES"])
    except OSError:
        content = ""
    return render_template("log_view.html", execution=execution, content=content)
