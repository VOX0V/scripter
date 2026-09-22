import os
import socket
from datetime import datetime
from pathlib import Path

from flask import Blueprint, abort, current_app, redirect, render_template, request, url_for
from flask_login import current_user, login_required

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
        }
        i += 1
    return servers


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
    try:
        for folder_entry in sorted(root.iterdir(), key=lambda p: p.name):
            if not folder_entry.is_dir() or folder_entry.is_symlink() or folder_entry.name == "logs":
                continue
            scripts = []
            for file in sorted(folder_entry.iterdir(), key=lambda p: p.name):
                if listed >= current_app.config["MAX_SCRIPT_COUNT"]:
                    break
                if file.is_symlink() or not file.is_file() or file.suffix != ".sh":
                    continue
                try:
                    if file.stat().st_size > current_app.config["MAX_SCRIPT_SIZE"]:
                        continue
                    content = file.read_text(encoding="utf-8", errors="ignore")
                    encoded_size = len(content.encode("utf-8", errors="ignore"))
                    if total_bytes + encoded_size > current_app.config["MAX_SCRIPT_CONTENT_BYTES"]:
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
    servers = get_configured_servers()
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
    script_path = _safe_script_path(current_app.config["DATA_DIR"], folder, script_name)
    if script_path is None:
        abort(400, "Script introuvable ou invalide")

    log_dir = Path(get_log_dir(current_app.config["DATA_DIR"]))
    app_obj = current_app._get_current_object()
    created_ids = []

    for server_id in dict.fromkeys(server_ids):
        if server_id not in servers:
            continue
        srv = servers[server_id]
        execution = Execution(
            user_id=current_user.id,
            server_id=server_id,
            server_host=srv["host"],
            category=folder,
            script_name=script_name,
            status="running",
            log_filename="pending",
            triggered_by=current_user.username,
        )
        db.session.add(execution)
        db.session.flush()
        log_filename = f"execution_{execution.id}.log"
        execution.log_filename = log_filename
        db.session.commit()
        created_ids.append(execution.id)
        start_interactive_session(
            app_obj, socketio, execution.id, srv, str(script_path), str(log_dir / log_filename)
        )

    if not created_ids:
        abort(400, "Aucun serveur valide sélectionné")
    return redirect(url_for("main.terminal", ids=",".join(map(str, created_ids))))


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
    return render_template("terminal.html", executions=executions, labels=labels)


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
            content = log_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        content = ""
    return render_template("log_view.html", execution=execution, content=content)
