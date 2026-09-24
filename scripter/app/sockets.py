from flask import session
from flask_login import current_user
from flask_wtf.csrf import validate_csrf
from flask_socketio import join_room

from app import socketio
from app.models import Execution
from app.ssh_runner import send_input


def _session_still_valid() -> bool:
    # v1.0 hardening: an admin clicking "Révoquer sessions" bumps
    # session_version, but a WebSocket connection opened before that doesn't
    # necessarily replay Flask's before_request hooks on every frame. Re-check
    # explicitly here so an active terminal is cut off too, not just future
    # HTTP page loads.
    return current_user.is_authenticated and session.get("sv") == current_user.session_version


def _authorized_execution(execution_id):
    try:
        execution_id = int(execution_id)
    except (TypeError, ValueError):
        return None
    if execution_id <= 0 or not _session_still_valid():
        return None
    execution = Execution.query.get(execution_id)
    if not execution:
        return None
    if current_user.is_admin or execution.user_id == current_user.id:
        return execution
    return None


def _valid_csrf(data):
    token = data.get("csrf") if isinstance(data, dict) else None
    if not token:
        return False
    try:
        validate_csrf(token)
        return True
    except Exception:
        return False


@socketio.on("join")
def handle_join(data):
    if not _session_still_valid() or not _valid_csrf(data):
        return
    execution = _authorized_execution(data.get("execution_id"))
    if execution:
        join_room(str(execution.id))


@socketio.on("terminal_input")
def handle_input(data):
    if not _session_still_valid() or not _valid_csrf(data):
        return
    execution = _authorized_execution(data.get("execution_id"))
    if not execution:
        return
    text = data.get("text", "")
    if not isinstance(text, str) or len(text) > 4096:
        return
    send_input(execution.id, text)
