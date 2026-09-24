import os
import secrets
from pathlib import Path

from flask import Flask, request
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login_page"
csrf = CSRFProtect()
socketio = SocketIO(async_mode="gevent")


def get_or_create_secret_key(instance_path: str) -> str:
    key_path = Path(instance_path) / "secret_key"
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()
    key = secrets.token_hex(32)
    key_path.write_text(key, encoding="utf-8")
    key_path.chmod(0o600)
    return key


def create_app():
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    version_path = Path(__file__).resolve().parent.parent / "VERSION"
    app.config["APP_VERSION"] = version_path.read_text(encoding="utf-8").strip()

    app.config["SECRET_KEY"] = get_or_create_secret_key(app.instance_path)
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{Path(app.instance_path) / 'scripter.db'}"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("SESSION_COOKIE_SECURE", "1") != "0"
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 2 * 1024 * 1024))
    app.config["DATA_DIR"] = os.environ.get("DATA_DIR", "/usr/src/app/data")
    app.config["MAX_SCRIPT_SIZE"] = int(os.environ.get("MAX_SCRIPT_SIZE", 1024 * 1024))
    app.config["MAX_SCRIPT_COUNT"] = int(os.environ.get("MAX_SCRIPT_COUNT", 500))
    app.config["MAX_SCRIPT_CONTENT_BYTES"] = int(os.environ.get("MAX_SCRIPT_CONTENT_BYTES", 5 * 1024 * 1024))
    app.config["MAX_TERMINAL_INPUT"] = int(os.environ.get("MAX_TERMINAL_INPUT", 4096))
    app.config["EXECUTION_TIMEOUT"] = int(os.environ.get("EXECUTION_TIMEOUT", 3600))
    app.config["SSH_CONNECT_TIMEOUT"] = int(os.environ.get("SSH_CONNECT_TIMEOUT", 10))
    # v1.0 hardening: cap concurrent executions per user and total output bytes
    # per execution, to limit abuse/DoS potential of an authenticated but
    # low-privilege account (see SECURITY.md).
    app.config["MAX_CONCURRENT_EXECUTIONS_PER_USER"] = int(
        os.environ.get("MAX_CONCURRENT_EXECUTIONS_PER_USER", 3)
    )
    app.config["MAX_EXECUTION_OUTPUT_BYTES"] = int(
        os.environ.get("MAX_EXECUTION_OUTPUT_BYTES", 2 * 1024 * 1024)
    )
    # v1.1 hardening: instance-wide concurrency cap, in addition to the
    # per-user one above (a per-user cap alone still lets N accounts add up
    # to an unbounded total load on target hosts).
    app.config["MAX_GLOBAL_CONCURRENT_EXECUTIONS"] = int(
        os.environ.get("MAX_GLOBAL_CONCURRENT_EXECUTIONS", 20)
    )
    # v1.2 hardening.
    app.config["MAX_CONCURRENT_EXECUTIONS_PER_SERVER"] = int(
        os.environ.get("MAX_CONCURRENT_EXECUTIONS_PER_SERVER", 2)
    )
    # Cap how many bytes of a log file /terminal and /log/<id> will read into
    # memory/response at once. Execution output itself is already capped
    # going forward (MAX_EXECUTION_OUTPUT_BYTES above); this additionally
    # protects viewing of older, pre-cap logs.
    app.config["MAX_LOG_READ_BYTES"] = int(
        os.environ.get("MAX_LOG_READ_BYTES", 5 * 1024 * 1024)
    )
    app.config["LOGIN_ATTEMPT_LOG_RETENTION_DAYS"] = int(
        os.environ.get("LOGIN_ATTEMPT_LOG_RETENTION_DAYS", 30)
    )

    db.init_app(app)

    socket_origin = os.environ.get("SOCKETIO_ORIGIN")

    def _ws_equivalent(origin: str) -> str | None:
        # Translate an http(s) origin into its ws(s) equivalent for CSP
        # connect-src, so we never need a broad "ws: wss:" scheme wildcard.
        if origin.startswith("https://"):
            return "wss://" + origin[len("https://"):]
        if origin.startswith("http://"):
            return "ws://" + origin[len("http://"):]
        return None

    connect_src = "'self'"
    if socket_origin:
        ws_origin = _ws_equivalent(socket_origin)
        if ws_origin:
            connect_src += f" {ws_origin}"

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            f"style-src 'self' 'unsafe-inline'; connect-src {connect_src}; "
            "img-src 'self' data:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    login_manager.init_app(app)
    csrf.init_app(app)

    # Empty list disables cross-origin Socket.IO requests. Set an explicit origin
    # only when the reverse proxy/browser deployment genuinely requires one.
    socketio.init_app(app, cors_allowed_origins=socket_origin if socket_origin else [])

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    from app.auth import auth_bp
    from app.main import main_bp
    from app.admin import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)

    from app import sockets  # noqa: F401

    @app.before_request
    def check_session_revocation():
        from flask import session
        from flask_login import current_user, logout_user

        if current_user.is_authenticated and session.get("sv") != current_user.session_version:
            logout_user()
            session.clear()

    with app.app_context():
        db.create_all()
        _migrate_execution_ownership()
        _migrate_script_hash_column()
        _ensure_initial_admin()
        _reap_orphaned_executions(app)
        _purge_old_login_attempt_logs(app)

    return app


def _migrate_execution_ownership():
    """Small SQLite migration for installations created before v0.2."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if "executions" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("executions")}
    if "user_id" not in columns:
        db.session.execute(text("ALTER TABLE executions ADD COLUMN user_id INTEGER"))
        db.session.commit()

    # Recover ownership for old rows when the triggering username still exists.
    db.session.execute(text("""
        UPDATE executions
        SET user_id = (SELECT id FROM users WHERE users.username = executions.triggered_by)
        WHERE user_id IS NULL
    """))
    db.session.commit()


def _reap_orphaned_executions(app):
    """v1.1 watchdog: an Execution row is written as "running" as soon as
    it's created, before the background SSH task is actually confirmed to
    have started (see app/main.py:run_script). If the process crashes,
    is killed, or is restarted while executions are in flight, those rows
    are left "running" forever — silently consuming the owner's concurrency
    quota and showing a misleading status. There is no way to know the
    execution's real remote outcome after a restart, so mark it as failed
    and note why, rather than leaving it stuck.
    """
    from app.models import Execution
    from app.ssh_runner import get_log_dir
    from datetime import datetime

    orphans = Execution.query.filter_by(status="running").all()
    if not orphans:
        return
    log_dir = Path(get_log_dir(app.config["DATA_DIR"]))
    note = (
        "\n*** Marquée en erreur au démarrage de Scripter : le processus a "
        "redémarré ou a été interrompu pendant que cette exécution était en "
        "cours. Son état réel sur la machine cible est inconnu. ***\n"
    )
    for execution in orphans:
        execution.status = "error"
        execution.finished_at = datetime.now()
        try:
            log_path = log_dir / execution.log_filename
            if log_path.name == execution.log_filename:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(note)
        except OSError:
            pass
        # v1.2: a snapshot (see main.py run_script / H2) is only ever cleaned
        # up by ssh_runner once its execution finishes normally; a crash
        # before that leaves it behind, so sweep it here too.
        try:
            (log_dir / f"execution_{execution.id}.sh.snapshot").unlink(missing_ok=True)
        except OSError:
            pass
    db.session.commit()


def _migrate_script_hash_column():
    """v1.2 migration: add Execution.script_sha256 for installations upgrading
    from an earlier version."""
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if "executions" not in inspector.get_table_names():
        return
    columns = {c["name"] for c in inspector.get_columns("executions")}
    if "script_sha256" not in columns:
        db.session.execute(text("ALTER TABLE executions ADD COLUMN script_sha256 VARCHAR(64)"))
        db.session.commit()


def _purge_old_login_attempt_logs(app):
    """v1.2: LoginAttemptLog previously grew forever. Keep only the last
    LOGIN_ATTEMPT_LOG_RETENTION_DAYS days at each startup."""
    from datetime import datetime, timedelta

    from app.models import LoginAttemptLog

    cutoff = datetime.now() - timedelta(days=app.config["LOGIN_ATTEMPT_LOG_RETENTION_DAYS"])
    LoginAttemptLog.query.filter(LoginAttemptLog.attempted_at < cutoff).delete()
    db.session.commit()


def _ensure_initial_admin():
    from app.models import User

    if User.query.count() != 0:
        return

    default_user = os.environ.get("DEFAULT_ADMIN_USER", "admin")
    default_pass = os.environ.get("DEFAULT_ADMIN_PASS", "admin")

    admin = User(username=default_user, is_admin=True)
    admin.set_password(default_pass)
    db.session.add(admin)
    db.session.commit()
