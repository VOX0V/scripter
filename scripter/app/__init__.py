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

    db.init_app(app)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline'; connect-src 'self' ws: wss:; "
            "img-src 'self' data:; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    login_manager.init_app(app)
    csrf.init_app(app)

    socket_origin = os.environ.get("SOCKETIO_ORIGIN")
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
        _ensure_initial_admin()

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
