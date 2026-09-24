from datetime import datetime, timedelta

from flask import Blueprint, redirect, render_template, request, session, url_for
from flask_login import login_user, logout_user, current_user

from app import db
from app.models import AccountAttempt, LoginAttempt, LoginAttemptLog, User

auth_bp = Blueprint("auth", __name__)

MAX_FAILED_ATTEMPTS = 3
BAN_DURATION_MINUTES = 60

# v1.2: per-account progressive lockout (index = fail_count, capped at the
# last value). The first two failures are free (mirrors the per-IP threshold
# below), then it escalates with repeated failures against the same
# username rather than an indefinite hard lock, and resets on the next
# success.
ACCOUNT_LOCKOUT_STEPS_MINUTES = [0, 0, 0, 1, 5, 15, 30, 60]


def get_client_ip() -> str:
    # Proxy headers are only trusted when the deployment explicitly enables them.
    if __import__("os").environ.get("TRUST_PROXY_HEADERS") == "1":
        return (
            request.headers.get("CF-Connecting-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote_addr
            or "unknown"
        )
    return request.remote_addr or "unknown"


def _get_or_create_attempt(ip_address: str) -> LoginAttempt:
    attempt = LoginAttempt.query.filter_by(ip_address=ip_address).first()
    if not attempt:
        attempt = LoginAttempt(ip_address=ip_address, fail_count=0)
        db.session.add(attempt)
    return attempt


def is_ip_banned(ip_address: str) -> bool:
    attempt = LoginAttempt.query.filter_by(ip_address=ip_address).first()
    return bool(attempt and attempt.is_banned())


def register_failed_attempt(ip_address: str) -> None:
    attempt = _get_or_create_attempt(ip_address)
    attempt.fail_count += 1
    attempt.last_attempt = datetime.now()
    if attempt.fail_count >= MAX_FAILED_ATTEMPTS:
        attempt.banned_until = datetime.now() + timedelta(minutes=BAN_DURATION_MINUTES)
    db.session.commit()


def register_successful_attempt(ip_address: str) -> None:
    attempt = LoginAttempt.query.filter_by(ip_address=ip_address).first()
    if attempt:
        attempt.fail_count = 0
        attempt.banned_until = None
        db.session.commit()


def _get_or_create_account_attempt(username: str) -> AccountAttempt:
    attempt = AccountAttempt.query.filter_by(username=username).first()
    if not attempt:
        attempt = AccountAttempt(username=username, fail_count=0)
        db.session.add(attempt)
    return attempt


def is_account_locked(username: str) -> bool:
    attempt = AccountAttempt.query.filter_by(username=username).first()
    return bool(attempt and attempt.is_locked())


def register_account_failed_attempt(username: str) -> None:
    attempt = _get_or_create_account_attempt(username)
    attempt.fail_count += 1
    attempt.last_attempt = datetime.now()
    step = ACCOUNT_LOCKOUT_STEPS_MINUTES[min(attempt.fail_count, len(ACCOUNT_LOCKOUT_STEPS_MINUTES) - 1)]
    if step > 0:
        attempt.locked_until = datetime.now() + timedelta(minutes=step)
    db.session.commit()


def register_account_successful_attempt(username: str) -> None:
    attempt = AccountAttempt.query.filter_by(username=username).first()
    if attempt:
        attempt.fail_count = 0
        attempt.locked_until = None
        db.session.commit()


@auth_bp.route("/", methods=["GET"])
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("login.html")


@auth_bp.route("/login", methods=["POST"])
def login():
    ip_address = get_client_ip()

    if is_ip_banned(ip_address):
        return render_template("login.html", error="Trop de tentatives échouées. Réessaie plus tard.")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if username and is_account_locked(username):
        return render_template(
            "login.html",
            error="Trop de tentatives échouées pour ce compte. Réessaie plus tard.",
        )

    user = User.query.filter_by(username=username).first()

    if user and user.check_password(password):
        register_successful_attempt(ip_address)
        register_account_successful_attempt(username)
        db.session.add(LoginAttemptLog(ip_address=ip_address, username_tried=username, success=True))
        db.session.commit()
        login_user(user)
        session["sv"] = user.session_version
        return redirect(url_for("main.dashboard"))

    register_failed_attempt(ip_address)
    if username:
        register_account_failed_attempt(username)
    db.session.add(LoginAttemptLog(ip_address=ip_address, username_tried=username, success=False))
    db.session.commit()
    return render_template("login.html", error="Identifiants incorrects")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("auth.login_page"))
