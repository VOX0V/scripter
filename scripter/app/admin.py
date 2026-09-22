from functools import wraps

from flask import Blueprint, abort, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.models import LoginAttempt, LoginAttemptLog, User

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


@admin_bp.route("/")
@login_required
@admin_required
def admin_home():
    users = User.query.order_by(User.username).all()
    banned_ips = (
        LoginAttempt.query.filter(LoginAttempt.banned_until.isnot(None))
        .order_by(LoginAttempt.last_attempt.desc())
        .all()
    )
    recent_attempts = (
        LoginAttemptLog.query.order_by(LoginAttemptLog.attempted_at.desc())
        .limit(50)
        .all()
    )
    return render_template(
        "admin.html", users=users, banned_ips=banned_ips, recent_attempts=recent_attempts
    )


@admin_bp.route("/users/add", methods=["POST"])
@login_required
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    is_admin = request.form.get("is_admin") == "on"

    if not username or not password:
        abort(400, "Nom d'utilisateur et mot de passe requis")
    if len(username) > 80 or not username.replace("_", "").replace("-", "").isalnum():
        abort(400, "Nom d'utilisateur invalide")
    if len(password) < 12 or len(password) > 1024:
        abort(400, "Le mot de passe doit contenir entre 12 et 1024 caractères")

    if User.query.filter_by(username=username).first():
        abort(400, "Cet utilisateur existe déjà")

    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for("admin.admin_home"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        abort(400, "Impossible de supprimer son propre compte")

    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("admin.admin_home"))


@admin_bp.route("/users/<int:user_id>/revoke", methods=["POST"])
@login_required
@admin_required
def revoke_sessions(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.revoke_sessions()
    db.session.commit()
    return redirect(url_for("admin.admin_home"))


@admin_bp.route("/bans/<int:ban_id>/unban", methods=["POST"])
@login_required
@admin_required
def unban(ban_id):
    attempt = db.session.get(LoginAttempt, ban_id)
    if not attempt:
        abort(404)
    attempt.fail_count = 0
    attempt.banned_until = None
    db.session.commit()
    return redirect(url_for("admin.admin_home"))
