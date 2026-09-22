from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_no_env_or_local_state_in_repo():
    assert not (ROOT / ".env").exists()
    instance = ROOT / "instance"
    assert not (instance / "scripter.db").exists()
    assert not (instance / "secret_key").exists()


def test_sudo_is_opt_in_and_noninteractive():
    text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert 'srv.get("use_sudo", False)' in text
    assert 'sudo -n --' in text
    assert 'sudo_wrapper' in text


def test_ssh_host_key_policy_is_strict():
    text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert "RejectPolicy" in text
    assert "AutoAddPolicy" not in text


def test_admin_template_has_no_inline_username_javascript():
    text = (ROOT / "app" / "templates" / "admin.html").read_text()
    assert "onsubmit=" not in text


def test_socketio_does_not_default_to_wildcard_cors():
    text = (ROOT / "app" / "__init__.py").read_text()
    assert "cors_allowed_origins=socket_origin if socket_origin else []" in text


def test_sudo_wrapper_is_root_execution_boundary():
    text = (ROOT / "deploy" / "scripter-run").read_text()
    assert "/tmp/scripter-????????????????????????????????.sh" in text
    assert "if [ ! -f \"$script\" ]" in text
    assert "[ -L \"$script\" ]" in text
    assert "exec /bin/sh -- \"$script\"" in text


def test_version_is_0_3_x_and_ui_reads_it():
    version = (ROOT / "VERSION").read_text().strip()
    assert version.startswith("0.3.")
    text = (ROOT / "app" / "templates" / "base.html").read_text()
    assert "APP_VERSION" in text
    assert "v0.2.2" not in text


def test_default_admin_credentials_are_admin_admin():
    text = (ROOT / "app" / "__init__.py").read_text()
    assert 'os.environ.get("DEFAULT_ADMIN_USER", "admin")' in text
    assert 'os.environ.get("DEFAULT_ADMIN_PASS", "admin")' in text
