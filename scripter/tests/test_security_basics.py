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


def test_version_is_1_x_and_ui_reads_it():
    version = (ROOT / "VERSION").read_text().strip()
    assert version.startswith("1.")
    text = (ROOT / "app" / "templates" / "base.html").read_text()
    assert "APP_VERSION" in text
    assert "v0.2.2" not in text


def test_default_admin_credentials_are_admin_admin():
    text = (ROOT / "app" / "__init__.py").read_text()
    assert 'os.environ.get("DEFAULT_ADMIN_USER", "admin")' in text
    assert 'os.environ.get("DEFAULT_ADMIN_PASS", "admin")' in text


def test_compose_persists_instance_on_host_data_and_scripts_on_data_dir():
    text = (ROOT.parent / "docker-compose.yml").read_text()
    assert "./data:/usr/src/app/instance" in text
    assert "./scripts:/usr/src/app/data" in text
    assert "./scripter/instance:/usr/src/app/instance" not in text
    assert 'DATA_DIR: /usr/src/app/data' in text

def test_admin_created_accounts_require_a_minimum_length_but_default_admin_does_not():
    admin_text = (ROOT / "app" / "admin.py").read_text()
    init_text = (ROOT / "app" / "__init__.py").read_text()
    # v1.2: an admin choosing a password on someone else's behalf gets a
    # minimum length, but DEFAULT_ADMIN_PASS (chosen for yourself) still
    # doesn't — that distinction is deliberate, see SECURITY.md.
    assert "len(password) < 8" in admin_text
    assert "len(password) > 1024" in admin_text
    assert 'os.environ.get("DEFAULT_ADMIN_PASS", "admin")' in init_text
    assert "len(default_pass)" not in init_text


def test_initial_admin_defaults_are_not_length_restricted():
    text = (ROOT / "app" / "__init__.py").read_text()
    assert 'os.environ.get("DEFAULT_ADMIN_PASS", "admin")' in text
    assert "12 caractères" not in text
    assert "len(default_pass)" not in text



def test_dashboard_javascript_is_external_and_version_is_copied_into_image():
    dashboard = (ROOT / "app" / "templates" / "dashboard.html").read_text()
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "<script>" not in dashboard
    assert "dashboard.js" in dashboard
    assert "COPY VERSION ." in dockerfile
    assert (ROOT / "app" / "static" / "js" / "dashboard.js").exists()


def test_terminal_javascript_is_external_and_carries_csrf_via_data_attribute():
    terminal = (ROOT / "app" / "templates" / "terminal.html").read_text()
    javascript = ROOT / "app" / "static" / "js" / "terminal.js"
    assert "<script>" not in terminal
    assert "js/terminal.js" in terminal
    assert "data-csrf-token" in terminal
    assert javascript.exists()
    js_text = javascript.read_text()
    assert 'socket.emit("join"' in js_text
    assert 'socket.emit("terminal_input"' in js_text

def test_version_is_1_2_0():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "1.2.0"


def test_terminal_replays_existing_log_and_status():
    terminal = (ROOT / "app" / "templates" / "terminal.html").read_text()
    main = (ROOT / "app" / "main.py").read_text()
    assert 'initial_logs.get(e.id, "")' in terminal
    assert 'e.status == "running"' in terminal
    assert 'initial_logs = {}' in main


# --- v1.0 hardening -------------------------------------------------------

def test_per_user_concurrent_execution_limit_is_enforced():
    text = (ROOT / "app" / "main.py").read_text()
    assert 'MAX_CONCURRENT_EXECUTIONS_PER_USER' in text
    assert 'status="running"' in text
    assert "running_count + len(valid_server_ids) > per_user_limit" in text


def test_execution_output_is_capped():
    init_text = (ROOT / "app" / "__init__.py").read_text()
    runner_text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert 'MAX_EXECUTION_OUTPUT_BYTES' in init_text
    assert "_OutputLimitExceeded" in runner_text
    assert "total_output_bytes > max_output_bytes" in runner_text


def test_forced_stop_attempts_best_effort_remote_kill():
    text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert "_best_effort_kill_remote" in text
    assert "pkill -9 -f --" in text
    # Called on both timeout and output-overflow forced stops, not on a
    # normal completed execution.
    assert "forced_stop = isinstance(exc, (TimeoutError, _OutputLimitExceeded))" in text


def test_websocket_revalidates_session_revocation():
    text = (ROOT / "app" / "sockets.py").read_text()
    assert "_session_still_valid" in text
    assert 'session.get("sv") == current_user.session_version' in text
    # Both handlers must use it, not just current_user.is_authenticated.
    assert "not current_user.is_authenticated or not _valid_csrf(data)" not in text


def test_csp_has_no_external_script_source_and_no_wildcard_ws_scheme():
    text = (ROOT / "app" / "__init__.py").read_text()
    assert "script-src 'self'; " in text
    assert "cdnjs.cloudflare.com" not in text
    assert "connect-src 'self' ws: wss:" not in text


def test_socketio_client_is_vendored_locally_not_from_a_cdn():
    terminal = (ROOT / "app" / "templates" / "terminal.html").read_text()
    assert "cdnjs.cloudflare.com" not in terminal
    assert "js/vendor/socket.io.min.js" in terminal
    assert (ROOT / "app" / "static" / "js" / "vendor" / "socket.io.min.js").exists()


# --- v1.1 hardening -------------------------------------------------------

def test_sudo_servers_are_admin_only_by_default():
    text = (ROOT / "app" / "main.py").read_text()
    assert "_accessible_servers" in text
    assert 'if srv.get("use_sudo"):' in text
    assert "SSH_ALLOWED_USERS_" in text
    # Both the dashboard and /run must apply the same access filter.
    assert text.count("_accessible_servers(current_user") >= 2


def test_execution_quota_reservation_is_transactional():
    text = (ROOT / "app" / "main.py").read_text()
    assert "BEGIN IMMEDIATE" in text
    assert "MAX_GLOBAL_CONCURRENT_EXECUTIONS" in text
    # The per-user and global counts must both be taken, and rolled back on
    # abort, inside the same reserved transaction.
    assert "if not committed:" in text
    assert "db.session.rollback()" in text


def test_orphaned_running_executions_are_reaped_on_startup():
    init_text = (ROOT / "app" / "__init__.py").read_text()
    assert "_reap_orphaned_executions" in init_text
    assert 'status="running"' in init_text
    assert "_reap_orphaned_executions(app)" in init_text


def test_script_listing_caps_stop_the_whole_scan():
    text = (ROOT / "app" / "main.py").read_text()
    # The cap check must appear before the inner per-file loop starts (i.e.
    # guard the outer folder loop too), not just inside it.
    outer_check_idx = text.index("if listed >= limit_count or total_bytes >= limit_bytes:")
    inner_loop_idx = text.index("for file in sorted(folder_entry.iterdir()")
    assert outer_check_idx < inner_loop_idx


# --- v1.2 hardening -------------------------------------------------------

def test_scripter_run_wrapper_has_a_privileged_kill_mode():
    text = (ROOT / "deploy" / "scripter-run").read_text()
    assert '"$1" = "--kill"' in text
    assert "pkill -9 -f -- \"$path\"" in text
    # Same script-path validation pattern must guard the kill mode too.
    assert text.count("/tmp/scripter-????????????????????????????????.sh)") == 2


def test_forced_stop_tries_privileged_kill_before_plain_pkill_in_sudo_mode():
    text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert "srv.get(\"sudo_wrapper\")" in text or 'srv["sudo_wrapper"]' in text
    assert "--kill" in text
    assert "_best_effort_kill_remote(ssh, remote_path, srv)" in text


def test_script_bytes_are_hashed_and_snapshotted_once_at_run_time():
    main_text = (ROOT / "app" / "main.py").read_text()
    models_text = (ROOT / "app" / "models.py").read_text()
    ssh_runner_text = (ROOT / "app" / "ssh_runner.py").read_text()
    assert "hashlib.sha256(script_bytes).hexdigest()" in main_text
    assert ".sh.snapshot" in main_text
    assert "script_sha256" in models_text
    # The snapshot, not the original source path, must be what gets executed
    # and later cleaned up.
    assert "os.remove(script_path)" in ssh_runner_text


def test_per_server_concurrent_execution_limit_is_enforced():
    text = (ROOT / "app" / "main.py").read_text()
    assert "MAX_CONCURRENT_EXECUTIONS_PER_SERVER" in text
    assert "server_running + requested > per_server_limit" in text


def test_log_reads_are_capped():
    init_text = (ROOT / "app" / "__init__.py").read_text()
    main_text = (ROOT / "app" / "main.py").read_text()
    assert "MAX_LOG_READ_BYTES" in init_text
    assert "_read_log_capped" in main_text
    assert main_text.count("_read_log_capped(log_path") >= 1


def test_login_attempt_log_is_purged_on_a_retention_window():
    init_text = (ROOT / "app" / "__init__.py").read_text()
    assert "LOGIN_ATTEMPT_LOG_RETENTION_DAYS" in init_text
    assert "_purge_old_login_attempt_logs" in init_text
    assert "_purge_old_login_attempt_logs(app)" in init_text


def test_per_account_lockout_is_progressive_not_a_hard_lock():
    auth_text = (ROOT / "app" / "auth.py").read_text()
    models_text = (ROOT / "app" / "models.py").read_text()
    assert "AccountAttempt" in models_text
    assert "ACCOUNT_LOCKOUT_STEPS_MINUTES" in auth_text
    assert "is_account_locked" in auth_text
    # Must escalate rather than lock forever: more than one distinct non-zero
    # delay step, and it must reset on success.
    assert "register_account_successful_attempt" in auth_text
    steps = [int(n) for n in __import__("re").findall(
        r"ACCOUNT_LOCKOUT_STEPS_MINUTES = \[([\d, ]+)\]", auth_text
    )[0].split(",")]
    assert len(set(s for s in steps if s > 0)) > 1
