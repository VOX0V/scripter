import os
import shlex
import uuid
from datetime import datetime

import paramiko

LOG_DIR_NAME = "logs"
active_channels = {}


def get_log_dir(data_dir: str) -> str:
    log_dir = os.path.join(data_dir, LOG_DIR_NAME)
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def start_interactive_session(app, socketio, execution_id, srv, script_path, log_path):
    socketio.start_background_task(
        _run_interactive, app, socketio, execution_id, srv, script_path, log_path
    )


def send_input(execution_id: int, text: str) -> bool:
    if not isinstance(text, str) or len(text) > 4096:
        return False
    chan = active_channels.get(execution_id)
    if chan and not chan.closed:
        chan.send(text)
        return True
    return False


def _known_hosts(ssh):
    ssh.load_system_host_keys()
    custom = os.environ.get("SSH_KNOWN_HOSTS")
    if custom:
        ssh.load_host_keys(os.path.expanduser(custom))
    ssh.set_missing_host_key_policy(paramiko.RejectPolicy())


def _run_interactive(app, socketio, execution_id, srv, script_path, log_path):
    from app import db
    from app.models import Execution

    room = str(execution_id)
    ssh = paramiko.SSHClient()
    status = "error"
    remote_path = None
    chan = None

    def emit_output(data: str):
        socketio.emit("output", {"id": execution_id, "data": data}, room=room)

    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "w", encoding="utf-8") as log_file:
            header = (
                f"=== Exécution démarrée le {datetime.now().isoformat()} ===\n"
                f"Cible : {srv['host']}:{srv['port']}\n\n"
            )
            log_file.write(header)
            log_file.flush()
            emit_output(header)

            _known_hosts(ssh)
            connect_kwargs = {
                "hostname": srv["host"],
                "port": srv["port"],
                "username": srv["user"],
                "timeout": app.config["SSH_CONNECT_TIMEOUT"],
                "banner_timeout": app.config["SSH_CONNECT_TIMEOUT"],
                "auth_timeout": app.config["SSH_CONNECT_TIMEOUT"],
            }
            if srv.get("key_path"):
                connect_kwargs["key_filename"] = srv["key_path"]
                if srv.get("key_passphrase"):
                    connect_kwargs["passphrase"] = srv["key_passphrase"]
            else:
                connect_kwargs["password"] = srv.get("pass")

            ssh.connect(**connect_kwargs)

            # Random per-execution path prevents collisions and predictable symlink targets.
            remote_path = f"/tmp/scripter-{uuid.uuid4().hex}.sh"
            sftp = ssh.open_sftp()
            try:
                sftp.put(script_path, remote_path)
                sftp.chmod(remote_path, 0o700)
            finally:
                sftp.close()

            transport = ssh.get_transport()
            chan = transport.open_session()
            chan.get_pty()
            chan.settimeout(0.0)
            # Sudo is explicit because these scripts are intentionally arbitrary
            # code. In sudo mode, prefer a root-owned wrapper on the target host
            # (SSH_SUDO_WRAPPER) over granting a broad sudoers wildcard.
            use_sudo = srv.get("use_sudo", False)
            sudo_wrapper = srv.get("sudo_wrapper")
            if use_sudo:
                if not sudo_wrapper:
                    raise RuntimeError(
                        "SSH_USE_SUDO est activé mais SSH_SUDO_WRAPPER n'est pas configuré"
                    )
                command = f"sudo -n -- {shlex.quote(sudo_wrapper)} {shlex.quote(remote_path)}"
            else:
                command = f"/bin/sh -- {shlex.quote(remote_path)}"
            chan.exec_command(command)
            active_channels[execution_id] = chan

            started = datetime.now().timestamp()
            timeout = app.config["EXECUTION_TIMEOUT"]
            while True:
                try:
                    if chan.recv_ready():
                        raw = chan.recv(4096).decode("utf-8", errors="ignore")
                        safe = raw.replace(srv.get("pass") or "\x00", "••••••••").replace(srv.get("key_passphrase") or "\x00", "••••••••")
                        log_file.write(safe)
                        log_file.flush()
                        emit_output(safe)
                except Exception:
                    pass

                if chan.exit_status_ready() and not chan.recv_ready():
                    break
                if datetime.now().timestamp() - started > timeout:
                    raise TimeoutError(f"Timeout d'exécution après {timeout} secondes")
                socketio.sleep(0.15)

            exit_status = chan.recv_exit_status()
            status = "success" if exit_status == 0 else "error"
            footer = f"\n=== Terminé (code {exit_status}) le {datetime.now().isoformat()} ===\n"
            log_file.write(footer)
            log_file.flush()
            emit_output(footer)

    except Exception as exc:
        status = "timeout" if isinstance(exc, TimeoutError) else "error"
        err = f"\n*** Erreur : {exc} ***\n"
        try:
            with open(log_path, "a", encoding="utf-8") as log_file:
                log_file.write(err)
        except OSError:
            pass
        emit_output(err)
    finally:
        active_channels.pop(execution_id, None)
        if chan is not None:
            try:
                chan.close()
            except Exception:
                pass
        if remote_path:
            try:
                ssh.exec_command(f"rm -f -- {shlex.quote(remote_path)}")[1].channel.close()
            except Exception:
                pass
        ssh.close()

        with app.app_context():
            execution = db.session.get(Execution, execution_id)
            if execution:
                execution.status = status
                execution.finished_at = datetime.now()
                db.session.commit()

        socketio.emit("status", {"id": execution_id, "status": status}, room=room)
