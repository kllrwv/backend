"""Read-only Docker telemetry and allowlisted operations for the API's local spool."""
import datetime
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

ROOT = Path("/root/killerwave")
SPOOL = ROOT / "ops-state"
ENV_FILE = ROOT / ".env"
RUNTIME_UID = 10001
SERVICES = ("gateway", "web", "admin", "api", "postgres")
ENV_KEYS = {
    "SMTP_HOST", "SMTP_PORT", "SMTP_MODE", "SMTP_FROM", "SMTP_USER", "SMTP_PASSWORD",
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_LOGIN_CLIENT_ID", "TELEGRAM_LOGIN_CLIENT_SECRET",
    "TELEGRAM_SUPPORT_CHAT_ID", "TELEGRAM_ADMIN_CHAT_ID", "S3_ENDPOINT", "S3_REGION",
    "S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_SESSION_TOKEN",
}
JOB = re.compile(r"([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})\.json\Z")


def docker(*args, timeout=100):
    return subprocess.run(
        ["docker", *args], cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=True, timeout=timeout, text=True,
    ).stdout


def compose(*args, timeout=100):
    return docker("compose", "-f", "compose.production.yaml", *args, timeout=timeout)


def rows(text):
    try:
        value = json.loads(text)
        return value if isinstance(value, list) else [value]
    except ValueError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]


def environment():
    config = json.loads(compose("config", "--format", "json", timeout=12))["services"]["api"]["environment"]
    return {key: config.get(key) for key in ENV_KEYS}


def atomic(path, content, group=0, mode=0o600):
    fd, filename = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), 0, group)
            os.fchmod(stream.fileno(), mode)
        os.replace(filename, path)
    finally:
        Path(filename).unlink(missing_ok=True)


def apply_environment(job):
    values, expected = job["values"], job["expected"]
    if not isinstance(values, dict) or not isinstance(expected, dict) or not values or values.keys() != expected.keys():
        return False
    for key, value in values.items():
        if key not in ENV_KEYS or not (value is None or isinstance(value, str) and len(value) <= 4096
                                       and not any(c in value for c in "\r\n\0")):
            return False
    current = environment()
    if all(current.get(key) == value for key, value in values.items()):
        return True
    if any(current.get(key) != value for key, value in expected.items()):
        return False
    previous = ENV_FILE.read_text()
    retained = [line for line in previous.splitlines() if line.split("=", 1)[0].strip() not in values]
    for key, value in values.items():
        if value is not None:
            escaped = value.replace("'", "\\'")
            retained.append(f"{key}='{escaped}'")
    atomic(ENV_FILE, "\n".join(retained) + "\n")
    recreate = ("up", "-d", "--no-deps", "--no-build", "--force-recreate", "--wait", "--wait-timeout", "65", "api")
    try:
        written = environment()
        if any(written.get(key) != value for key, value in values.items()):
            raise ValueError("dotenv round trip failed")
        compose(*recreate)
    except (ValueError, subprocess.SubprocessError):
        atomic(ENV_FILE, previous)
        try:
            compose(*recreate)
        except subprocess.SubprocessError:
            pass
        return False
    return True


def process(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 32_000 or info.st_uid != RUNTIME_UID:
            return False
        job = json.load(stream)
    if job.get("op") == "restart" and job.get("service") in (*SERVICES, "all"):
        args = [] if job["service"] == "all" else [job["service"]]
        compose("restart", "--timeout", "15", *args)
        return True
    if job.get("op") == "env":
        return apply_environment(job)
    return False


def get_host():
    mem = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemTotal", "MemAvailable"):
            mem[key] = int(value.split()[0]) * 1024
    disk = shutil.disk_usage(ROOT)
    return {
        "uptime": float(Path("/proc/uptime").read_text().split()[0]),
        "cpu": " / ".join(f"{load:.2f}" for load in os.getloadavg()),
        "memory": f"{(mem['MemTotal'] - mem['MemAvailable']) / 2**20:.0f} / {mem['MemTotal'] / 2**20:.0f} mib",
        "disk": f"{disk.used / 2**30:.1f} / {disk.total / 2**30:.1f} gib",
    }


def get_services():
    entries = rows(compose("ps", "-a", "--format", "json", timeout=12))
    containers = {row["Service"]: row for row in entries if row.get("Service") in SERVICES}
    running = [row["ID"] for row in containers.values() if row.get("State") == "running"]
    metrics = {}
    up = {}
    if running:
        try:
            metrics = {row["Container"]: row for row in rows(
                docker("stats", "--no-stream", "--format", "{{json .}}", *running, timeout=12))}
            started = docker("inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *running, timeout=10)
            for line in started.splitlines():
                identifier, raw = line.split(" ", 1)
                since = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
                up[identifier[:12]] = max(0, int(time.time() - since.timestamp()))
        except (subprocess.SubprocessError, ValueError, KeyError):
            pass
    data = []
    for name in SERVICES:
        entry = containers.get(name, {})
        container = entry.get("ID", "")[:12]
        usage = metrics.get(container, {})
        data.append({"name": name, "state": entry.get("State", "missing"), "health": entry.get("Health"),
                     "cpu": usage.get("CPUPerc"), "memory": usage.get("MemUsage", "").lower(), "uptime": up.get(container)})
    return data


def main():
    with (SPOOL / "runner.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state_path = SPOOL / "state.json"
        try:
            previous = json.loads(state_path.read_text())
        except (OSError, ValueError):
            previous = {}
        results = previous.get("results", {})
        for path in sorted((SPOOL / "inbox").glob("*.json"), key=lambda value: value.lstat().st_mtime):
            match = JOB.fullmatch(path.name)
            if not match:
                continue
            identity = match[1]
            if identity not in results:
                try:
                    success = process(path)
                except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
                    success = False
                results[identity] = {"success": success, "at": int(time.time())}
                # Keep the completion marker across API and host restarts before removing the input.
                previous["results"] = results
                atomic(state_path, json.dumps(previous), RUNTIME_UID, 0o640)
            path.unlink(missing_ok=True)
        results = dict(sorted(results.items(), key=lambda item: item[1]["at"])[-100:])
        state = {"host": get_host(), "services": get_services(), "env": environment(), "results": results,
                 "generated": int(time.time())}
        atomic(state_path, json.dumps(state), RUNTIME_UID, 0o640)


if __name__ == "__main__":
    main()
