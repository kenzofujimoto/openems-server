"""Windows service entry point; install using install_service.ps1 as administrator."""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
from collections.abc import Callable
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlsplit

# Isolated Python invocations intentionally ignore PYTHONPATH and user packages.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import openems_agent as agent

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    HAVE_PYWIN32 = True
except ImportError:
    HAVE_PYWIN32 = False

_DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "openems"
CONFIG_PATH = str(_DATA_DIR / "agent.json")
LOG_PATH = str(_DATA_DIR / "agent.log")
_LOG_LOCK = threading.Lock()


def load_config(path: str = CONFIG_PATH) -> agent.AgentConfig:
    """Read legacy BOM files too; never coerce truthy strings or numeric identities."""
    with open(path, encoding="utf-8-sig") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("Agent configuration must be an object")
    text_fields = {"server", "devid", "vdom", "hosts_path", "state_path", "invitation", "device_token"}
    bool_fields = {"block_page", "dry_run", "allow_insecure_http"}
    int_fields = {"interval", "block_page_port"}
    if data.keys() - text_fields - bool_fields - int_fields:
        raise ValueError("Unknown agent configuration option")
    for name in text_fields & data.keys():
        if not isinstance(data[name], str) or not data[name].strip():
            raise ValueError(f"Invalid configuration option: {name}")
    for name in bool_fields & data.keys():
        if type(data[name]) is not bool:
            raise ValueError(f"Invalid configuration option: {name}")
    for name in int_fields & data.keys():
        if type(data[name]) is not int:
            raise ValueError(f"Invalid configuration option: {name}")
    if not {"server", "devid"} <= data.keys():
        raise ValueError("Server and device identity are required")
    endpoint = urlsplit(data["server"])
    if endpoint.scheme not in {"http", "https"} or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError("Invalid server URL")
    if endpoint.query or endpoint.fragment:
        raise ValueError("Server URL cannot contain a query or fragment")
    if data.get("interval", 15) < 1 or not 1 <= data.get("block_page_port", 80) <= 65535:
        raise ValueError("Interval and port must be within their valid ranges")
    data["server"] = data["server"].rstrip("/")
    data.setdefault("state_path", str(Path(path).with_name("state.json")))
    return agent.AgentConfig(**data)


class _StrictRotatingFileHandler(RotatingFileHandler):
    def handleError(self, record: logging.LogRecord) -> None:
        raise OSError("log write failed")


def _make_log_handler() -> RotatingFileHandler:
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    handler = _StrictRotatingFileHandler(LOG_PATH, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    return handler


def log(msg: str) -> None:
    # A short lived handler also recovers if a disk/log ACL is repaired.
    try:
        with _LOG_LOCK:
            handler = _make_log_handler()
            try:
                record = logging.LogRecord("openems", logging.INFO, "", 0, str(msg), (), None)
                handler.emit(record)
            finally:
                handler.close()
    except OSError:
        sys.stderr.write("openems service log unavailable\n")
        if HAVE_PYWIN32:
            servicemanager.LogErrorMsg("openems service log unavailable")


def run_loop(stop_event: threading.Event) -> None:
    """Use the same cache, registration, ACK and enforcement path as the CLI."""
    agent.run(load_config(), log=log, stop_event=stop_event)


class _UnexpectedWorkerExit(RuntimeError):
    pass


def supervise(stop_event: threading.Event, wait: Callable[[], object], wake: Callable[[], object]) -> None:
    """Wake the SCM thread when the worker stops, including unexpected failures."""
    failures: list[Exception] = []

    def execute() -> None:
        try:
            run_loop(stop_event)
            if not stop_event.is_set():
                raise _UnexpectedWorkerExit("Agent worker exited unexpectedly")
        except Exception as exc:
            failures.append(exc)
        finally:
            wake()

    worker = threading.Thread(target=execute, name="openems-agent", daemon=True)
    worker.start()
    try:
        wait()
    finally:
        stop_event.set()
        worker.join(timeout=30)
    if worker.is_alive():
        raise RuntimeError("Agent worker did not stop within 30 seconds")
    if failures:
        if isinstance(failures[0], _UnexpectedWorkerExit):
            raise RuntimeError("Agent worker exited unexpectedly") from failures[0]
        raise RuntimeError(f"Agent worker failed ({type(failures[0]).__name__})") from failures[0]


if HAVE_PYWIN32:

    class OpenemsAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "openems-agent"
        _svc_display_name_ = "openems endpoint agent"
        _svc_description_ = "Enforces server-defined web/app policy locally (openems)."

        def __init__(self, args):
            super().__init__(args)
            self._wait = win32event.CreateEvent(None, 0, 0, None)
            self._stop = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self._stop.set()
            win32event.SetEvent(self._wait)

        def SvcDoRun(self):
            try:
                supervise(
                    self._stop,
                    lambda: win32event.WaitForSingleObject(self._wait, win32event.INFINITE),
                    lambda: win32event.SetEvent(self._wait),
                )
            except Exception as exc:
                message = f"openems agent service failed ({type(exc).__name__}); inspect configuration and logs"
                log(message)
                servicemanager.LogErrorMsg(message)
                self.ReportServiceStatus(win32service.SERVICE_STOPPED, win32ExitCode=1066, svcExitCode=1)
                # The native service host records unhandled tracebacks too.
                raise RuntimeError(message) from None


if __name__ == "__main__":
    if sys.argv[1:] == ["cleanup-hosts"]:
        agent.clear_hosts(load_config().hosts_path)
    else:
        if not HAVE_PYWIN32:
            raise SystemExit("pywin32 is required: install agent/requirements.txt")
        win32serviceutil.HandleCommandLine(OpenemsAgentService)
