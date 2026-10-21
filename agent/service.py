"""openems agent as a Windows service (LocalSystem, auto-start at boot).

Why a service: running under LocalSystem means the policy is enforced
continuously, independent of who is logged in, and a **standard (non-admin)
user cannot stop it or bypass it** — stopping the service, editing the hosts
file (ACL-protected) and uninstalling all require administrator rights.

  Honest limit: a local **administrator** can always stop/remove any service
  (Windows trust model), so "only bypassable with admin" is the real guarantee —
  the same as every endpoint agent, FortiClient included.

Install (run an elevated / Administrator shell):
    pip install pywin32
    python service.py install
    python service.py start
Config is read from C:\\ProgramData\\openems\\agent.json
(see install_service.ps1, which writes it for you).

Commands: install | start | stop | remove | restart.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone

import openems_agent as agent

try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    HAVE_PYWIN32 = True
except ImportError:
    HAVE_PYWIN32 = False

CONFIG_PATH = r"C:\ProgramData\openems\agent.json"
LOG_PATH = r"C:\ProgramData\openems\agent.log"


def load_config(path: str = CONFIG_PATH) -> agent.AgentConfig:
    with open(path, encoding="utf-8") as fh:
        d = json.load(fh)
    return agent.AgentConfig(
        server=str(d["server"]).rstrip("/"),
        devid=str(d["devid"]),
        vdom=str(d.get("vdom", "Default")),
        hosts_path=str(d.get("hosts_path", agent.DEFAULT_HOSTS)),
        interval=int(d.get("interval", 15)),
    )


def log(msg: str) -> None:
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"{datetime.now(timezone.utc).isoformat()} {msg}\n")
    except OSError:
        pass


def run_loop(stop_event: threading.Event) -> None:
    """Register once, then enforce + report on each interval until stopped."""
    try:
        cfg = load_config()
    except Exception as e:
        log(f"config error: {e!r}")
        return
    client_id = None
    while not stop_event.is_set():
        try:
            if client_id is None:
                client_id = agent.register(cfg)
                log(f"registered client_id={client_id}")
            result = agent.enforce(cfg, agent.fetch_profile(cfg, client_id), log=log)
            agent.report_host_tags(cfg, client_id, agent.compute_host_tags(cfg, result))
        except Exception as e:
            log(f"loop error: {e!r}")
            client_id = None  # re-register next cycle
        stop_event.wait(cfg.interval)
    log("service stopped")


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
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            worker = threading.Thread(target=run_loop, args=(self._stop,), daemon=True)
            worker.start()
            win32event.WaitForSingleObject(self._wait, win32event.INFINITE)


if __name__ == "__main__":
    if not HAVE_PYWIN32:
        raise SystemExit("pywin32 is required: pip install pywin32")
    win32serviceutil.HandleCommandLine(OpenemsAgentService)
