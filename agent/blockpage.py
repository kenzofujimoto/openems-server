"""Local block-page server.

When web filtering is in "block page" mode the agent points blocked domains at
127.0.0.1 instead of 0.0.0.0, so the browser lands on this tiny local server,
which serves the RSM-branded "access blocked" page for any host/path. Binding
port 80 needs admin/root (same privilege the agent already needs to edit hosts).

Identity follows rsm.global/brazil: RSM blue and green, the Prelo typeface
with the same Noto Sans fallback, and the official logo. Everything is inline
so the page renders with no network access.
"""

from __future__ import annotations

import html
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Official RSM logo (rsm.global theme asset), embedded so the page never fetches it.
_LOGO = (
    "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"
)

_PAGE = """<!doctype html>
<html lang="pt-br"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acesso bloqueado</title>
<style>
  :root {{ --blue:#009cde; --blue-dark:#006e9d; --green:#3f9c35; --gray:#888b8d;
    --ink:#1f2428; --text:#515356; --line:#e7e9ec; --canvas:#f6f7f9; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; min-height:100vh; display:flex; flex-direction:column; background:var(--canvas);
    color:var(--text); font:16px/1.6 "Prelo","Noto Sans","Segoe UI","Helvetica Neue",Arial,sans-serif; }}
  .brandbar {{ display:flex; height:6px; }}
  .brandbar span:nth-child(1) {{ flex:1; background:var(--gray); }}
  .brandbar span:nth-child(2) {{ flex:2; background:var(--green); }}
  .brandbar span:nth-child(3) {{ flex:7; background:var(--blue); }}
  header {{ padding:24px 32px; }}
  header img {{ height:40px; width:auto; display:block; }}
  main {{ flex:1; display:flex; align-items:center; justify-content:center; padding:24px; }}
  .card {{ width:100%; max-width:600px; background:#fff; border:1px solid var(--line); border-radius:16px;
    padding:44px 40px; text-align:center; }}
  .badge {{ width:64px; height:64px; margin:0 auto 20px; border-radius:16px; background:#e5f5fc;
    display:flex; align-items:center; justify-content:center; }}
  h1 {{ margin:0; color:var(--ink); font-size:28px; font-weight:500; letter-spacing:-0.01em; }}
  .host {{ display:inline-block; margin:16px 0 20px; padding:8px 14px; border-radius:10px; background:var(--canvas);
    border:1px solid var(--line); color:var(--blue-dark); font:15px/1.4 Consolas,"Courier New",monospace; word-break:break-all; }}
  p {{ margin:0 auto; max-width:440px; }}
  footer {{ padding:24px; text-align:center; font-size:13px; color:var(--gray); }}
  footer strong {{ color:var(--blue-dark); font-weight:500; }}
</style></head>
<body>
  <div class="brandbar" aria-hidden="true"><span></span><span></span><span></span></div>
  <header><img src="data:image/png;base64,{logo}" alt="RSM"></header>
  <main>
    <div class="card">
      <div class="badge" aria-hidden="true">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
          <rect x="4" y="10.5" width="16" height="10" rx="2.5" stroke="#006e9d" stroke-width="1.8"/>
          <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" stroke="#006e9d" stroke-width="1.8" stroke-linecap="round"/>
          <circle cx="12" cy="15.5" r="1.4" fill="#009cde"/>
        </svg>
      </div>
      <h1>Acesso bloqueado</h1>
      <div class="host">{host}</div>
      <p>Este site foi bloqueado pela pol&iacute;tica de seguran&ccedil;a da sua organiza&ccedil;&atilde;o.
      Se voc&ecirc; acredita que isto &eacute; um engano, fale com o time de TI.</p>
    </div>
  </main>
  <footer>RSM Brasil &middot; <strong>O poder de ser compreendido</strong></footer>
</body></html>
"""


def render(host: str) -> bytes:
    safe = html.escape(host) if host else "este site"
    return _PAGE.format(host=safe, logo=_LOGO).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    def _serve(self) -> None:
        host = (self.headers.get("Host", "") or "").split(":")[0]
        body = render(host)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    do_GET = _serve

    def do_POST(self) -> None:
        self._serve()

    def log_message(self, *args) -> None:  # silence
        pass


class _LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    allow_reuse_port = False

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def create_server(port: int = 80, bind: str = "127.0.0.1") -> ThreadingHTTPServer:
    """Bind before starting the worker so callers can report startup failures."""
    return _LocalHTTPServer((bind, port), _Handler)


def serve(port: int = 80, bind: str = "127.0.0.1") -> None:
    with create_server(port, bind) as server:
        server.serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 80)
