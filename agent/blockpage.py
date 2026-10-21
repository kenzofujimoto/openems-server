"""Local block-page server.

When web filtering is in "block page" mode the agent points blocked domains at
127.0.0.1 instead of 0.0.0.0, so the browser lands on this tiny local server,
which serves a branded "access blocked" page for any host/path. Binding port 80
needs admin/root (same privilege the agent already needs to edit hosts).

The page is an original design using RSM's identity cues (brand green, the "RSM"
wordmark as text, the public tagline) — it does not embed RSM's logo asset.
"""

from __future__ import annotations

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_PAGE = """<!doctype html>
<html lang="pt-br"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acesso bloqueado</title>
<style>
  :root {{ --rsm:#3f9c35; --rsm-dark:#2e7d28; --ink:#2b2b2b; --muted:#6b7280; }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; min-height:100vh; display:flex; flex-direction:column;
    font:16px/1.6 "Segoe UI",system-ui,Arial,sans-serif; color:var(--ink); background:#f4f6f5; }}
  .bar {{ height:6px; background:linear-gradient(90deg,var(--rsm),var(--rsm-dark)); }}
  header {{ padding:22px 28px; display:flex; align-items:center; gap:14px; }}
  .wordmark {{ font-weight:800; font-size:30px; letter-spacing:1px; color:var(--rsm); }}
  .seg {{ color:var(--muted); font-size:13px; border-left:2px solid #d7ddd9; padding-left:12px; }}
  main {{ flex:1; display:flex; align-items:center; justify-content:center; padding:24px; }}
  .card {{ background:#fff; max-width:620px; width:100%; border:1px solid #e5e9e7;
    border-radius:16px; padding:40px; box-shadow:0 10px 40px rgba(0,0,0,.06); text-align:center; }}
  .icon {{ width:76px; height:76px; margin:0 auto 18px; }}
  h1 {{ margin:6px 0 4px; font-size:26px; }}
  .host {{ display:inline-block; margin:10px 0 18px; padding:7px 14px; background:#f0f5ef;
    border:1px solid #dce7d9; border-radius:8px; font-family:monospace; color:var(--rsm-dark); word-break:break-all; }}
  p.msg {{ color:#444; margin:0 auto; max-width:460px; }}
  footer {{ text-align:center; color:var(--muted); font-size:13px; padding:20px; }}
  .tag {{ color:var(--rsm-dark); font-weight:600; }}
</style></head>
<body>
  <div class="bar"></div>
  <header>
    <span class="wordmark">RSM</span>
    <span class="seg">Audit&nbsp;·&nbsp;Tax&nbsp;·&nbsp;Consulting</span>
  </header>
  <main>
    <div class="card">
      <svg class="icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="12" cy="12" r="10" stroke="#3f9c35" stroke-width="2"/>
        <line x1="6.3" y1="6.3" x2="17.7" y2="17.7" stroke="#3f9c35" stroke-width="2"/>
      </svg>
      <h1>Acesso bloqueado</h1>
      <div class="host">{host}</div>
      <p class="msg">Este site foi bloqueado pela pol&iacute;tica de seguran&ccedil;a da sua
      organiza&ccedil;&atilde;o. Se voc&ecirc; acredita que isto &eacute; um engano, contate o time de TI.</p>
    </div>
  </main>
  <footer>RSM &middot; <span class="tag">O poder de ser compreendido</span></footer>
</body></html>
"""


def render(host: str) -> bytes:
    safe = html.escape(host) if host else "este site"
    return _PAGE.format(host=safe).encode("utf-8")


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

    def do_POST(self) -> None:  # noqa: N802
        self._serve()

    def log_message(self, *args) -> None:  # silence
        pass


def serve(port: int = 80, bind: str = "0.0.0.0") -> None:
    ThreadingHTTPServer((bind, port), _Handler).serve_forever()


if __name__ == "__main__":
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else 80)
