"""Application catalog from the open winget index, matched against agent inventories.

The catalog classifies applications; it never ships binaries or signer identities. Execution rules
are expanded only from identities really observed in inventories and apply only where present.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from app.categories import _write_atomic

ATTRIBUTION = ("Application names, vendors and tags: microsoft/winget-pkgs community repository, "
               "licensed MIT. Categories regrouped by openems.")
SOURCE_URL = "https://cdn.winget.microsoft.com/cache/source2.msix"
CATALOG_FILE = "app-catalog.json"
MAX_PACKAGES = 100_000
MAX_RULES = 256

# Ordered from most to least specific: a package takes the first category whose tags it carries.
TAXONOMY: list[tuple[str, str, frozenset[str]]] = [
    ("p2p", "P2P e torrent", frozenset({"torrent", "bittorrent", "p2p", "peer-to-peer", "magnet"})),
    ("proxy_vpn", "VPN e proxy", frozenset({"vpn", "proxy", "tor", "anonymity", "censorship-circumvention"})),
    ("remote_access", "Acesso remoto", frozenset({"remote-desktop", "remote-access", "remote-control", "remote-support", "rdp", "vnc"})),
    ("crypto", "Criptomoedas", frozenset({"crypto", "cryptocurrency", "bitcoin", "mining", "blockchain", "ethereum"})),
    ("hacking", "Ferramentas de invasão", frozenset({"pentest", "penetration-testing", "hacking", "password-cracking", "exploit"})),
    ("games", "Jogos", frozenset({"game", "games", "gaming", "video-games", "games-store", "游戏"})),
    ("cloud_storage", "Armazenamento em nuvem", frozenset({"cloud-storage", "file-sync", "file-sharing", "file-hosting"})),
    ("messaging", "Chat e mensageiros", frozenset({"chat", "messenger", "messaging", "instant-messaging", "voip"})),
    ("social", "Redes sociais", frozenset({"social", "social-network", "social-media"})),
    ("media", "Áudio e vídeo", frozenset({"streaming", "music", "video-player", "media-player", "iptv", "podcast"})),
    ("browser", "Navegadores", frozenset({"browser", "web-browser", "webbrowser"})),
    ("ai", "Inteligência artificial", frozenset({"ai", "llm", "chatbot", "large-language-model", "artificial-intelligence"})),
    ("email", "E-mail", frozenset({"email", "mail", "email-client"})),
    ("download", "Gerenciadores de download", frozenset({"download-manager", "downloader"})),
]
_CATEGORY_IDS = {identifier for identifier, _, _ in TAXONOMY}
# Reviewed by openems: community tags miss or mislabel these frequently seen corporate cases.
CURATED: dict[str, str] = {
    "Discord.Discord": "messaging", "WhatsApp.WhatsApp": "messaging", "Telegram.TelegramDesktop": "messaging",
    "SlackTechnologies.Slack": "messaging", "Zoom.Zoom": "messaging", "Spotify.Spotify": "media",
    "Valve.Steam": "games", "EpicGames.EpicGamesLauncher": "games", "ElectronicArts.EADesktop": "games",
    "Ubisoft.Connect": "games", "GOG.Galaxy": "games", "BattleNet.BattleNet": "games",
    "TeamViewer.TeamViewer": "remote_access", "AnyDesk.AnyDesk": "remote_access", "RustDesk.RustDesk": "remote_access",
    "Dropbox.Dropbox": "cloud_storage", "Google.GoogleDrive": "cloud_storage", "Mega.MEGASync": "cloud_storage",
    "qBittorrent.qBittorrent": "p2p", "BitTorrent.BitTorrent": "p2p", "uTorrent.uTorrent": "p2p",
    "TorProject.TorBrowser": "proxy_vpn", "NordSecurity.NordVPN": "proxy_vpn", "ProtonTechnologies.ProtonVPN": "proxy_vpn",
}
_TABLES = {"packages", "tags2", "tags2_map", "commands2", "commands2_map", "norm_names2", "norm_publishers2", "productcodes2"}
_ARCHITECTURE = re.compile(r"\b(x64|x86|amd64|arm64|64-bit|32-bit|64bit|32bit)\b")
_VERSION = re.compile(r"\b(v?\d+(\.\d+)+|\d+)\b")
_LEGAL = {"corp", "corporation", "inc", "incorporated", "llc", "ltd", "limited", "gmbh", "co", "company",
          "sa", "ag", "bv", "srl", "plc", "pty", "kg", "sarl", "oy", "ab", "as"}
_DN_PART = re.compile(r'(?:^|,)\s*(CN|O)=("([^"]*)"|[^,]*)')


def normalize_name(raw: str) -> str:
    text = raw.lower().removesuffix(".exe")
    text = re.sub(r"\([^)]*\)", " ", text)
    text = _VERSION.sub(" ", _ARCHITECTURE.sub(" ", text))
    return re.sub(r"[^a-z0-9]", "", text)


def normalize_vendor(raw: str) -> str:
    parts = {match.group(1): (match.group(3) if match.group(3) is not None else match.group(2)) for match in _DN_PART.finditer(raw)}
    text = (parts.get("O") or parts.get("CN") or raw).lower()
    words = [word for word in re.split(r"[^a-z0-9]+", text) if word and word not in _LEGAL]
    return "".join(words)


def _category(tags: Iterable[str]) -> str | None:
    present = {tag.lower() for tag in tags}
    return next((identifier for identifier, _, keys in TAXONOMY if keys & present), None)


def _grouped(db: sqlite3.Connection, query: str) -> dict[int, list[str]]:
    grouped: dict[int, list[str]] = {}
    for package, value in db.execute(query):
        if isinstance(value, str) and value:
            grouped.setdefault(package, []).append(value)
    return grouped


def build_catalog(index: Path, output: Path, *, now: datetime) -> dict[str, Any]:
    """Build app-catalog.json from a winget source2 index; a failed build keeps the previous file."""
    try:
        db = sqlite3.connect(f"{index.resolve().as_uri()}?mode=ro", uri=True)
    except sqlite3.Error as error:
        raise ValueError("invalid winget index") from error
    try:
        tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
        if not tables >= _TABLES:
            raise ValueError("invalid winget index: required tables are missing")
        packages = db.execute("select rowid, id, name, moniker from packages order by id").fetchall()
        if len(packages) > MAX_PACKAGES:
            raise ValueError("winget index exceeds the package limit")
        tags = _grouped(db, "select m.package, t.tag from tags2_map m join tags2 t on t.rowid = m.tag")
        commands = _grouped(db, "select m.package, c.command from commands2_map m join commands2 c on c.rowid = m.command")
        names = _grouped(db, "select package, norm_name from norm_names2")
        vendors = _grouped(db, "select package, norm_publisher from norm_publishers2 order by package, norm_publisher")
        codes = _grouped(db, "select package, productcode from productcodes2")
    except sqlite3.Error as error:
        raise ValueError("invalid winget index") from error
    finally:
        db.close()
    apps = []
    for row, identifier, name, moniker in packages:
        if not isinstance(identifier, str) or not isinstance(name, str):
            continue
        vendor = normalize_vendor(vendors.get(row, [""])[0]) or normalize_vendor(identifier.split(".", 1)[0])
        apps.append({
            "id": identifier, "name": name, "vendor": vendor, "category": CURATED.get(identifier) or _category(tags.get(row, [])),
            "names": sorted({normalize_name(name), *map(normalize_name, names.get(row, []))} - {""}),
            "commands": sorted({command.lower() for command in commands.get(row, [])} | ({moniker.lower()} if moniker else set())),
            "product_codes": sorted({code.lower() for code in codes.get(row, [])}),
            "blockable": "microsoft" not in vendor,
        })
    counts = {identifier: 0 for identifier in _CATEGORY_IDS}
    for app in apps:
        if app["category"]:
            counts[app["category"]] += 1
    manifest = {"version": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "attribution": ATTRIBUTION, "source": SOURCE_URL,
                "categories": [{"id": identifier, "label": label, "apps": counts[identifier]} for identifier, label, _ in TAXONOMY],
                "apps": apps}
    output.mkdir(parents=True, exist_ok=True)
    _write_atomic(output / CATALOG_FILE, json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
    return manifest


class AppCatalog:
    """Read side: classification, search and fleet summaries over the published catalog."""

    def __init__(self, directory: Path) -> None:
        self._path = directory / CATALOG_FILE
        self._loaded: tuple[float, dict[str, Any]] | None = None

    def manifest(self) -> dict[str, Any]:
        try:
            stamp = self._path.stat().st_mtime
        except FileNotFoundError:
            return {"version": None, "attribution": "", "categories": [], "apps": []}
        if self._loaded is None or self._loaded[0] != stamp:
            manifest = json.loads(self._path.read_text(encoding="utf-8"))
            by_id = {app["id"]: app for app in manifest["apps"]}
            by_name: dict[str, list[str]] = {}
            by_command: dict[str, list[str]] = {}
            for app in manifest["apps"]:
                for name in app["names"]:
                    by_name.setdefault(name, []).append(app["id"])
                for command in app["commands"]:
                    by_command.setdefault(command, []).append(app["id"])
            self._index = (by_id, by_name, by_command)
            self._loaded = (stamp, manifest)
        return self._loaded[1]

    def app(self, identifier: str) -> dict[str, Any] | None:
        self.manifest()
        return self._index[0].get(identifier) if self._loaded else None

    def match(self, application: dict[str, Any]) -> str | None:
        if self.manifest()["version"] is None:
            return None
        by_id, by_name, by_command = self._index
        stems = [Path(str(value).replace("\\", "/")).name.lower().removesuffix(".exe")
                 for value in (application.get("path"), application.get("original_name")) if value]
        candidates = [*by_name.get(normalize_name(str(application.get("name", ""))), []),
                      *(identifier for stem in stems for identifier in by_command.get(stem, [])),
                      *(identifier for stem in stems for identifier in by_name.get(normalize_name(stem), []))]
        signer = normalize_vendor(str(application.get("publisher", ""))) if _signed(application) else ""
        for identifier in dict.fromkeys(candidates):
            vendor = by_id[identifier]["vendor"]
            if not signer or not vendor or signer.startswith(vendor) or vendor.startswith(signer):
                return identifier
        return None

    def search(self, query: str, *, category: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
        needle = query.strip().lower()
        found = [app for app in self.manifest()["apps"]
                 if (category is None or app["category"] == category)
                 and (not needle or needle in app["name"].lower() or needle in app["id"].lower() or needle in app["vendor"])]
        def rank(app: dict[str, Any]) -> tuple[int, str, str]:
            name = app["name"].lower()
            return (0 if name == needle else 1 if name.startswith(needle) else 2, name, app["id"])
        return sorted(found, key=rank)[:limit]

    def summary(self, inventories: Iterable[tuple[str, list[dict[str, Any]]]]) -> dict[str, Any]:
        manifest = self.manifest()
        observed: dict[str, set[str]] = {}
        for devid, applications in inventories:
            for application in applications:
                identifier = self.match(application)
                if identifier:
                    observed.setdefault(identifier, set()).add(devid)
        by_id = self._index[0] if self._loaded else {}
        categories = []
        for category in manifest["categories"]:
            endpoints = {devid for identifier, devices in observed.items() if by_id[identifier]["category"] == category["id"] for devid in devices}
            categories.append({**category, "observed_endpoints": len(endpoints)})
        return {"version": manifest["version"], "attribution": manifest["attribution"], "categories": categories,
                "observed": {identifier: len(devices) for identifier, devices in sorted(observed.items())}}


def _signed(application: dict[str, Any]) -> bool:
    # Uploaded inventories omit signature_valid: agents report a publisher only for a valid signature.
    return bool(application.get("signature_valid", bool(application.get("publisher"))))


# Mirrors the agent's protected components: never terminated or isolated whatever the catalog says.
_PROTECTED = {"openems-agent.exe", "openems-session.exe", "services.exe", "lsass.exe", "svchost.exe", "winlogon.exe",
              "csrss.exe", "smss.exe", "powershell.exe", "citool.exe", "explorer.exe"}
ACTIONS = ("block", "block_network", "allow")


def _validate_actions(actions: dict[str, Any], catalog: AppCatalog) -> None:
    for key, action in actions.items():
        kind, _, target = str(key).partition(":")
        valid_target = (kind == "category" and target in _CATEGORY_IDS) or (kind == "app" and catalog.app(target) is not None)
        if action not in ACTIONS or not valid_target:
            raise ValueError(f"invalid catalog action for {key}")


def _executable(application: dict[str, Any]) -> str | None:
    """The observed absolute executable path, unless it is a Windows or protected component."""
    path = str(application.get("path", ""))
    if not re.fullmatch(r"[A-Za-z]:\\.+\.exe", path, re.IGNORECASE):
        return None
    lower = path.lower()
    if "\\windows\\" in lower or lower.rsplit("\\", 1)[-1] in _PROTECTED:
        return None
    return path


def _execution_rule(application: dict[str, Any]) -> dict[str, Any] | None:
    publisher = str(application.get("publisher", ""))
    if _signed(application) and publisher:
        kind, value = "publisher", publisher
    elif application.get("original_name"):
        kind, value = "name", str(application["original_name"]).lower()
    elif re.fullmatch(r"[0-9a-fA-F]{64}", str(application.get("sha256", ""))):
        kind, value = "hash", str(application["sha256"]).lower()
    else:
        return None
    digest = hashlib.sha256(f"{kind}\0{value}".encode()).hexdigest()[:12]
    return {"id": f"catalog-{digest}", "kind": kind, "value": value, "if_present": True}


def expand(actions: dict[str, Any], applications: Iterable[dict[str, Any]], catalog: AppCatalog) -> dict[str, Any]:
    """Turn catalog decisions into controls from identities observed in inventories.

    block: present-only execution rules (WDAC where supported) plus process termination, which works on
    every Windows edition. block_network: per-executable firewall isolation; the application still opens.
    """
    if not isinstance(actions, dict):
        raise ValueError("invalid catalog action map")
    _validate_actions(actions, catalog)
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    processes: set[str] = set()
    network: dict[str, str] = {}
    skipped: set[str] = set()
    for application in applications:
        identifier = catalog.match(application)
        entry = catalog.app(identifier) if identifier else None
        if entry is None:
            continue
        decision = actions.get(f"app:{identifier}") or actions.get(f"category:{entry['category']}")
        if decision not in ("block", "block_network"):
            continue
        if not entry["blockable"] or "microsoft" in str(application.get("publisher", "")).lower():
            skipped.add(identifier)
            continue
        executable = _executable(application)
        if decision == "block_network":
            if executable:
                network.setdefault(executable.lower(), executable)
            continue
        if executable:
            processes.add(executable.rsplit("\\", 1)[-1].lower())
        rule = _execution_rule(application)
        if rule and executable is not None:
            rules[(rule["kind"], rule["value"])] = rule
    if len(rules) > MAX_RULES or len(network) > MAX_RULES:
        raise ValueError(f"catalog expansion exceeds {MAX_RULES} rules")
    return {"rules": [rules[key] for key in sorted(rules)], "processes": sorted(processes),
            "network": [network[key] for key in sorted(network)],
            "skipped": [{"app": identifier, "reason": "microsoft_publisher"} for identifier in sorted(skipped)]}