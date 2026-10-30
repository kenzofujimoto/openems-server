"""Application catalog built from the open winget index and matched against real inventories."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from app.app_catalog import AppCatalog, build_catalog, expand, normalize_name, normalize_vendor

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)
PACKAGES = {
    "Valve.Steam": ("Steam", "steam", ["game", "gaming", "store"], ["steam"], ["valve"], []),
    "EpicGames.EpicGamesLauncher": ("Epic Games Launcher", None, ["games"], ["epicgameslauncher"], ["epicgames"], []),
    "qBittorrent.qBittorrent": ("qBittorrent", None, ["torrent", "p2p", "download"], ["qbittorrent"], ["qbittorrent"], []),
    "AnyDeskSoftwareGmbH.AnyDesk": ("AnyDesk", "anydesk", ["remote-desktop", "remote-access"], ["anydesk"], ["anydesksoftware"], []),
    "Notepad++.Notepad++": ("Notepad++", "notepad++", ["editor", "text"], ["notepad"], ["notepad"], ["npp"]),
    "Microsoft.Teams": ("Microsoft Teams", "teams", ["chat", "collaboration"], ["microsoftteams"], ["microsoft"], []),
}


def winget_index(path: Path, packages: dict = PACKAGES) -> Path:
    db = sqlite3.connect(path)
    db.executescript("""
        create table packages(rowid integer primary key, id text, name text, moniker text, latest_version text,
                              arp_min_version text, arp_max_version text, hash blob);
        create table tags2(rowid integer primary key, tag text);
        create table tags2_map(tag integer, package integer);
        create table commands2(rowid integer primary key, command text);
        create table commands2_map(command integer, package integer);
        create table productcodes2(productcode text, package integer);
        create table norm_names2(norm_name text, package integer);
        create table norm_publishers2(norm_publisher text, package integer);
    """)
    tags: dict[str, int] = {}
    commands: dict[str, int] = {}
    for identifier, (name, moniker, package_tags, names, publishers, package_commands) in packages.items():
        row = db.execute("insert into packages(id,name,moniker,latest_version) values (?,?,?,?)",
                         (identifier, name, moniker, "1.0")).lastrowid
        for tag in package_tags:
            tags.setdefault(tag, db.execute("insert into tags2(tag) values (?)", (tag,)).lastrowid)
            db.execute("insert into tags2_map values (?,?)", (tags[tag], row))
        for command in package_commands:
            commands.setdefault(command, db.execute("insert into commands2(command) values (?)", (command,)).lastrowid)
            db.execute("insert into commands2_map values (?,?)", (commands[command], row))
        db.executemany("insert into norm_names2 values (?,?)", [(value, row) for value in names])
        db.executemany("insert into norm_publishers2 values (?,?)", [(value, row) for value in publishers])
    db.commit()
    db.close()
    return path


@pytest.fixture
def catalog(tmp_path):
    manifest = build_catalog(winget_index(tmp_path / "index.db"), tmp_path / "out", now=NOW)
    return manifest, AppCatalog(tmp_path / "out")


def test_build_maps_winget_tags_to_a_reviewed_taxonomy_with_attribution(catalog, tmp_path):
    manifest, _ = catalog
    assert manifest["version"] == "2026-10-30T12:00:00Z"
    assert "winget-pkgs" in manifest["attribution"] and "MIT" in manifest["attribution"]
    apps = {app["id"]: app for app in manifest["apps"]}
    assert apps["Valve.Steam"]["category"] == "games"
    assert apps["EpicGames.EpicGamesLauncher"]["category"] == "games"
    assert apps["qBittorrent.qBittorrent"]["category"] == "p2p"
    assert apps["AnyDeskSoftwareGmbH.AnyDesk"]["category"] == "remote_access"
    assert apps["Notepad++.Notepad++"]["category"] is None
    assert apps["Valve.Steam"]["vendor"] == "valve" and apps["Valve.Steam"]["names"] == ["steam"]
    assert apps["Microsoft.Teams"]["blockable"] is False
    counts = {category["id"]: category["apps"] for category in manifest["categories"]}
    assert counts["games"] == 2 and counts["p2p"] == 1 and counts["remote_access"] == 1
    assert json.loads((tmp_path / "out" / "app-catalog.json").read_text(encoding="utf-8")) == manifest


def test_a_malformed_index_keeps_the_previous_catalog(catalog, tmp_path):
    broken = tmp_path / "broken.db"
    sqlite3.connect(broken).execute("create table packages(id text)").connection.close()
    with pytest.raises(ValueError, match="winget index"):
        build_catalog(broken, tmp_path / "out", now=NOW)
    assert json.loads((tmp_path / "out" / "app-catalog.json").read_text(encoding="utf-8"))["version"] == "2026-10-30T12:00:00Z"


@pytest.mark.parametrize("raw,expected", [
    ("Steam", "steam"), ("Steam (x64) 2.10.91.91", "steam"), ("AnyDesk 9.0.5 64-bit", "anydesk"),
    ("Epic Games Launcher", "epicgameslauncher"), ("", ""),
])
def test_names_normalize_like_the_winget_index(raw, expected):
    assert normalize_name(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US", "valve"),
    ("CN=\"AnyDesk Software GmbH\", O=\"AnyDesk Software GmbH\", C=DE", "anydesksoftware"),
    ("Microsoft Corporation", "microsoft"), ("", ""),
])
def test_vendors_normalize_from_authenticode_subjects(raw, expected):
    assert normalize_vendor(raw) == expected


def steam(**overrides):
    application = {"name": "Steam", "path": r"C:\Program Files (x86)\Steam\steam.exe", "sha256": "a" * 64,
                   "publisher": "CN=Valve Corp., O=Valve Corp., L=Bellevue, S=Washington, C=US",
                   "signature_valid": True, "original_name": "steam.exe", "running": False, "version": "2.10"}
    return {**application, **overrides}


def test_inventory_entries_match_by_name_and_vendor_but_never_a_different_signer(catalog):
    _, apps = catalog
    assert apps.match(steam()) == "Valve.Steam"
    assert apps.match(steam(name="steam.exe", running=True)) == "Valve.Steam"
    assert apps.match(steam(name="npp", path=r"C:\Tools\npp.exe", publisher="", signature_valid=False, original_name="")) == "Notepad++.Notepad++"
    assert apps.match(steam(publisher="CN=Someone Else", signature_valid=True)) is None
    assert apps.match(steam(name="Unknown Tool", path=r"C:\Tools\tool.exe", original_name="tool.exe")) is None


def test_category_block_expands_to_present_only_rules_and_honours_app_allow_overrides(catalog):
    _, apps = catalog
    epic = steam(name="Epic Games Launcher", path=r"C:\Epic\EpicGamesLauncher.exe", sha256="b" * 64,
                 publisher="CN=Epic Games Inc., O=Epic Games Inc., C=US", original_name="EpicGamesLauncher.exe")
    torrent = steam(name="qBittorrent", path=r"C:\qBittorrent\qbittorrent.exe", sha256="c" * 64, publisher="",
                    signature_valid=False, original_name="qbittorrent.exe")
    unnamed = steam(name="qBittorrent", path=r"C:\Portable\qbt.exe", sha256="d" * 64, publisher="",
                    signature_valid=False, original_name="")
    teams = steam(name="Microsoft Teams", path=r"C:\Teams\ms-teams.exe", publisher="CN=Microsoft Corporation, O=Microsoft Corporation",
                  original_name="ms-teams.exe")
    result = expand({"category:games": "block", "app:Valve.Steam": "allow", "category:p2p": "block", "app:Microsoft.Teams": "block"},
                    [steam(), epic, torrent, unnamed, teams, epic], apps)
    rules = {(rule["kind"], rule["value"]) for rule in result["rules"]}
    assert rules == {("publisher", "CN=Epic Games Inc., O=Epic Games Inc., C=US"), ("name", "qbittorrent.exe"), ("hash", "d" * 64)}
    assert all(rule["if_present"] is True and rule["id"].startswith("catalog-") for rule in result["rules"])
    assert len({rule["id"] for rule in result["rules"]}) == len(result["rules"])
    assert result["skipped"] == [{"app": "Microsoft.Teams", "reason": "microsoft_publisher"}]
    again = expand({"category:games": "block", "app:Valve.Steam": "allow", "category:p2p": "block", "app:Microsoft.Teams": "block"},
                   [epic, unnamed, torrent, steam(), teams], apps)
    assert again["rules"] == result["rules"], "expansion must be order independent for stable policy digests"


def test_unknown_actions_are_rejected(catalog):
    _, apps = catalog
    with pytest.raises(ValueError, match="catalog action"):
        expand({"category:games": "maybe"}, [], apps)
    with pytest.raises(ValueError, match="catalog action"):
        expand({"vendor:valve": "block"}, [], apps)


def test_search_and_summary_report_observed_machines(catalog):
    _, apps = catalog
    summary = apps.summary([("PC-1", [steam()]), ("PC-2", [steam(), steam(name="qBittorrent", original_name="qbittorrent.exe", publisher="", signature_valid=False)])])
    games = next(category for category in summary["categories"] if category["id"] == "games")
    assert games["apps"] == 2 and games["observed_endpoints"] == 2
    assert summary["observed"]["Valve.Steam"] == 2 and summary["observed"]["qBittorrent.qBittorrent"] == 1
    assert [app["id"] for app in apps.search("steam")] == ["Valve.Steam"]
    assert [app["id"] for app in apps.search("", category="p2p")] == ["qBittorrent.qBittorrent"]


def test_curated_overrides_fix_misleading_community_tags(tmp_path):
    packages = {**PACKAGES, "Discord.Discord": ("Discord", "discord", ["gaming", "chat"], ["discord"], ["discord"], []),
                "Spotify.Spotify": ("Spotify", "spotify", ["podcasts"], ["spotify"], ["spotify"], [])}
    manifest = build_catalog(winget_index(tmp_path / "index.db", packages), tmp_path / "out", now=NOW)
    apps = {app["id"]: app for app in manifest["apps"]}
    assert apps["Discord.Discord"]["category"] == "messaging"
    assert apps["Spotify.Spotify"]["category"] == "media"


def test_search_ranks_exact_and_prefix_names_before_substrings(tmp_path):
    packages = {**PACKAGES, "JustArchiNET.ArchiSteamFarm": ("ArchiSteamFarm", None, [], ["archisteamfarm"], ["justarchinet"], []),
                "Example.SteamTools": ("Steam Tools", None, [], ["steamtools"], ["example"], [])}
    build_catalog(winget_index(tmp_path / "index.db", packages), tmp_path / "out", now=NOW)
    assert [app["id"] for app in AppCatalog(tmp_path / "out").search("steam")] == ["Valve.Steam", "Example.SteamTools", "JustArchiNET.ArchiSteamFarm"]


def test_block_also_terminates_processes_and_block_network_isolates_observed_executables(catalog):
    _, apps = catalog
    epic = steam(name="Epic Games Launcher", path=r"C:\Epic\EpicGamesLauncher.exe", sha256="b" * 64,
                 publisher="CN=Epic Games Inc., O=Epic Games Inc., C=US", original_name="EpicGamesLauncher.exe")
    torrent = steam(name="qBittorrent", path=r"C:\qBittorrent\qbittorrent.exe", sha256="c" * 64, publisher="",
                    signature_valid=False, original_name="qbittorrent.exe")
    result = expand({"category:games": "block", "app:Valve.Steam": "allow", "category:p2p": "block_network"}, [steam(), epic, torrent], apps)
    assert result["processes"] == ["epicgameslauncher.exe"]
    assert result["network"] == [r"C:\qBittorrent\qbittorrent.exe"]
    assert {rule["value"] for rule in result["rules"]} == {epic["publisher"]}, "network-only decisions add no execution rule"


def test_expansion_never_terminates_or_isolates_protected_windows_components(catalog):
    _, apps = catalog
    shell = steam(name="qBittorrent", path=r"C:\Windows\System32\svchost.exe", publisher="", signature_valid=False, original_name="")
    result = expand({"category:p2p": "block_network", "app:qBittorrent.qBittorrent": "block"}, [shell], apps)
    assert result["processes"] == [] and result["network"] == []
