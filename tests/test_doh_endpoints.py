"""The DoH endpoint list embedded in the native agent must stay valid and conservative."""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from agent.policy import normalize_domain

LIST = Path(__file__).resolve().parents[1] / "contract" / "doh-endpoints.json"


def test_hosts_are_normalized_unique_public_names():
    data = json.loads(LIST.read_text(encoding="utf-8"))
    hosts = data["hosts"]
    assert len(hosts) >= 20
    assert len(set(hosts)) == len(hosts)
    assert all(normalize_domain(host) == host for host in hosts)
    for required in ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com"):
        assert required in hosts


def test_addresses_are_unique_global_unicast_ips():
    data = json.loads(LIST.read_text(encoding="utf-8"))
    addresses = [ipaddress.ip_address(value) for value in data["addresses"]]
    assert len(set(addresses)) == len(addresses)
    assert any(address.version == 6 for address in addresses)
    for address in addresses:
        assert address.is_global and not address.is_multicast, address
    for required in ("1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111", "2001:4860:4860::8888"):
        assert ipaddress.ip_address(required) in addresses
