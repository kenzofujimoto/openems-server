"""Static checks of the publisher fixture setup; never run the controls harness on the host."""

from __future__ import annotations

from pathlib import Path
import re

HARNESS = (Path(__file__).resolve().parents[1] / "deploy/test-controls-sandbox.ps1").read_text(encoding="utf-8")


def _publisher_setup() -> str:
    start = HARNESS.index("$publisherFixture = Join-Path $work 'PublisherFixture.exe'")
    end = HARNESS.index("Record-Check 'WDAC denied only the dedicated test publisher", start)
    return HARNESS[start:end]


def test_publisher_fixture_never_writes_the_trusted_publisher_store():
    # SYSTEM is refused TrustedPublisher imports on the acceptance guest (0x80070005); WDAC does not use it.
    imports = re.findall(r"Import-Certificate[^\n]*-CertStoreLocation\s+(\S+)", _publisher_setup())
    assert imports == [r"Cert:\LocalMachine\Root"]


def test_publisher_fixture_still_requires_a_valid_signature_before_the_policy():
    setup = _publisher_setup()
    assert "New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Openems Acceptance Fixture'" in setup
    assert setup.index("Set-AuthenticodeSignature") < setup.index("if ($signature.Status -ne 'Valid') { throw")
    assert setup.index("if ($signature.Status -ne 'Valid') { throw") < setup.index("kind='publisher'")
    assert "Assert-ExecutionDenied $publisherFixture" in setup and "Assert-ExecutionDenied $publisherCopy" in setup


def test_released_usb_waits_for_an_inventory_that_reports_the_drive():
    # Inventory is uploaded after the release ACK, from a background collection.
    start = HARNESS.index("$PhysicalDrive = $PhysicalDrive.ToUpperInvariant()")
    selection = HARNESS[start:HARNESS.index("$partition = Get-Partition", start)]
    assert "Wait-Until { $null -ne (Get-UsbDevice $PhysicalDrive) -and (Test-Path -LiteralPath ($PhysicalDrive + '\\')) } 120" in selection
    assert selection.index("Wait-Until") < selection.index("$device = Get-UsbDevice $PhysicalDrive")
    assert "if ($null -eq $device -or -not $device.instance_id -or -not $device.serial -or -not $device.vid -or -not $device.pid) { throw" in selection


def test_fixture_backend_startup_allows_a_cold_guest_and_reports_the_job_state():
    start = HARNESS.index("function Start-Backend {")
    backend = HARNESS[start:HARNESS.index("function Stop-Backend {", start)]
    assert "Test-Path -LiteralPath $ready } 120 'startup'" in backend
    assert "'Fixture backend did not start; job state ' + $job.State" in backend
    # ACK and inventory deadlines are acceptance criteria and stay unchanged.
    assert "$_.success }).Count -gt 0 } 90 'The service did not successfully apply and ACK" in HARNESS
    assert "Wait-Until { @(Read-Rows 'inventory.log').Count -gt 0 } 90 'The service did not upload an inventory.'" in HARNESS


def test_publisher_certificate_cleanup_still_covers_every_store():
    cleanup = HARNESS[HARNESS.index("if ($null -ne $certificate) {"):]
    assert "foreach ($store in @('My','Root','TrustedPublisher'))" in cleanup[:400]
