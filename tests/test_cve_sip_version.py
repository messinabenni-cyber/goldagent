"""Unit tests for check_sip_version_disclosure and check_asterisk_cve_2025_57767."""
from scanner.cve import check_sip_version_disclosure, check_asterisk_cve_2025_57767


def _sip_check(banner):
    return check_sip_version_disclosure("127.0.0.1", 5060, banner)


def _57767_check(banner):
    return check_asterisk_cve_2025_57767("127.0.0.1", 5060, banner)


# ---------------------------------------------------------------------------
# check_sip_version_disclosure
# ---------------------------------------------------------------------------

def test_eol_asterisk_18():
    results = _sip_check("Asterisk PBX 18.9.0")
    assert len(results) == 1
    r = results[0]
    assert r.cve_id == "CONFIG-ASTERISK-EOL"
    assert r.severity == "critical"
    assert "end-of-life" in r.title


def test_eol_asterisk_16():
    results = _sip_check("Asterisk PBX 16.20.0")
    assert len(results) == 1
    assert results[0].cve_id == "CONFIG-ASTERISK-EOL"


def test_bare_major_asterisk_20_no_finding():
    # "Asterisk 20" has only 1 version part — must produce no finding
    results = _sip_check("Asterisk 20")
    assert results == []


def test_asterisk_20_below_threshold_finding():
    results = _sip_check("Asterisk PBX 20.14.1")
    assert len(results) == 1
    r = results[0]
    assert r.cve_id == "CVE-2025-57767"
    assert "20.14.1" in r.affected_version


def test_asterisk_20_at_threshold_no_finding():
    results = _sip_check("Asterisk PBX 20.15.2")
    assert results == []


def test_asterisk_20_above_threshold_no_finding():
    results = _sip_check("Asterisk PBX 20.16.0")
    assert results == []


def test_asterisk_21_below_threshold():
    results = _sip_check("Asterisk PBX 21.9.0")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-57767"


def test_asterisk_21_at_threshold_no_finding():
    results = _sip_check("Asterisk PBX 21.10.2")
    assert results == []


def test_asterisk_22_below_threshold():
    results = _sip_check("Asterisk PBX 22.4.0")
    assert len(results) == 1
    assert results[0].cve_id == "CVE-2025-57767"


def test_asterisk_22_at_threshold_no_finding():
    results = _sip_check("Asterisk PBX 22.5.2")
    assert results == []


def test_no_banner():
    results = _sip_check("")
    assert results == []


def test_non_asterisk_banner():
    results = _sip_check("FreeSWITCH 1.10.7")
    assert results == []


# ---------------------------------------------------------------------------
# check_asterisk_cve_2025_57767
# ---------------------------------------------------------------------------

def test_57767_bare_major_no_finding():
    # "Asterisk 20" — bare major only, must return None
    result = _57767_check("Asterisk 20")
    assert result is None


def test_57767_20_14_1_finding():
    result = _57767_check("Asterisk PBX 20.14.1")
    assert result is not None
    assert result.cve_id == "CVE-2025-57767"


def test_57767_20_15_2_no_finding():
    result = _57767_check("Asterisk PBX 20.15.2")
    assert result is None


def test_57767_21_below():
    result = _57767_check("Asterisk PBX 21.9.1")
    assert result is not None
    assert result.cve_id == "CVE-2025-57767"


def test_57767_22_below():
    result = _57767_check("Asterisk PBX 22.3.0")
    assert result is not None
    assert result.cve_id == "CVE-2025-57767"


def test_57767_no_banner():
    result = _57767_check("")
    assert result is None
