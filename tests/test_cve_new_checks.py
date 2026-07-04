"""Unit tests for CVE-2025-66039 (FreePBX auth bypass) and CVE-2024-41713 (Mitel path traversal)."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from scanner.cve import (
    check_freepbx_cve_2025_66039,
    check_mitel_cve_2024_41713,
)


# ---------------------------------------------------------------------------
# check_freepbx_cve_2025_66039
# ---------------------------------------------------------------------------

class TestFreePBXCVE202566039:
    def _mock_get(self, status, body):
        return patch(
            "scanner.cve._http_get",
            return_value=(status, {}, body),
        )

    def test_admin_panel_no_login_form_triggers_finding(self):
        """HTTP 200 with admin panel content and no password input → CRITICAL finding."""
        body = "FreePBX Administration - Welcome to the admin panel"
        with self._mock_get(200, body):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is not None
        assert result.cve_id == "CVE-2025-66039"
        assert result.severity == "critical"

    def test_login_form_present_no_finding(self):
        """HTTP 200 with admin content but login form with password input → no finding."""
        body = (
            "FreePBX Administration"
            '<input type="password" name="password" />'
        )
        with self._mock_get(200, body):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is None

    def test_non_200_response_no_finding(self):
        with self._mock_get(401, "Unauthorized"):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is None

    def test_connection_failure_no_finding(self):
        with self._mock_get(0, ""):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is None

    def test_200_without_admin_indicators_no_finding(self):
        with self._mock_get(200, "<html><body>Hello World</body></html>"):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is None

    def test_admin_panel_indicator_triggers_finding(self):
        """'admin panel' indicator (lowercase) also triggers."""
        body = "Welcome to the admin panel - system configuration"
        with self._mock_get(200, body):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is not None
        assert result.cve_id == "CVE-2025-66039"

    def test_extra_headers_passed_to_http_get(self):
        """Verify Authorization header is passed to _http_get."""
        with patch("scanner.cve._http_get", return_value=(0, {}, "")) as mock_get:
            check_freepbx_cve_2025_66039("10.0.0.1", 80)
        call_kwargs = mock_get.call_args
        extra = call_kwargs.kwargs.get("extra_headers") or (
            call_kwargs[1].get("extra_headers") if call_kwargs[1] else None
        )
        if extra is None and len(call_kwargs[0]) >= 6:
            extra = call_kwargs[0][5]
        assert extra is not None
        auth_val = extra.get("Authorization", "")
        assert "YWRtaW46aW52YWxpZA==" in auth_val

    def test_login_form_type_password_variants(self):
        """Various spacing in <input type=password> still suppresses finding."""
        body = "FreePBX Administration <input   type =  password  id='pw'>"
        with self._mock_get(200, body):
            result = check_freepbx_cve_2025_66039("10.0.0.1", 80)
        assert result is None


# ---------------------------------------------------------------------------
# check_mitel_cve_2024_41713
# ---------------------------------------------------------------------------

class TestMitelCVE202441713:
    def _mock_get(self, status, body):
        return patch(
            "scanner.cve._http_get",
            return_value=(status, {}, body),
        )

    def test_passwd_content_triggers_critical_finding(self):
        """HTTP 200 with /etc/passwd root entry → CRITICAL finding."""
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
        with self._mock_get(200, body):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is not None
        assert result.cve_id == "CVE-2024-41713"
        assert result.severity == "critical"

    def test_no_passwd_content_no_finding(self):
        with self._mock_get(200, "<html>Not found</html>"):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is None

    def test_connection_failure_no_finding(self):
        with self._mock_get(0, ""):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is None

    def test_passwd_with_shadow_star_triggers_finding(self):
        """root:*:0:0: format (BSD/macOS) also triggers."""
        body = "root:*:0:0:System Administrator:/var/root:/bin/sh\n"
        with self._mock_get(200, body):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is not None
        assert result.cve_id == "CVE-2024-41713"

    def test_passwd_with_exclamation_triggers_finding(self):
        body = "root:!:0:0::/root:/bin/bash\n"
        with self._mock_get(200, body):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is not None

    def test_uses_tls(self):
        """Verify the probe uses use_tls=True."""
        with patch("scanner.cve._http_get", return_value=(0, {}, "")) as mock_get:
            check_mitel_cve_2024_41713("10.0.0.1", 443)
        for call in mock_get.call_args_list:
            args = call[0]
            kwargs = call[1]
            tls_arg = kwargs.get("use_tls", args[4] if len(args) > 4 else False)
            assert tls_arg is True

    def test_root_bare_string_no_finding(self):
        """'root:' without numeric UID/GID must not trigger."""
        body = "root: the default administrator account"
        with self._mock_get(200, body):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is None

    def test_references_include_nvd(self):
        body = "root:x:0:0:root:/root:/bin/bash\n"
        with self._mock_get(200, body):
            result = check_mitel_cve_2024_41713("10.0.0.1", 443)
        assert result is not None
        assert any("CVE-2024-41713" in ref for ref in result.references)
