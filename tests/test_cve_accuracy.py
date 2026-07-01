"""Unit tests for CVE check accuracy fixes."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

from scanner.cve import (
    check_freepbx_cve_2021_45461,
    check_freepbx_path_traversal,
)


# ---------------------------------------------------------------------------
# check_freepbx_cve_2021_45461
# ---------------------------------------------------------------------------

class TestFreePBXCVE202145461:
    def _mock_post(self, status, body):
        return patch(
            "scanner.cve._http_post",
            return_value=(status, {}, body),
        )

    def test_sqlite_master_no_finding(self):
        """sqlite_master is a table name, not an error string — must not trigger."""
        with self._mock_post(200, "sqlite_master"):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is None

    def test_sql_syntax_error_triggers_finding(self):
        """Real SQL error string should produce a finding."""
        body = "You have an error in your SQL syntax near '1'='1'"
        with self._mock_post(200, body):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is not None
        assert result.cve_id == "CVE-2021-45461"

    def test_no_sql_error_no_finding(self):
        """A normal response with no SQL errors must not produce a finding."""
        with self._mock_post(200, '{"status": "ok"}'):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is None

    def test_connection_failure_no_finding(self):
        with self._mock_post(0, ""):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is None

    def test_uses_post_not_get(self):
        """Verify the probe uses _http_post, not _http_get."""
        with patch("scanner.cve._http_get") as mock_get, \
             patch("scanner.cve._http_post", return_value=(200, {}, "you have an error in your sql")) as mock_post:
            check_freepbx_cve_2021_45461("10.0.0.1", 80)
        mock_get.assert_not_called()
        mock_post.assert_called_once()

    def test_post_path_and_body(self):
        """Verify the correct endpoint and injection payload are used."""
        with patch("scanner.cve._http_post", return_value=(0, {}, "")) as mock_post:
            check_freepbx_cve_2021_45461("10.0.0.1", 80)
        call_args = mock_post.call_args
        path_arg = call_args[0][2]
        body_arg = call_args[0][3]
        assert "voicemail" in path_arg
        assert "getSIPCredentials" in path_arg
        assert "OR" in body_arg

    def test_version_guard_downgrade_confirmed(self):
        """When version is outside vulnerable range, confirmed=False."""
        body = "you have an error in your sql FPBX-17.0.0.0"
        with self._mock_post(200, body):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is not None
        assert result.confirmed is False

    def test_version_guard_vulnerable_version_confirmed(self):
        """When version is within the vulnerable range, confirmed=True."""
        body = "you have an error in your sql FPBX-15.0.10.0"
        with self._mock_post(200, body):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is not None
        assert result.confirmed is True

    def test_pg_query_triggers_finding(self):
        body = "pg_query(): Query failed: ERROR: syntax error"
        with self._mock_post(200, body):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is not None

    def test_syntax_error_at_or_near_triggers_finding(self):
        body = 'ERROR: syntax error at or near "OR"'
        with self._mock_post(200, body):
            result = check_freepbx_cve_2021_45461("10.0.0.1", 80)
        assert result is not None


# ---------------------------------------------------------------------------
# check_freepbx_path_traversal
# ---------------------------------------------------------------------------

class TestFreePBXPathTraversal:
    def _mock_get(self, status, body):
        return patch(
            "scanner.cve._http_get",
            return_value=(status, {}, body),
        )

    def test_passwd_content_triggers_finding(self):
        """Real /etc/passwd content must produce a finding."""
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is not None
        assert result.cve_id == "CONFIG-FREEPBX-PATH-TRAVERSAL"

    def test_rooted_in_history_no_finding(self):
        """'root:' substring not in passwd format must not trigger a finding."""
        body = "rooted in history, the system was originally designed"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is None

    def test_root_colon_only_no_finding(self):
        """Bare 'root:' without UID/GID numbers must not trigger."""
        body = "root: the administrator account"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is None

    def test_connection_failure_no_finding(self):
        with self._mock_get(0, ""):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is None

    def test_cve_id_updated(self):
        body = "root:x:0:0:root:/root:/bin/bash\n"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is not None
        assert result.cve_id == "CONFIG-FREEPBX-PATH-TRAVERSAL"

    def test_references_note_distinguishes_from_cve_2022_2347(self):
        body = "root:x:0:0:root:/root:/bin/bash\n"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is not None
        refs_text = " ".join(result.references)
        assert "CVE-2022-2347" in refs_text

    def test_passwd_with_shadow_style_no_x(self):
        """Entries using '*' or '!' placeholder must also match."""
        body = "root:*:0:0:System Administrator:/var/root:/bin/sh\n"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is not None

    def test_passwd_with_exclamation_placeholder(self):
        body = "root:!:0:0::/root:/bin/bash\n"
        with self._mock_get(200, body):
            result = check_freepbx_path_traversal("10.0.0.1", 80)
        assert result is not None
