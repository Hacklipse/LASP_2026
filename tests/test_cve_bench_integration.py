"""CVE-Bench adapter stays explicit and uses the public LASP CLI."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from integrations.cve_bench.suite import (
    _authenticate_session,
    _lasp_command,
    _task_metadata,
)
from integrations.cve_bench.target_scoring import score_target_confirmation


class CveBenchIntegrationTests(unittest.TestCase):
    def test_authentication_does_not_accept_prelogin_cookie(self) -> None:
        class Response:
            def __init__(self, body: str):
                self.body = body

            def read(self, _limit: int) -> bytes:
                return self.body.encode()

            def close(self) -> None:
                pass

        login = '<form action="/" method="post"><input name="u"><input type="password" name="p"></form>'
        with patch(
            "integrations.cve_bench.suite._open_without_redirects",
            side_effect=[(Response(login), "http://local/"), (Response(login), "http://local/")],
        ):
            self.assertIsNone(
                _authenticate_session(
                    "http://local", aliases=(), username="user", password="bad"
                )
            )

    def test_target_scoring_separates_companion_fields_from_signal_parameter(self) -> None:
        result = score_target_confirmation(
            "CVE-2024-3495",
            {
                "surfaces": [
                    {
                        "surface_key": "ajax",
                        "method": "POST",
                        "path": "/wp-admin/admin-ajax.php",
                        "parameters": ["action", "nonce_ajax", "cnt"],
                    }
                ],
                "candidates": [
                    {
                        "candidate_id": "candidate-1",
                        "surface_key": "ajax",
                        "status": "confirmed",
                        "exploration_parameters": ["action", "nonce_ajax", "cnt"],
                        "signal_parameters": ["cnt"],
                    }
                ],
            },
        )

        self.assertTrue(result["confirmed"])
        self.assertEqual(result["matches"][0]["matched_parameters"], ["cnt"])

    def test_target_scoring_does_not_fallback_when_signal_list_is_empty(self) -> None:
        result = score_target_confirmation(
            "CVE-2024-37849",
            {
                "surfaces": [
                    {
                        "surface_key": "login",
                        "method": "POST",
                        "path": "/process.php",
                        "parameters": ["username", "password"],
                    }
                ],
                "candidates": [
                    {
                        "candidate_id": "candidate-1",
                        "surface_key": "login",
                        "status": "confirmed",
                        "exploration_parameters": ["username", "password"],
                        "signal_parameters": [],
                    }
                ],
            },
        )

        self.assertFalse(result["confirmed"])

    def test_rejects_invalid_task_identifier_before_filesystem_access(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid CVE-Bench task id"):
            _task_metadata(Path("/does/not/matter"), "../../unexpected")

    def test_sqli_profile_is_explicit_and_does_not_embed_task_answers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = _lasp_command(
                root,
                target_url="http://127.0.0.1:12345/",
                code_version="test-version",
                routing_log=root / "routing.jsonl",
                report=root / "report.md",
                redirect_origin_aliases=("target:9090", "127.0.0.1:9090"),
            )

        self.assertEqual(command[command.index("--vuln") + 1], "sqli")
        self.assertEqual(command[command.index("--recon-entry") + 1], "base-url")
        self.assertIn("--approve-state-changing", command)
        self.assertEqual(command[command.index("--recon-max-pages") + 1], "64")
        self.assertEqual(command[command.index("--budget-allocation") + 1], "hybrid")
        self.assertEqual(
            command[command.index("--redirect-origin-alias") + 1], "target:9090"
        )
        self.assertIn("127.0.0.1:9090", command)
        self.assertFalse(any(part.startswith("CVE-") for part in command))


if __name__ == "__main__":
    unittest.main()
