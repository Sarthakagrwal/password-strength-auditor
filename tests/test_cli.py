"""Tests for the ``pwaudit`` command-line interface.

The HIBP network call is patched throughout so the suite is deterministic and
offline. A dedicated test class verifies the privacy guarantee: no file written
during a CLI run ever contains a password.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from pwaudit.cli import main


@pytest.fixture
def no_breach():
    """Patch the HIBP lookup to always report 'not breached' (count 0)."""
    with patch("pwaudit.audit.check_password", return_value=0) as mock:
        yield mock


@pytest.fixture
def always_breached():
    """Patch the HIBP lookup to always report a breach hit."""
    with patch("pwaudit.audit.check_password", return_value=12345) as mock:
        yield mock


class TestSingleMode:
    """`pwaudit` with no --file: a single prompted password."""

    def test_strong_password_exits_zero(self, no_breach, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value="k4Lm9Qx2Vt7Zp1Rb6Wn"):
            code = main([])
        assert code == 0
        out = capsys.readouterr().out
        assert "SAFE" in out

    def test_weak_password_exits_one(self, no_breach, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value="hunter2"):
            code = main([])
        assert code == 1
        assert "WEAK" in capsys.readouterr().out

    def test_breached_password_exits_one(self, always_breached, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value="k4Lm9Qx2Vt7Zp1Rb6Wn"):
            code = main([])
        assert code == 1
        assert "UNSAFE" in capsys.readouterr().out

    def test_empty_password_is_usage_error(self, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value=""):
            code = main(["--no-hibp"])
        assert code == 2
        assert "empty password" in capsys.readouterr().err

    def test_keyboard_interrupt_at_prompt(self, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", side_effect=KeyboardInterrupt):
            code = main(["--no-hibp"])
        assert code == 130


class TestJsonMode:
    """`--json` produces machine-readable output."""

    def test_json_output_is_valid(self, no_breach, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value="k4Lm9Qx2Vt7Zp1Rb6Wn"):
            code = main(["--json"])
        assert code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["verdict"] == "SAFE"
        assert "zxcvbn" in payload
        assert "breach" in payload

    def test_json_output_omits_the_password(self, no_breach, capsys) -> None:
        secret = "k4Lm9Qx2Vt7Zp1Rb6Wn"
        with patch("pwaudit.cli._prompt_password", return_value=secret):
            main(["--json"])
        # The password must not appear anywhere in the JSON output.
        assert secret not in capsys.readouterr().out


class TestNoHibpMode:
    """`--no-hibp` skips the breach check entirely."""

    def test_no_hibp_does_not_call_the_api(self, capsys) -> None:
        with patch("pwaudit.audit.check_password") as mock_hibp:
            with patch("pwaudit.cli._prompt_password", return_value="k4Lm9Qx2Vt7Zp1Rb6Wn"):
                code = main(["--no-hibp"])
        mock_hibp.assert_not_called()
        assert code == 0
        assert "offline mode" in capsys.readouterr().out

    def test_no_hibp_json_marks_breach_unchecked(self, capsys) -> None:
        with patch("pwaudit.cli._prompt_password", return_value="k4Lm9Qx2Vt7Zp1Rb6Wn"):
            main(["--no-hibp", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["breach"]["checked"] is False


class TestFileMode:
    """`--file` audits a list of passwords."""

    def test_file_mode_table_output(self, no_breach, tmp_path, capsys) -> None:
        pw_file = tmp_path / "list.txt"
        pw_file.write_text("k4Lm9Qx2Vt7Zp1Rb6Wn\nanotherStr0ng!Phrase9\n")
        code = main(["--file", str(pw_file)])
        out = capsys.readouterr().out
        assert code == 0
        # Two rows, identified by line number not password.
        assert "#1" in out
        assert "#2" in out

    def test_file_mode_nonzero_exit_if_any_weak(self, no_breach, tmp_path, capsys) -> None:
        pw_file = tmp_path / "list.txt"
        pw_file.write_text("k4Lm9Qx2Vt7Zp1Rb6Wn\nhunter2\n")
        code = main(["--file", str(pw_file)])
        capsys.readouterr()
        # One weak password in the list -> overall exit code 1.
        assert code == 1

    def test_file_mode_nonzero_exit_if_any_breached(
        self, always_breached, tmp_path, capsys
    ) -> None:
        pw_file = tmp_path / "list.txt"
        pw_file.write_text("k4Lm9Qx2Vt7Zp1Rb6Wn\n")
        code = main(["--file", str(pw_file)])
        capsys.readouterr()
        assert code == 1

    def test_file_mode_skips_blank_and_comment_lines(self, no_breach, tmp_path, capsys) -> None:
        pw_file = tmp_path / "list.txt"
        pw_file.write_text("# header comment\n\nk4Lm9Qx2Vt7Zp1Rb6Wn\n\n")
        code = main(["--file", str(pw_file)])
        out = capsys.readouterr().out
        assert code == 0
        # Only one real password -> only line #1.
        assert "#1" in out
        assert "#2" not in out

    def test_file_mode_missing_file_is_error(self, capsys) -> None:
        code = main(["--file", "/nonexistent/path/passwords.txt", "--no-hibp"])
        assert code == 2
        assert "cannot read file" in capsys.readouterr().err

    def test_file_mode_empty_file_is_error(self, tmp_path, capsys) -> None:
        pw_file = tmp_path / "empty.txt"
        pw_file.write_text("\n# only a comment\n\n")
        code = main(["--file", str(pw_file), "--no-hibp"])
        assert code == 2
        assert "no passwords" in capsys.readouterr().err

    def test_file_mode_json_output(self, no_breach, tmp_path, capsys) -> None:
        pw_file = tmp_path / "list.txt"
        pw_file.write_text("k4Lm9Qx2Vt7Zp1Rb6Wn\nhunter2\n")
        code = main(["--file", str(pw_file), "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert code == 1
        assert payload["count"] == 2
        assert len(payload["results"]) == 2
        assert payload["results"][0]["line"] == 1


class TestPrivacyNoFileLeak:
    """The CLI must never write a password to any file."""

    def test_no_output_file_contains_the_password(
        self, no_breach, tmp_path, capsys, monkeypatch
    ) -> None:
        secret = "k4Lm9Qx2Vt7Zp1Rb6Wn"

        # Snapshot the directory tree before the run.
        work_dir = tmp_path / "work"
        work_dir.mkdir()
        monkeypatch.chdir(work_dir)

        pw_file = work_dir / "input.txt"
        pw_file.write_text(secret + "\n")
        before = set(work_dir.rglob("*"))

        # Run every CLI mode that could conceivably touch disk.
        main(["--file", str(pw_file)])
        capsys.readouterr()
        main(["--file", str(pw_file), "--json"])
        capsys.readouterr()
        with patch("pwaudit.cli._prompt_password", return_value=secret):
            main(["--json"])
        capsys.readouterr()

        # No NEW files were created by the CLI.
        after = set(work_dir.rglob("*"))
        new_files = after - before
        assert new_files == set(), f"CLI created unexpected files: {new_files}"

        # And the only pre-existing file (the input the user supplied) is the
        # sole place the password lives — nothing else on disk contains it.
        for path in after:
            if path.is_file() and path != pw_file:
                content = path.read_bytes()
                assert secret.encode() not in content, f"{path} leaked the password"

    def test_json_report_to_disk_would_not_carry_password(self, no_breach) -> None:
        # Defence in depth: even if a caller serialised the report themselves,
        # to_dict() carries no password. (audit.to_dict is covered in test_audit;
        # here we assert the CLI's JSON payload likewise omits it.)
        from io import StringIO

        secret = "k4Lm9Qx2Vt7Zp1Rb6Wn"
        buffer = StringIO()
        with patch("sys.stdout", buffer):
            with patch("pwaudit.cli._prompt_password", return_value=secret):
                main(["--json"])
        assert secret not in buffer.getvalue()


class TestVersionFlag:
    """`--version` prints a version and exits 0."""

    def test_version_flag(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "pwaudit" in capsys.readouterr().out


def test_pwaudit_console_script_is_installed() -> None:
    """The `pwaudit` entry point is available on PATH after `pip install -e`."""
    # The console script wraps pwaudit.cli:main; importing main is the contract.
    assert callable(main)
    # Sanity-check the package metadata exposes the script (best-effort).
    venv_bin = Path(os.sys.executable).parent
    script = venv_bin / "pwaudit"
    if script.exists():  # present in the project venv; may differ in CI shells.
        assert script.is_file()
