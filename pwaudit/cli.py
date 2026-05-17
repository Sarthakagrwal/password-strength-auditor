"""Command-line interface for the password strength auditor.

Usage patterns
--------------
* ``pwaudit`` — prompt for a single password via :func:`getpass.getpass` (the
  input is never echoed to the terminal) and print a full report.
* ``pwaudit --file passwords.txt`` — audit every non-empty line of a file and
  print a compact table.
* ``pwaudit --json`` — emit machine-readable JSON instead of a formatted report.
* ``pwaudit --no-hibp`` — skip the breach check and run fully offline.

Privacy guarantee
-----------------
The password is held in memory only for the duration of the audit. The CLI
**never** echoes it, **never** prints it back, **never** logs it and **never**
writes it (or any file derived from it) to disk. ``--file`` reads passwords from
a path the user supplies; it does not create one. All output — table, JSON,
report — contains only derived metrics, never the password itself.
"""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence

from pwaudit import __version__
from pwaudit.audit import VERDICT_UNSAFE, VERDICT_WEAK, AuditReport, audit
from pwaudit.entropy import SCENARIO_LABELS

# ANSI colour codes; suppressed automatically when stdout is not a TTY.
_COLOURS = {
    "safe": "\033[32m",
    "warn": "\033[33m",
    "danger": "\033[31m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}


def _supports_colour() -> bool:
    """Return ``True`` if ANSI colour should be used on stdout."""
    return sys.stdout.isatty()


def _paint(text: str, colour: str, enabled: bool) -> str:
    """Wrap *text* in an ANSI *colour* when *enabled*, else return it plain."""
    if not enabled or colour not in _COLOURS:
        return text
    return f"{_COLOURS[colour]}{text}{_COLOURS['reset']}"


def _build_parser() -> argparse.ArgumentParser:
    """Construct the :class:`argparse.ArgumentParser` for the CLI."""
    parser = argparse.ArgumentParser(
        prog="pwaudit",
        description=(
            "Score password strength and privately check it against real-world "
            "breaches (Have I Been Pwned k-anonymity). The password is never "
            "transmitted, logged or written to disk."
        ),
        epilog=(
            "With no --file, you are prompted for a password without it being "
            "echoed to the terminal."
        ),
    )
    parser.add_argument(
        "--file",
        metavar="PATH",
        help="audit every non-empty line of this file (one password per line)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON instead of a formatted report",
    )
    parser.add_argument(
        "--no-hibp",
        action="store_true",
        help="skip the breach check and run fully offline",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _verdict_colour(report: AuditReport) -> str:
    """Map a report's risk band to a colour key."""
    return report.risk


# --- Single-password rendering --------------------------------------------------


def _render_report(report: AuditReport, colour: bool) -> str:
    """Render a single :class:`AuditReport` as a formatted multi-line string."""
    lines: list[str] = []
    z = report.strength.zxcvbn
    cs = report.strength.charset

    verdict_text = _paint(f" {report.verdict} ", _verdict_colour(report), colour)
    lines.append("")
    lines.append(f"  Verdict : {verdict_text}  (score {report.score}/4 — {report.score_label})")
    lines.append(f"  {_paint(report.summary, 'dim', colour)}")
    lines.append("")

    # Strength block.
    lines.append(_paint("  STRENGTH", "bold", colour))
    classes = []
    if cs.has_lowercase:
        classes.append("lower")
    if cs.has_uppercase:
        classes.append("upper")
    if cs.has_digits:
        classes.append("digits")
    if cs.has_symbols:
        classes.append("symbols")
    lines.append(
        f"    Length {cs.length}, character pool {cs.pool_size} ({', '.join(classes) or 'none'})"
    )
    lines.append(
        f"    Naive charset entropy : {report.strength.naive_entropy_bits:.1f} bits "
        f"{_paint('(optimistic — assumes randomness)', 'dim', colour)}"
    )
    lines.append(
        f"    zxcvbn estimate       : 10^{z.guesses_log10:.1f} guesses "
        f"{_paint('(realistic — the number to trust)', 'dim', colour)}"
    )

    # Crack-time table (zxcvbn's realistic figures).
    lines.append("")
    lines.append(_paint("  CRACK TIME (zxcvbn estimate)", "bold", colour))
    for key, label in SCENARIO_LABELS.items():
        value = z.crack_times_display.get(key, "—")
        lines.append(f"    {label:<42} {value}")

    # zxcvbn feedback.
    if z.warning or z.suggestions:
        lines.append("")
        lines.append(_paint("  FEEDBACK", "bold", colour))
        if z.warning:
            lines.append(f"    ! {z.warning}")
        for suggestion in z.suggestions:
            lines.append(f"    - {suggestion}")

    # Our transparent pattern findings.
    if report.patterns:
        lines.append("")
        lines.append(_paint("  PATTERN FINDINGS", "bold", colour))
        for finding in report.patterns:
            lines.append(f"    {_paint('x', 'danger', colour)} {finding.reason}")

    # Breach status.
    lines.append("")
    lines.append(_paint("  BREACH CHECK (Have I Been Pwned)", "bold", colour))
    status_colour = "danger" if report.breached else "safe"
    if report.breach_count is None or not report.hibp_checked:
        status_colour = "warn"
    lines.append(f"    {_paint(report.breach_status, status_colour, colour)}")
    if report.hibp_checked:
        lines.append(
            f"    {
                _paint(
                    'Only a 5-char SHA-1 prefix was sent — the password never left this machine.',
                    'dim',
                    colour,
                )
            }"
        )
    lines.append("")
    return "\n".join(lines)


# --- File-mode (table) rendering ------------------------------------------------


def _render_table(reports: Sequence[tuple[int, AuditReport]], colour: bool) -> str:
    """Render audits of a password list as a compact table.

    Each row is identified by its 1-based line number, never by the password.
    """
    header = f"  {'LINE':<6}{'SCORE':<8}{'VERDICT':<10}{'BREACH':<28}SUMMARY"
    lines = ["", header, "  " + "-" * (len(header) - 2)]
    for line_no, report in reports:
        verdict = _paint(f"{report.verdict:<9}", _verdict_colour(report), colour)
        breach = report.breach_status
        if len(breach) > 26:
            breach = breach[:25] + "…"
        short_summary = report.summary.split(".")[0]
        lines.append(f"  #{line_no:<5}{report.score}/4     {verdict} {breach:<28}{short_summary}")
    lines.append("")
    return "\n".join(lines)


# --- Input helpers --------------------------------------------------------------


def _read_password_list(path: str) -> list[str]:
    """Read non-empty, non-comment lines from *path* as passwords.

    Trailing newlines are stripped. Blank lines and lines beginning with ``#``
    are skipped so the file can carry comments.
    """
    with open(path, encoding="utf-8") as handle:
        passwords: list[str] = []
        for raw in handle:
            line = raw.rstrip("\n\r")
            if not line or line.lstrip().startswith("#"):
                continue
            passwords.append(line)
    return passwords


def _prompt_password() -> str:
    """Prompt for a password without echoing it to the terminal."""
    return getpass.getpass("Password to audit (input hidden): ")


# --- Exit-code policy -----------------------------------------------------------


def _is_failing(report: AuditReport) -> bool:
    """Return ``True`` if a report should make the CLI exit non-zero.

    A password "fails" if it is breached (``UNSAFE``) or weak (``WEAK``); only a
    ``SAFE`` verdict passes.
    """
    return report.verdict in (VERDICT_UNSAFE, VERDICT_WEAK)


# --- Entry points ---------------------------------------------------------------


def _run_file_mode(path: str, *, check_breaches: bool, as_json: bool, colour: bool) -> int:
    """Audit a password file and print results. Returns the process exit code."""
    try:
        passwords = _read_password_list(path)
    except OSError as exc:
        print(f"error: cannot read file '{path}': {exc}", file=sys.stderr)
        return 2

    if not passwords:
        print(f"error: file '{path}' contains no passwords", file=sys.stderr)
        return 2

    reports = [
        (i, audit(pw, check_breaches=check_breaches)) for i, pw in enumerate(passwords, start=1)
    ]

    if as_json:
        payload = {
            "count": len(reports),
            "results": [{"line": line_no, **report.to_dict()} for line_no, report in reports],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(_render_table(reports, colour))

    # Non-zero exit if ANY password is weak or breached.
    return 1 if any(_is_failing(r) for _, r in reports) else 0


def _run_single_mode(*, check_breaches: bool, as_json: bool, colour: bool) -> int:
    """Prompt for one password, audit it, print the result. Returns exit code."""
    try:
        password = _prompt_password()
    except (KeyboardInterrupt, EOFError):
        print("\naborted.", file=sys.stderr)
        return 130

    if not password:
        print("error: empty password — nothing to audit", file=sys.stderr)
        return 2

    report = audit(password, check_breaches=check_breaches)

    if as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_report(report, colour))

    return 1 if _is_failing(report) else 0


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code (0 = all audited passwords safe).

    Exit codes:
        * ``0`` — every audited password is SAFE.
        * ``1`` — at least one password is WEAK or breached (UNSAFE).
        * ``2`` — a usage / input error (e.g. unreadable file, empty password).
        * ``130`` — interrupted at the password prompt.
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    check_breaches = not args.no_hibp
    as_json = bool(args.json)
    colour = _supports_colour() and not as_json

    if args.file:
        return _run_file_mode(
            args.file, check_breaches=check_breaches, as_json=as_json, colour=colour
        )
    return _run_single_mode(check_breaches=check_breaches, as_json=as_json, colour=colour)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
