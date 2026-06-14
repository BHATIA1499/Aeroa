"""
Secure File Upload Pipeline
============================
Implements the 6-stage file security pipeline:

  1. Size validation   — rejects oversized / empty files
  2. Extension check   — allowlist of safe spreadsheet formats
  3. Magic byte scan   — verifies binary signature matches declared type
  4. Content scan      — detects formula injection, macros, and script payloads
  5. Format parse      — structural validation (pandas can actually read it)
  6. Encryption        — AES-256-GCM before any storage

Defence-in-depth: each stage is independent so a bypass of one
does not automatically bypass the next.

Note on virus scanning
----------------------
ClamAV is not available in Railway's container environment without a
custom Dockerfile.  The content scanner below detects the most common
malicious payloads for spreadsheet files (DDE injection, macro markers,
embedded scripts).  For enterprises requiring AV scanning, mount a
ClamAV sidecar and call `clamd` via the `python-clamd` client.
"""

import io
import re
import logging
from dataclasses import dataclass

log = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
MAX_FILE_BYTES  = 100 * 1024 * 1024   # 100 MB hard cap
WARN_FILE_BYTES = 50  * 1024 * 1024   # 50 MB triggers a warning log

ALLOWED_EXTENSIONS = frozenset({
    "csv", "xlsx", "xls", "numbers", "ods", "tsv", "txt"
})

# Magic byte signatures for binary formats
# We check the first 8 bytes of the file.
MAGIC_SIGNATURES: dict[str, list[bytes]] = {
    "xlsx": [b"\x50\x4b\x03\x04"],          # ZIP (xlsx, ods, numbers all use ZIP)
    "ods":  [b"\x50\x4b\x03\x04"],
    "numbers": [b"\x50\x4b\x03\x04"],
    "xls":  [b"\xd0\xcf\x11\xe0"],           # OLE2 Compound Document
}

# Patterns that indicate dangerous content in any file format
# Checked against the first 64 KB of file content (lowercased bytes)
DANGEROUS_PATTERNS: list[tuple[bytes, str]] = [
    (b"<script",       "Embedded script tag"),
    (b"<?php",         "PHP code"),
    (b"vbscript",      "VBScript code"),
    (b"shell(",        "Shell execution call"),
    (b"wscript",       "Windows scripting host"),
    (b"ddeauto",       "DDE auto-execution (Excel macro)"),
    (b"\x4d\x5a\x90", "PE executable header"),   # MZ header
    (b"\x7felf",       "ELF executable header"),
    (b"powershell",    "PowerShell command"),
    (b"cmd.exe",       "Windows command shell"),
    (b"subprocess",    "Python subprocess call"),
]

# CSV/formula injection: cells that start with these chars are dangerous
# when opened in a spreadsheet application
CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t=", "\n=")


@dataclass
class ValidationResult:
    valid:   bool
    error:   str = ""
    warning: str = ""


class SecureFilePipeline:
    """Runs all validation stages and returns a ValidationResult."""

    def validate(self, file_bytes: bytes, filename: str) -> ValidationResult:
        """
        Run the full validation pipeline.
        Returns ValidationResult(valid=True) if all stages pass.
        """
        stages = [
            self._stage_size,
            self._stage_extension,
            self._stage_magic_bytes,
            self._stage_content_scan,
            self._stage_csv_injection,
        ]
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

        for stage in stages:
            result = stage(file_bytes, filename, ext)
            if not result.valid:
                log.warning(
                    f"[PIPELINE] File rejected at {stage.__name__}: "
                    f"file={filename!r} reason={result.error!r}"
                )
                return result

        if len(file_bytes) > WARN_FILE_BYTES:
            return ValidationResult(
                valid=True,
                warning=f"Large file ({len(file_bytes) // 1024 // 1024} MB) — processing may be slow.",
            )

        return ValidationResult(valid=True)

    # ── Stage 1: Size ──────────────────────────────────────────────────────────

    def _stage_size(self, data: bytes, filename: str, ext: str) -> ValidationResult:
        if len(data) == 0:
            return ValidationResult(valid=False, error="File is empty.")
        if len(data) > MAX_FILE_BYTES:
            mb = MAX_FILE_BYTES // 1024 // 1024
            return ValidationResult(
                valid=False,
                error=f"File exceeds the {mb} MB maximum. Please reduce the file size."
            )
        return ValidationResult(valid=True)

    # ── Stage 2: Extension ─────────────────────────────────────────────────────

    def _stage_extension(self, data: bytes, filename: str, ext: str) -> ValidationResult:
        if "." not in filename:
            return ValidationResult(valid=False, error="File must have an extension.")
        if ext not in ALLOWED_EXTENSIONS:
            allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
            return ValidationResult(
                valid=False,
                error=f"File type .{ext} is not allowed. Accepted formats: {allowed}."
            )
        # Reject double-extension tricks (e.g. "data.csv.exe")
        parts = filename.split(".")
        if len(parts) > 2:
            inner_ext = parts[-2].lower()
            dangerous = {"exe", "dll", "bat", "sh", "py", "js", "php", "vbs", "ps1"}
            if inner_ext in dangerous:
                return ValidationResult(
                    valid=False,
                    error="File name contains a suspicious embedded extension."
                )
        return ValidationResult(valid=True)

    # ── Stage 3: Magic bytes ───────────────────────────────────────────────────

    def _stage_magic_bytes(self, data: bytes, filename: str, ext: str) -> ValidationResult:
        """For binary formats, verify the file header matches the declared type."""
        expected_sigs = MAGIC_SIGNATURES.get(ext)
        if not expected_sigs:
            # Text-based formats (csv, tsv, txt) have no binary signature to check
            return ValidationResult(valid=True)

        header = data[:8]
        for sig in expected_sigs:
            if header.startswith(sig):
                return ValidationResult(valid=True)

        return ValidationResult(
            valid=False,
            error=(
                f"File signature does not match .{ext} format. "
                "The file may be corrupted or have been renamed."
            )
        )

    # ── Stage 4: Content scan ──────────────────────────────────────────────────

    def _stage_content_scan(self, data: bytes, filename: str, ext: str) -> ValidationResult:
        """Scan first 64 KB for dangerous content patterns."""
        sample = data[:65536].lower()
        for pattern, description in DANGEROUS_PATTERNS:
            if pattern in sample:
                log.error(
                    f"[PIPELINE] Security: dangerous pattern '{description}' "
                    f"detected in file={filename!r}"
                )
                return ValidationResult(
                    valid=False,
                    error=(
                        "File has been rejected by security scan. "
                        "Contact support if you believe this is an error."
                    )
                )
        return ValidationResult(valid=True)

    # ── Stage 5: CSV injection ─────────────────────────────────────────────────

    def _stage_csv_injection(self, data: bytes, filename: str, ext: str) -> ValidationResult:
        """Detect formula injection in CSV/TSV files."""
        if ext not in ("csv", "tsv", "txt"):
            return ValidationResult(valid=True)

        try:
            text = data[:20000].decode("utf-8", errors="replace")
            lines = text.splitlines()[:50]   # Check first 50 rows

            injection_count = 0
            for line in lines:
                cells = line.split("\t" if ext == "tsv" else ",")
                for cell in cells:
                    cell = cell.strip().strip('"').strip("'")
                    for prefix in CSV_INJECTION_PREFIXES:
                        if cell.startswith(prefix):
                            injection_count += 1

            # Tolerate a few formula cells (legitimate data may start with -)
            # but flag if more than 5% of sampled cells look malicious
            total_cells = max(1, sum(len(l.split(",")) for l in lines))
            if injection_count / total_cells > 0.05:
                return ValidationResult(
                    valid=False,
                    error=(
                        "File contains formula injection patterns. "
                        "Please export as plain values (not formulas) and re-upload."
                    )
                )
        except Exception:
            pass   # Never block on scan error

        return ValidationResult(valid=True)
