"""Map TUI form state to UnlockOptions + validation (no I/O)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from dietrich.types import UnlockOptions


@dataclass(frozen=True)
class FormState:
    """Snapshot of TUI controls used to build UnlockOptions."""

    password: str = ""
    wordlist: str = ""
    mask: str = ""
    soft_only: bool = False
    strip_signatures: bool = False
    unlock_vba: bool = False
    use_hashcat: bool = False
    workers: int = 1
    overwrite: bool = False
    resign_cert: str = ""
    resign_key: str = ""
    hashcat_timeout: str = ""


@dataclass(frozen=True)
class ValidationResult:
    """Either a ready UnlockOptions or a user-facing error message."""

    options: UnlockOptions | None = None
    error: str | None = None

    @property
    def ok(self) -> bool:
        """True when options were built without a validation error."""
        return self.options is not None and self.error is None


def _empty_to_none(value: str) -> str | None:
    """Strip whitespace; treat empty as None for optional form fields."""
    text = (value or "").strip()
    return text or None


def _path_or_none(value: str) -> Path | None:
    """Parse a non-empty path string into Path, else None."""
    text = _empty_to_none(value)
    return Path(text) if text else None


def validate_and_build(state: FormState) -> ValidationResult:
    """Validate form state and return UnlockOptions or an error string."""
    cert = _path_or_none(state.resign_cert)
    key = _path_or_none(state.resign_key)
    if (cert is None) ^ (key is None):
        return ValidationResult(
            error="Re-sign needs both certificate PEM and key PEM (or leave both empty)."
        )

    wordlist = _path_or_none(state.wordlist)
    if wordlist is not None and not wordlist.is_file():
        return ValidationResult(error=f"Wordlist not found: {wordlist}")

    if state.use_hashcat:
        mask = _empty_to_none(state.mask)
        if wordlist is None and mask is None:
            return ValidationResult(error="Hashcat needs a wordlist, a mask, or leave Hashcat off.")

    workers = max(1, int(state.workers or 1))
    timeout: int | None = None
    timeout_raw = _empty_to_none(state.hashcat_timeout)
    if timeout_raw is not None:
        try:
            timeout = int(timeout_raw)
            if timeout <= 0:
                raise ValueError
        except ValueError:
            return ValidationResult(error="Hashcat timeout must be a positive integer (seconds).")

    options = UnlockOptions(
        remove_worksheet_protection=True,
        remove_workbook_protection=True,
        remove_document_protection=True,
        remove_modify_verifier=True,
        remove_mark_as_final=True,
        strip_pdf_permissions=True,
        strip_signatures=state.strip_signatures,
        unlock_vba=state.unlock_vba,
        soft_only=state.soft_only,
        password=_empty_to_none(state.password),
        wordlist=wordlist,
        mask=_empty_to_none(state.mask),
        workers=workers,
        overwrite=state.overwrite,
        resign_cert=cert,
        resign_key=key,
        use_hashcat=state.use_hashcat,
        hashcat_timeout=timeout,
    )
    return ValidationResult(options=options)


def form_state_from_widgets(
    values: dict[str, str],
    checks: dict[str, bool],
) -> FormState:
    """Build :class:`FormState` from widget id → value / checked maps.

    ``values`` keys: password, wordlist, mask, workers, resign-cert,
    resign-key, hashcat-timeout.
    ``checks`` keys: chk-soft-only, chk-strip-sig, chk-vba, chk-hashcat,
    chk-overwrite.
    """
    workers_raw = (values.get("workers") or "").strip() or "1"
    try:
        workers = max(1, int(workers_raw))
    except ValueError:
        workers = 1
    return FormState(
        password=values.get("password", ""),
        wordlist=values.get("wordlist", ""),
        mask=values.get("mask", ""),
        soft_only=checks.get("chk-soft-only", False),
        strip_signatures=checks.get("chk-strip-sig", False),
        unlock_vba=checks.get("chk-vba", False),
        use_hashcat=checks.get("chk-hashcat", False),
        workers=workers,
        overwrite=checks.get("chk-overwrite", False),
        resign_cert=values.get("resign-cert", ""),
        resign_key=values.get("resign-key", ""),
        hashcat_timeout=values.get("hashcat-timeout", ""),
    )


def default_output_path(input_path: Path) -> Path:
    """Match CLI default: ``stem_unprotected`` + original suffix."""
    return input_path.with_name(f"{input_path.stem}_unprotected{input_path.suffix}")
