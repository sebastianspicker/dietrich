"""PDF encryption/permissions inspection for classify and CLI --inspect."""

from __future__ import annotations

from pathlib import Path

from dietrich.types import DocumentFormat, DocumentInspection


def inspect_pdf(path: Path) -> DocumentInspection:
    """Return DocumentInspection for a PDF path."""
    input_path = Path(path)
    strategies: list[str] = ["soft:pdf_permissions"]
    notes: list[str] = []
    encrypted = False
    user_required = False
    owner_restrictions = False

    try:
        import pikepdf
    except ImportError:
        notes.append("Install dietrich[pdf] (pikepdf) for full PDF inspect/unlock.")
        # Heuristic: look for /Encrypt in raw bytes
        blob = input_path.read_bytes()[:200_000]
        if b"/Encrypt" in blob:
            encrypted = True
            user_required = True
            strategies.extend(["crypto:pdf_password", "crypto:wordlist", "crypto:export_hash"])
        return DocumentInspection(
            input_path=input_path,
            document_format=DocumentFormat.PDF,
            strategies=tuple(strategies),
            encrypted=encrypted,
            user_password_required=user_required,
            owner_restrictions=bool(encrypted),
            notes=tuple(notes),
        )

    try:
        with pikepdf.open(input_path) as pdf:
            # Opened without password
            encrypted = bool(pdf.is_encrypted)
            # If encrypted but opened empty password, may still have restrictions
            owner_restrictions = encrypted
            if encrypted:
                strategies.append("soft:pdf_permissions")
    except pikepdf.PasswordError:
        encrypted = True
        user_required = True
        owner_restrictions = True
        strategies.extend(["crypto:pdf_password", "crypto:wordlist", "crypto:export_hash"])
        notes.append("User password required to open this PDF.")
    except Exception as exc:
        notes.append(f"PDF inspect limited: {exc}")

    return DocumentInspection(
        input_path=input_path,
        document_format=DocumentFormat.PDF,
        strategies=tuple(dict.fromkeys(strategies)),
        encrypted=encrypted,
        user_password_required=user_required,
        owner_restrictions=owner_restrictions,
        notes=tuple(notes),
    )
