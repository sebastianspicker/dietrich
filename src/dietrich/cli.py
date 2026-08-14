"""Command-line interface for Dietrich.

Parses flags into :class:`~dietrich.types.UnlockOptions` and routes through
:mod:`dietrich.dispatch`. Terminal UI: ``dietrich --tui``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from dietrich.brand import HELP_DESCRIPTION, HELP_EPILOG
from dietrich.dispatch import (
    export_document_hash,
    inspect_document,
    unlock_document,
)
from dietrich.errors import (
    DietrichError,
    MissingDependencyError,
    OutputExistsError,
    PasswordNotFoundError,
)
from dietrich.types import DocumentInspection, UnlockOptions, UnlockResult


def main(argv: Sequence[str] | None = None) -> int:
    """Parse argv and run inspect/export/unlock; return process exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return _execute_parsed_args(args, parser)
    except OutputExistsError as exc:
        print(f"error: {exc} Use --force to overwrite.", file=sys.stderr)
        return 2
    except PasswordNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except MissingDependencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    except DietrichError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _execute_parsed_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    """Route parsed flags to UI, research, or the ordinary document command."""
    if getattr(args, "tui", False):
        return _run_tui(args.input)
    if getattr(args, "research_fuzz", False):
        if not args.input:
            parser.error("INPUT is required for --research-fuzz")
        return _run_research_fuzz(args)
    if not args.input:
        parser.error("INPUT is required (or pass --tui for the terminal UI)")
    return _run_document_command(args)


def _run_tui(input_path: str | None) -> int:
    """Launch the optional terminal UI with its established exit contract."""
    from dietrich.tui import run_tui

    try:
        return run_tui(initial_path=input_path)
    except MissingDependencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3


def _run_document_command(args: argparse.Namespace) -> int:
    """Handle export, inspection, or unlock for a validated input path."""
    input_path = Path(args.input)
    if args.export_hash:
        print(export_document_hash(input_path, args.export_hash))
        return 0
    if args.inspect:
        _print_document_inspection(inspect_document(input_path), as_json=args.json)
        return 0

    output_path = Path(args.output) if args.output else _default_output_path(input_path)
    options = _options_from_args(args)
    if (options.resign_cert is None) ^ (options.resign_key is None):
        print("error: --resign-cert and --resign-key must be provided together", file=sys.stderr)
        return 2
    result = unlock_document(input_path, output_path, options)
    _print_unlock_result(result, as_json=args.json)
    return 0


def _options_from_args(args: argparse.Namespace) -> UnlockOptions:
    """Translate parsed CLI flags into the public unlock options value."""
    options = UnlockOptions(
        remove_worksheet_protection=True,
        remove_workbook_protection=not args.worksheets_only,
        remove_document_protection=not args.keep_document_protection,
        remove_modify_verifier=not args.keep_modify_verifier,
        strip_pdf_permissions=True,
        strip_signatures=args.strip_signatures,
        unlock_vba=args.vba,
        soft_only=args.soft_only,
        password=args.password,
        wordlist=Path(args.wordlist) if args.wordlist else None,
        mask=args.mask,
        charset=args.charset if args.brute or args.charset else None,
        max_length=args.max_length,
        max_candidates=args.max_candidates,
        workers=max(1, args.workers),
        overwrite=args.force,
        resign_cert=Path(args.resign_cert) if args.resign_cert else None,
        resign_key=Path(args.resign_key) if args.resign_key else None,
        use_hashcat=args.hashcat,
        hashcat_args=tuple(args.hashcat_arg or ()),
        hashcat_timeout=args.hashcat_timeout,
    )
    return _with_default_brute_options(options, args)


def _with_default_brute_options(options: UnlockOptions, args: argparse.Namespace) -> UnlockOptions:
    """Apply the documented bounded brute-force defaults when requested."""
    if not args.brute or args.charset:
        return options
    return replace(
        options,
        charset="digits",
        max_length=4 if options.max_length is None else options.max_length,
    )


def _print_document_inspection(inspection: DocumentInspection, *, as_json: bool) -> None:
    """Render inspection output in the requested established format."""
    if as_json:
        print(json.dumps(_inspection_dict(inspection), indent=2, default=str))
    else:
        _print_inspection(inspection)


def _print_unlock_result(result: UnlockResult, *, as_json: bool) -> None:
    """Render unlock output in the requested established format."""
    if as_json:
        print(json.dumps(_result_dict(result), indent=2, default=str))
    else:
        _print_result(result)


def _run_research_fuzz(args: argparse.Namespace) -> int:
    """Generate local OOXML mutants for lab research (not product unlock)."""
    from dietrich.research.fuzz_gen import generate_ooxml_mutants, generate_xml_part_mutants

    seed = Path(args.input)
    out = Path(args.output) if args.output else Path("research/fuzz/out")
    paths = generate_xml_part_mutants(seed, out, count=args.fuzz_count, seed=args.fuzz_seed)
    if not paths:
        paths = generate_ooxml_mutants(seed, out, count=args.fuzz_count, seed=args.fuzz_seed)
    print(f"Wrote {len(paths)} mutants under {out}")
    print("Lab use only: do not distribute as weaponized documents.")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    """Construct the ``dietrich`` argparse CLI."""
    parser = argparse.ArgumentParser(
        prog="dietrich",
        description=HELP_DESCRIPTION,
        epilog=HELP_EPILOG,
    )
    _add_document_arguments(parser)
    _add_recovery_arguments(parser)
    _add_advanced_arguments(parser)
    return parser


def _add_document_arguments(parser: argparse.ArgumentParser) -> None:
    """Add input, UI, output, and soft-protection command flags."""
    parser.add_argument(
        "input",
        metavar="INPUT",
        nargs="?",
        default=None,
        help="Input document path (optional with --tui)",
    )
    parser.add_argument(
        "--tui",
        action="store_true",
        help="Launch the terminal UI (requires: pip install 'dietrich[ui]')",
    )
    parser.add_argument("--output", metavar="PATH", help="Output path")
    parser.add_argument("--inspect", action="store_true", help="Inspect without writing output")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output")
    parser.add_argument(
        "--worksheets-only",
        action="store_true",
        help="Excel: remove sheet protection only",
    )
    parser.add_argument(
        "--keep-document-protection",
        action="store_true",
        help="Word: keep documentProtection",
    )
    parser.add_argument(
        "--keep-modify-verifier",
        action="store_true",
        help="PowerPoint: keep modifyVerifier",
    )


def _add_recovery_arguments(parser: argparse.ArgumentParser) -> None:
    """Add open-password recovery and external hashcat command flags."""
    parser.add_argument(
        "--soft-only", action="store_true", help="Never attempt open-password recovery"
    )
    parser.add_argument("--password", help="Password for open-encrypted documents")
    parser.add_argument("--wordlist", metavar="PATH", help="Password wordlist file")
    parser.add_argument("--mask", help="Mask attack pattern, e.g. '?d?d?d?d'")
    parser.add_argument(
        "--brute",
        action="store_true",
        help="Enable brute force (requires --charset/--max-length; default digits len<=4)",
    )
    parser.add_argument(
        "--charset",
        help="Charset name for brute: digits, lower, upper, alpha, alnum, printable",
    )
    parser.add_argument("--max-length", type=int, help="Max brute length")
    parser.add_argument(
        "--max-candidates",
        type=int,
        default=5_000_000,
        help="Cap on password candidates (default 5000000)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Parallel password-verify workers for wordlist/mask/brute (default 1)",
    )
    parser.add_argument(
        "--hashcat",
        action="store_true",
        help="External hashcat GPU recovery (needs --wordlist, --mask, or --hashcat-arg)",
    )
    parser.add_argument(
        "--hashcat-arg",
        action="append",
        default=[],
        help="Extra argument passed to hashcat (repeatable)",
    )
    parser.add_argument(
        "--hashcat-timeout",
        type=int,
        default=None,
        help="Seconds before hashcat is aborted (default: no limit)",
    )


def _add_advanced_arguments(parser: argparse.ArgumentParser) -> None:
    """Add signing, VBA, hash-export, and lab-only fuzzing command flags."""
    parser.add_argument(
        "--resign-cert",
        metavar="PEM",
        help="After unlock, re-sign OOXML with this certificate (PEM)",
    )
    parser.add_argument(
        "--resign-key",
        metavar="PEM",
        help="Private key PEM for --resign-cert (honest re-sign only)",
    )
    parser.add_argument(
        "--export-hash",
        choices=("hashcat", "john"),
        help="Export a hash line for external GPU tools and exit",
    )
    parser.add_argument(
        "--strip-signatures",
        action="store_true",
        help="Strip OOXML digital signatures (unsigned working copy; loud warning)",
    )
    parser.add_argument(
        "--vba",
        action="store_true",
        help="Clear VBA project password verifiers in vbaProject.bin (opt-in)",
    )
    parser.add_argument(
        "--research-fuzz",
        action="store_true",
        help="Experimental: generate local fuzz mutants from INPUT into --output dir",
    )
    parser.add_argument(
        "--fuzz-count",
        type=int,
        default=10,
        help="Experimental: mutant count for --research-fuzz",
    )
    parser.add_argument(
        "--fuzz-seed",
        type=int,
        default=0,
        help="Experimental: RNG seed for --research-fuzz",
    )


def _default_output_path(input_path: Path) -> Path:
    """Return ``stem_unprotected`` + original suffix next to the input."""
    return input_path.with_name(f"{input_path.stem}_unprotected{input_path.suffix}")


def _print_inspection(inspection: DocumentInspection) -> None:
    """Human-readable --inspect output."""
    print(f"Document: {inspection.input_path}")
    print(f"Format: {inspection.document_format.value}")
    print(f"Encrypted: {inspection.encrypted}")
    print(f"Signed: {inspection.signed}")
    print(f"User password required: {inspection.user_password_required}")
    print(f"Owner restrictions: {inspection.owner_restrictions}")
    print(f"VBA project: {'present' if inspection.vba_project_present else 'absent'}")
    _print_encryption_details(inspection)
    _print_irm_status(inspection.input_path)
    _print_inspection_collections(inspection)


def _print_encryption_details(inspection: DocumentInspection) -> None:
    """Print optional open-encryption metadata."""
    if inspection.encryption_scheme:
        print(f"Encryption scheme: {inspection.encryption_scheme}")
        print(f"Encryption version: {inspection.encryption_version}")
        print(f"Spin count: {inspection.encryption_spin_count}")
        print(f"Cost class: {inspection.encryption_cost_class}")
        if inspection.hashcat_mode:
            print(f"Hashcat mode: {inspection.hashcat_mode}")


def _print_irm_status(path: Path) -> None:
    """Print the best-effort rights-management probe result."""
    try:
        from dietrich.crypto.irm import detect_irm

        irm = detect_irm(path)
        print(f"IRM/RMS: {'yes (' + irm.kind + ')' if irm.is_irm else 'no'}")
    except (AttributeError, OSError, TypeError, ValueError):
        print("IRM/RMS: unknown")


def _print_inspection_collections(inspection: DocumentInspection) -> None:
    """Print strategy, soft-protection, and note collections."""
    print("Strategies:")
    for strategy in inspection.strategies:
        print(f"  - {strategy}")
    if inspection.soft_protections:
        print("Soft protections:")
        for part in inspection.soft_protections:
            print(f"  - {part.path}: {part.kind} x{part.count}")
    for note in inspection.notes:
        print(f"note: {note}")


def _print_result(result: UnlockResult) -> None:
    """Human-readable unlock success summary."""
    print(f"Wrote: {result.output_path}")
    print(f"Format: {result.document_format.value}")
    r = result.removed
    print(f"Removed worksheet protections: {r.worksheet_protections}")
    print(f"Removed workbook protections: {r.workbook_protections}")
    print(f"Removed document protections: {r.document_protections}")
    print(f"Removed modify verifiers: {r.modify_verifiers}")
    print(f"PDF permission strips: {r.pdf_permission_strips}")
    print(f"Signatures stripped: {r.signatures_stripped}")
    print(f"VBA unlocked: {r.vba_unlocked}")
    if result.password_used is not None:
        print("Password: recovered (not echoed by default)")
    if result.vba_project_present and r.vba_unlocked == 0:
        print("VBA project detected: pass --vba to attempt password field clear.")
    for warning in result.warnings:
        print(f"warning: {warning}")


def _inspection_dict(inspection: DocumentInspection) -> dict:
    """JSON-serializable dict for --inspect --json."""
    return {
        "input_path": str(inspection.input_path),
        "document_format": inspection.document_format.value,
        "strategies": list(inspection.strategies),
        "soft_protections": [
            {"path": p.path, "kind": p.kind, "count": p.count} for p in inspection.soft_protections
        ],
        "encrypted": inspection.encrypted,
        "signed": inspection.signed,
        "vba_project_present": inspection.vba_project_present,
        "user_password_required": inspection.user_password_required,
        "owner_restrictions": inspection.owner_restrictions,
        "encryption_scheme": inspection.encryption_scheme,
        "encryption_version": inspection.encryption_version,
        "encryption_spin_count": inspection.encryption_spin_count,
        "encryption_cost_class": inspection.encryption_cost_class,
        "hashcat_mode": inspection.hashcat_mode,
        "notes": list(inspection.notes),
    }


def _result_dict(result: UnlockResult) -> dict:
    """JSON-serializable dict for unlock --json."""
    r = result.removed
    return {
        "input_path": str(result.input_path),
        "output_path": str(result.output_path),
        "document_format": result.document_format.value,
        "removed": {
            "worksheet_protections": r.worksheet_protections,
            "workbook_protections": r.workbook_protections,
            "document_protections": r.document_protections,
            "modify_verifiers": r.modify_verifiers,
            "pdf_permission_strips": r.pdf_permission_strips,
            "signatures_stripped": r.signatures_stripped,
            "vba_unlocked": r.vba_unlocked,
        },
        "vba_project_present": result.vba_project_present,
        "password_recovered": result.password_used is not None,
        "warnings": list(result.warnings),
    }
