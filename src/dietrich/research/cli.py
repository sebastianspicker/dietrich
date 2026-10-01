"""Command-line entry point for the experimental OOXML mutation research tool.

This is a local lab utility, kept deliberately separate from the ``dietrich``
document command. It generates mutated copies of a seed OOXML document for
fuzzing local parsers. It never touches passwords, keys, or the unlock path.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from dietrich.research.fuzz_gen import generate_ooxml_mutants, generate_xml_part_mutants

DEFAULT_OUTPUT = Path("research/fuzz/out")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dietrich-research",
        description="Generate local OOXML fuzz mutants from a seed document (lab use only).",
    )
    parser.add_argument("input", metavar="INPUT", help="Seed OOXML document to mutate")
    parser.add_argument(
        "--output",
        metavar="PATH",
        help=f"Directory for generated mutants (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--count", type=int, default=10, help="Number of mutants to generate")
    parser.add_argument("--seed", type=int, default=0, help="RNG seed for reproducible mutants")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments and write fuzz mutants; return a process exit code."""
    args = _build_parser().parse_args(argv)
    seed = Path(args.input)
    out = Path(args.output) if args.output else DEFAULT_OUTPUT
    paths = generate_xml_part_mutants(seed, out, count=args.count, seed=args.seed)
    if not paths:
        paths = generate_ooxml_mutants(seed, out, count=args.count, seed=args.seed)
    print(f"Wrote {len(paths)} mutants under {out}")
    print("Lab use only: do not distribute as weaponized documents.")
    return 0
