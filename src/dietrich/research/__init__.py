"""Research-only helpers (fuzz generation). Not weaponized."""

from dietrich.research.cli import main
from dietrich.research.fuzz_gen import generate_ooxml_mutants, generate_xml_part_mutants

__all__ = ["generate_ooxml_mutants", "generate_xml_part_mutants", "main"]
