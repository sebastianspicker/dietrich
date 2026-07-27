"""Legacy binary (CFBF/BIFF) inspect + soft protection rewrite."""

from dietrich.legacy.binary_soft import unlock_binary_office
from dietrich.legacy.cfbf import inspect_cfbf, is_cfbf

__all__ = ["inspect_cfbf", "is_cfbf", "unlock_binary_office"]
