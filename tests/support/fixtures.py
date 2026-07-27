"""Paths and public credentials shared by the active test suite."""

from pathlib import Path

TESTS_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = TESTS_ROOT / "fixtures"
ENCRYPTED_XLSX = FIXTURES / "example_password.xlsx"
ENCRYPTED_DOCX = FIXTURES / "example_password.docx"
PLAIN_XLS = FIXTURES / "plain.xls"
PLAIN_DOC = FIXTURES / "plain.doc"
PLAIN_PPT = FIXTURES / "plain.ppt"
KNOWN_PASSWORD = "Password1234_"
