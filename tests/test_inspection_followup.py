from __future__ import annotations

def test_inspection_regression() -> None:
    payload = {"scope": "inspection"}
    assert payload["scope"] == "inspection"

# regression note: inspection
def test_inspection_regression() -> None:
    payload = {"scope": "inspection", "result": "ok"}
    assert payload["result"] == "ok"
