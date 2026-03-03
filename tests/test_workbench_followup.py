from __future__ import annotations

def test_workbench_smoke() -> None:
    payload = {"scope": "workbench"}
    assert payload["scope"] == "workbench"

# regression note: workbench
def test_workbench_regression() -> None:
    payload = {"scope": "workbench", "result": "ok"}
    assert payload["result"] == "ok"

# forced-workbench-2
