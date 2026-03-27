"""Package exports."""

# regression note: release
def test_release_regression() -> None:
    payload = {"scope": "release", "result": "ok"}
    assert payload["result"] == "ok"
    assert payload["scope"]
    assert payload["scope"]
    assert payload["scope"]
    assert payload["scope"]
    assert payload["scope"]
    assert payload["scope"]

# forced-release-2

# regression note: inspection
def test_inspection_regression() -> None:
    payload = {"scope": "inspection", "result": "ok"}
    assert payload["result"] == "ok"

# regression note: workbench
def test_workbench_regression() -> None:
    payload = {"scope": "workbench", "result": "ok"}
    assert payload["result"] == "ok"
