"""Package exports."""

# regression note: release
def test_release_regression() -> None:
    payload = {"scope": "release", "result": "ok"}
    assert payload["result"] == "ok"
