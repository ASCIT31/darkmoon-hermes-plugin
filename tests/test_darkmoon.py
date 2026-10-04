import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"darkmoon_plugin.{name}", ROOT / f"{name}.py", submodule_search_locations=None)
    pkg = sys.modules.setdefault("darkmoon_plugin", type(sys)("darkmoon_plugin"))
    pkg.__path__ = [str(ROOT)]
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"darkmoon_plugin.{name}"] = module
    spec.loader.exec_module(module)
    return module


tools = _load("tools")
FINDINGS = [
    {"title": "Reflected XSS", "severity": "medium", "cvss_score": 6.1, "status": "confirmed", "endpoint": "https://t/x"},
    {"title": "SQL injection | login", "severity": "critical", "cvss_score": 9.8, "status": "exploited", "endpoint": "https://t/login"},
    {"title": "Banner", "severity": "info", "status": "unconfirmed"},
    {"title": "Odd", "severity": "bogus", "status": "unconfirmed"},
]


def call(**args):
    return json.loads(tools.handle_darkmoon_findings(args))


def test_array_sorted_and_counts():
    out = call(findings_json=json.dumps(FINDINGS))
    assert [f["title"] for f in out["findings"]][0] == "SQL injection | login"
    assert out["total"] == 4
    assert out["severity_counts"] == {"critical": 1, "high": 0, "medium": 1, "low": 0, "info": 1}
    assert out["highest_severity"] == "critical" and out["gate_failed"] is True
    assert "SQL injection \\| login" in out["markdown_report"]


def test_envelopes():
    assert call(findings_json=json.dumps({"findings": FINDINGS}))["total"] == 4
    assert call(findings_json=json.dumps({"data": FINDINGS}))["total"] == 4


def test_filters_and_gate():
    out = call(findings_json=json.dumps(FINDINGS), min_severity="high")
    assert [f["severity"] for f in out["findings"]] == ["critical"]
    out = call(findings_json=json.dumps(FINDINGS), only_proven=True)
    assert out["total"] == 2
    out = call(findings_json=json.dumps(FINDINGS), fail_on="never")
    assert out["gate_failed"] is False
    out = call(findings_json=json.dumps([FINDINGS[2], FINDINGS[3]]))
    assert out["gate_failed"] is False and out["highest_severity"] == "info"


def test_sarif():
    sarif = {"runs": [{"tool": {"driver": {"rules": [
        {"id": "sqli", "shortDescription": {"text": "SQL injection"}, "properties": {"security-severity": "9.8"}}]}},
        "results": [
            {"ruleId": "sqli", "message": {"text": "boom"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "/login"}}}]},
            {"ruleId": "other", "level": "note", "message": {"text": "meh"}}]}]}
    out = call(findings_json=json.dumps(sarif))
    assert out["findings"][0]["severity"] == "critical" and out["findings"][0]["endpoint"] == "/login"
    assert out["findings"][1]["severity"] == "low"


def test_path(tmp_path):
    p = tmp_path / "findings.json"
    p.write_text(json.dumps(FINDINGS))
    assert call(path=str(p))["total"] == 4
    assert "error" in call(path=str(tmp_path / "missing.json"))
    bad = tmp_path / "x.txt"
    bad.write_text("[]")
    assert "error" in call(path=str(bad))


def test_errors():
    assert "error" in call()
    assert "error" in call(path="a.json", findings_json="[]")
    assert "error" in call(findings_json="not json")
    assert "error" in call(findings_json='{"x": 1}')
    assert "error" in call(findings_json="[1]")
    assert "error" in call(findings_json="[]", min_severity="nope")
    assert call(findings_json="[]")["highest_severity"] == "none"
