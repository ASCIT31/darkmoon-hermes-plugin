"""Handler for the darkmoon_findings tool: parse and triage a Darkmoon findings file."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

MAX_BYTES = 10 * 1024 * 1024
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
PROVEN_STATUSES = {"exploited", "confirmed"}
FAIL_LEVELS = ["never"] + SEVERITY_ORDER[1:]
_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


class FindingsError(ValueError):
    """The input is not a Darkmoon findings document."""


def _error(message: str) -> str:
    return json.dumps({"error": message}, ensure_ascii=False)


def _severity_from_score(score: Any) -> Optional[str]:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "critical"
    if value >= 7.0:
        return "high"
    if value >= 4.0:
        return "medium"
    return "low" if value > 0 else "info"


def _from_sarif(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten SARIF results into finding dicts (severity from security-severity, else level)."""
    findings: List[Dict[str, Any]] = []
    for run in doc.get("runs") or []:
        rules = {}
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            if isinstance(rule, dict) and rule.get("id"):
                rules[rule["id"]] = rule
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            rule = rules.get(result.get("ruleId"), {})
            score = (result.get("properties") or {}).get("security-severity")
            if score is None:
                score = (rule.get("properties") or {}).get("security-severity")
            severity = _severity_from_score(score) or _SARIF_LEVEL.get(
                str(result.get("level") or rule.get("defaultConfiguration", {}).get("level") or "warning"),
                "medium",
            )
            locations = result.get("locations") or [{}]
            uri = (((locations[0] or {}).get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri", "")
            finding: Dict[str, Any] = {
                "title": (rule.get("shortDescription") or {}).get("text")
                or (result.get("message") or {}).get("text")
                or str(result.get("ruleId") or ""),
                "severity": severity,
                "category": result.get("ruleId"),
                "endpoint": uri,
                "description": (result.get("message") or {}).get("text"),
            }
            try:
                finding["cvss_score"] = float(score)
            except (TypeError, ValueError):
                pass
            findings.append(finding)
    return findings


def parse_findings(raw: str) -> List[Dict[str, Any]]:
    """Accept SARIF, a bare JSON array, or an object holding 'findings' or 'data'."""
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsError(f"not valid JSON ({exc.msg} at line {exc.lineno})") from None
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        return _from_sarif(doc)
    if isinstance(doc, dict):
        inner = doc.get("findings") if doc.get("findings") is not None else doc.get("data")
        if inner is None:
            raise FindingsError("expected a findings array, an object with 'findings' or 'data', or SARIF")
        doc = inner
    if not isinstance(doc, list) or not all(isinstance(item, dict) for item in doc):
        raise FindingsError("findings must be a JSON array of objects")
    return doc


def _rank(finding: Dict[str, Any]) -> int:
    value = str(finding.get("severity") or "").strip().lower()
    return SEVERITY_ORDER.index(value) if value in SEVERITY_ORDER else -1


def _cell(value: Any) -> str:
    return " ".join(str(value if value is not None else "").split()).replace("|", "\\|")


def _markdown(findings: List[Dict[str, Any]], counts: Dict[str, int]) -> str:
    summary = ", ".join(f"{n} {level}" for level, n in counts.items() if n)
    lines = [f"## Darkmoon findings: {len(findings)} ({summary or 'none rated'})"]
    if findings:
        lines += ["", "| Severity | CVSS | Status | Title | Endpoint |", "|---|---|---|---|---|"]
        for f in findings:
            score = f.get("cvss_score")
            cvss = f"{score:.1f}" if isinstance(score, (int, float)) else ""
            row = [str(f.get("severity") or "unrated").upper(), cvss, f.get("status"),
                   f.get("title") or "(untitled)", f.get("endpoint")]
            lines.append("| " + " | ".join(_cell(v) for v in row) + " |")
    return "\n".join(lines)


def triage(findings: List[Dict[str, Any]], min_severity: str = "info",
           only_proven: bool = False, fail_on: str = "high") -> Dict[str, Any]:
    """Filter, sort and summarise findings. Unrated findings are kept as info and never trip the gate."""
    floor = SEVERITY_ORDER.index(min_severity)
    kept = []
    for f in findings:
        rank = _rank(f)
        if floor and rank < floor:  # unrated findings (rank -1) survive only at info
            continue
        if only_proven and str(f.get("status") or "").lower() not in PROVEN_STATUSES:
            continue
        kept.append(f)
    kept.sort(key=lambda f: -_rank(f))
    counts = {level: 0 for level in reversed(SEVERITY_ORDER)}
    for f in kept:
        if _rank(f) >= 0:
            counts[SEVERITY_ORDER[_rank(f)]] += 1
    top = max((_rank(f) for f in kept), default=-1)
    gate = fail_on != "never" and top >= SEVERITY_ORDER.index(fail_on)
    return {
        "total": len(kept),
        "severity_counts": counts,
        "highest_severity": SEVERITY_ORDER[top] if top >= 0 else "none",
        "gate_failed": bool(gate),
        "findings": kept,
        "markdown_report": _markdown(kept, counts),
    }


def _read(path: str) -> str:
    target = Path(path).expanduser()
    if target.suffix.lower() not in {".json", ".sarif"}:
        raise FindingsError("path must end in .json or .sarif")
    if not target.is_file():
        raise FindingsError(f"no such file: {path}")
    if target.stat().st_size > MAX_BYTES:
        raise FindingsError("file is larger than 10 MB")
    return target.read_text(encoding="utf-8")


def handle_darkmoon_findings(args: Dict[str, Any], **_kw) -> str:
    path, inline = args.get("path"), args.get("findings_json")
    if bool(path) == bool(inline):
        return _error("give exactly one of path or findings_json")
    min_severity = str(args.get("min_severity") or "info").lower()
    fail_on = str(args.get("fail_on") or "high").lower()
    if min_severity not in SEVERITY_ORDER:
        return _error(f"min_severity must be one of {SEVERITY_ORDER}")
    if fail_on not in FAIL_LEVELS:
        return _error(f"fail_on must be one of {FAIL_LEVELS}")
    try:
        raw = _read(path) if path else str(inline)
        if len(raw.encode("utf-8")) > MAX_BYTES:
            raise FindingsError("findings_json is larger than 10 MB")
        result = triage(parse_findings(raw), min_severity, bool(args.get("only_proven")), fail_on)
    except (FindingsError, OSError, UnicodeDecodeError) as exc:
        return _error(f"cannot read Darkmoon findings: {exc}")
    return json.dumps(result, ensure_ascii=False)
