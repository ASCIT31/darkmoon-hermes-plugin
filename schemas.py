"""Tool schema for the darkmoon plugin."""

DARKMOON_FINDINGS = {
    "name": "darkmoon_findings",
    "description": (
        "Triage the findings file of a Darkmoon scan (open source autonomous AI pentest "
        "platform). Reads a findings JSON (array, or object with 'findings' or 'data') or a "
        "SARIF 2.1.0 file that the Darkmoon GitHub Action produced, filters it, and returns "
        "the findings most severe first, per-severity counts, the highest severity, a "
        "Markdown table, and a gate flag for a fail_on severity. Read-only: it never runs a "
        "scan and never contacts any service. Give exactly one of path or findings_json."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "path": {
                "type": "string",
                "description": "Path to a local .json or .sarif findings file (max 10 MB).",
            },
            "findings_json": {
                "type": "string",
                "description": "The findings document pasted inline, as a JSON or SARIF string.",
            },
            "min_severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
                "description": "Drop findings below this severity. Default info keeps all.",
            },
            "only_proven": {
                "type": "boolean",
                "description": (
                    "Keep only findings with status 'exploited' or 'confirmed' (JSON "
                    "findings only; SARIF carries no proof status). Default false."
                ),
            },
            "fail_on": {
                "type": "string",
                "enum": ["never", "low", "medium", "high", "critical"],
                "description": "gate_failed turns true when a kept finding reaches this severity. Default high.",
            },
        },
        "additionalProperties": False,
    },
}
