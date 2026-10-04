# darkmoon: Hermes plugin for Darkmoon scan findings

[Darkmoon](https://github.com/ASCIT31/Dark-Moon) is an open source (GPL-3.0) autonomous AI penetration testing platform. Its engine and CLI are open source, and a scan produces a findings file (JSON, or SARIF through the [Darkmoon GitHub Action](https://github.com/ASCIT31/darkmoon-action)). This plugin gives a Hermes agent one tool to read that file and triage it.

The web dashboard and the remediation to pull request agent of Darkmoon are Pro features. This plugin does not use them and does not talk to any Darkmoon service.

## Tool

`darkmoon_findings` reads a findings document and returns:

| Field | Meaning |
|---|---|
| `findings` | kept findings, most severe first, all original fields preserved |
| `total` | number of kept findings |
| `severity_counts` | kept findings per severity |
| `highest_severity` | most severe rating kept, or `none` |
| `gate_failed` | true when a kept finding reaches `fail_on` |
| `markdown_report` | severity-sorted Markdown table, ready for a chat or a ticket |

Arguments: exactly one of `path` (local `.json` or `.sarif`, max 10 MB) or `findings_json` (inline string); `min_severity` (default `info`); `only_proven` (keep `exploited` and `confirmed` JSON findings); `fail_on` (`never`, `low`, `medium`, `high`, `critical`; default `high`).

Accepted input: a JSON array of findings, an object with a `findings` or `data` array, or SARIF 2.1.0 (severity comes from `security-severity` when present, otherwise from the SARIF `level`). Findings with no recognised severity are kept at `info` and never trip the gate.

## Disclosure

- Read-only. It never runs a scan, never starts a process, never opens a network connection and needs no credentials or environment variables.
- It reads only the single file path you give it, and only if it ends in `.json` or `.sarif`.
- Standard library only, no Python dependencies.

## Install

```bash
hermes plugins install darkmoon
```

## Example

Run a scan with the Darkmoon CLI or GitHub Action, then ask the agent: "Triage `findings.json`, only proven findings, and tell me whether the release should be blocked on high severity." The agent calls `darkmoon_findings` with `path: findings.json`, `only_proven: true`, `fail_on: high`.

## Develop

```bash
python3 -m pytest tests
hermes plugins validate .
```

License: GPL-3.0-only.
