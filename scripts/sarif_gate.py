#!/usr/bin/env python3
"""
sarif_gate.py — merge SARIF reports from several scanners into one summary
and decide whether the build should fail.

Each tool expresses severity differently, so findings are normalised to
critical / high / medium / low:

  1. A numeric `security-severity` on the rule (Trivy, CodeQL) wins:
       >= 9.0 critical, >= 7.0 high, >= 4.0 medium, else low
  2. Otherwise the SARIF level from the result or the rule default:
       error -> high, warning -> medium, note/none -> low
  3. Secret-detection tools are always treated as high: a leaked credential
     is urgent regardless of what the tool labels it.

Usage:
  sarif_gate.py reports/*.sarif --fail-on high [--enforce] [--summary FILE]

Exit code is 1 only when --enforce is set and at least one finding is at or
above the --fail-on severity. Without --enforce the gate is report-only.
Standard library only, so it runs on any runner without installing anything.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

LEVELS = ["critical", "high", "medium", "low"]
RANK = {name: i for i, name in enumerate(LEVELS)}  # lower = more severe
SARIF_LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
SECRET_TOOLS = ("gitleaks", "trufflehog")


def score_to_level(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def classify(result: dict, rule: dict, tool: str) -> str:
    if any(s in tool.lower() for s in SECRET_TOOLS):
        return "high"
    props = rule.get("properties", {}) or {}
    sev = props.get("security-severity")
    if sev is not None:
        try:
            return score_to_level(float(sev))
        except (TypeError, ValueError):
            pass
    level = (
        result.get("level")
        or (rule.get("defaultConfiguration") or {}).get("level")
        or "warning"  # SARIF spec default
    )
    return SARIF_LEVEL_MAP.get(level, "medium")


def location(result: dict) -> str:
    try:
        phys = result["locations"][0]["physicalLocation"]
        uri = phys["artifactLocation"]["uri"]
        line = phys.get("region", {}).get("startLine")
        return f"{uri}:{line}" if line else uri
    except (KeyError, IndexError):
        return "-"


def load_findings(paths):
    findings = []
    for path in paths:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)
            continue
        for run in data.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool = driver.get("name", Path(path).stem)
            rules = {r.get("id"): r for r in driver.get("rules", [])}
            for res in run.get("results", []):
                rule = rules.get(res.get("ruleId"), {})
                findings.append(
                    {
                        "tool": tool,
                        "rule": res.get("ruleId", "?"),
                        "severity": classify(res, rule, tool),
                        "where": location(res),
                        "message": (res.get("message", {}).get("text") or "").splitlines()[0][:140],
                    }
                )
    return findings


def render(findings, fail_on, enforce):
    by_tool = defaultdict(Counter)
    for f in findings:
        by_tool[f["tool"]][f["severity"]] += 1
    blocking = [f for f in findings if RANK[f["severity"]] <= RANK[fail_on]]

    out = ["## Security scan summary", ""]
    mode = "**enforcing**" if enforce else "**report-only**"
    out.append(f"Gate: fail on `{fail_on}` or worse — mode {mode}.")
    out.append("")
    out.append("| Tool | Critical | High | Medium | Low | Total |")
    out.append("|---|---:|---:|---:|---:|---:|")
    for tool in sorted(by_tool):
        c = by_tool[tool]
        out.append(
            f"| {tool} | {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {sum(c.values())} |"
        )
    total = Counter(f["severity"] for f in findings)
    out.append(
        f"| **All** | **{total['critical']}** | **{total['high']}** | **{total['medium']}** "
        f"| **{total['low']}** | **{len(findings)}** |"
    )
    out.append("")
    if blocking:
        verdict = "FAIL" if enforce else "WOULD FAIL"
        out.append(f"### {verdict}: {len(blocking)} finding(s) at `{fail_on}` or above")
        out.append("")
        out.append("| Severity | Tool | Rule | Location |")
        out.append("|---|---|---|---|")
        blocking.sort(key=lambda f: (RANK[f["severity"]], f["tool"], f["where"]))
        for f in blocking[:25]:
            out.append(f"| {f['severity']} | {f['tool']} | `{f['rule']}` | `{f['where']}` |")
        if len(blocking) > 25:
            out.append(f"| … | | {len(blocking) - 25} more | |")
    else:
        out.append(f"### PASS: nothing at `{fail_on}` or above")
    out.append("")
    out.append("Full details: repository **Security → Code scanning** tab.")
    return "\n".join(out), blocking


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sarif", nargs="+", help="SARIF files to evaluate")
    ap.add_argument("--fail-on", choices=LEVELS, default="high")
    ap.add_argument("--enforce", action="store_true", help="exit 1 when blocking findings exist")
    ap.add_argument("--summary", help="append markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()

    findings = load_findings(args.sarif)
    report, blocking = render(findings, args.fail_on, args.enforce)
    print(report)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")
    return 1 if (args.enforce and blocking) else 0


if __name__ == "__main__":
    sys.exit(main())
