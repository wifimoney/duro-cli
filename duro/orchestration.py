from __future__ import annotations

import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discovery import discover_solidity_files

VECTOR_DIR = Path("duro/references/attack-vectors")
AGENTS_DIR = Path("duro/references/agents")


@dataclass
class VectorFinding:
    root_cause: str
    title: str
    confidence: float
    severity: str
    file: str
    evidence: str
    vector: str


def check_rulepack_version(local_version_path: str = "duro/references/VERSION") -> dict[str, Any]:
    local = Path(local_version_path).read_text().strip() if Path(local_version_path).exists() else "0.0.0"
    remote = None
    warning = None
    try:
        url = "https://raw.githubusercontent.com/0xdefence/duro-cli/main/duro/references/VERSION"
        with urllib.request.urlopen(url, timeout=5) as r:
            remote = r.read().decode("utf-8").strip()
        if remote and remote != local:
            warning = f"rulepack update available: local={local} remote={remote}"
    except Exception:
        pass
    return {"local": local, "remote": remote, "warning": warning}


def _load_vector_prompts() -> list[tuple[str, str]]:
    out = []
    for p in sorted(VECTOR_DIR.glob("attack-vectors-*.md")):
        out.append((p.stem, p.read_text()))
    return out


def _bundle_for_agent(sol_files: list[Path], vector_name: str, vector_prompt: str) -> str:
    chunks = [f"# Agent Bundle: {vector_name}", "## Vector prompt", vector_prompt, "## Solidity files"]
    for sf in sol_files:
        chunks.append(f"\n### {sf}\n```solidity\n{sf.read_text()}\n```")
    return "\n".join(chunks)


def _scan_bundle(bundle: str, vector_name: str) -> list[VectorFinding]:
    findings: list[VectorFinding] = []
    file_matches = re.findall(r"^### (.+\.sol)$", bundle, flags=re.MULTILINE)
    code = bundle.lower()

    def add(rc: str, title: str, conf: float, sev: str, evidence: str):
        findings.append(
            VectorFinding(
                root_cause=rc,
                title=title,
                confidence=conf,
                severity=sev,
                file=file_matches[0] if file_matches else "unknown.sol",
                evidence=evidence,
                vector=vector_name,
            )
        )

    if "delegatecall" in code:
        add("delegatecall_untrusted", "Untrusted delegatecall pathway", 0.86, "high", "delegatecall keyword detected")
    if "tx.origin" in code:
        add("tx_origin_auth", "tx.origin-based auth risk", 0.84, "high", "tx.origin usage detected")
    if "selfdestruct" in code:
        add("selfdestruct_surface", "selfdestruct usage risk", 0.72, "medium", "selfdestruct usage detected")
    if "unchecked" in code:
        add("unchecked_math", "Unchecked arithmetic path", 0.62, "medium", "unchecked block detected")
    if "assembly" in code:
        add("inline_assembly_review", "Inline assembly requires manual review", 0.55, "low", "assembly keyword detected")

    return findings


def _dedupe_findings(findings: list[VectorFinding]) -> list[VectorFinding]:
    by_root: dict[str, VectorFinding] = {}
    for f in findings:
        cur = by_root.get(f.root_cause)
        if cur is None or f.confidence > cur.confidence:
            by_root[f.root_cause] = f
    return sorted(by_root.values(), key=lambda x: x.confidence, reverse=True)


def run_parallel_vector_scan(root: str = ".", mode: str = "fast") -> dict[str, Any]:
    sol_files = discover_solidity_files(root)
    vectors = _load_vector_prompts()
    if not vectors:
        return {"files": [], "findings": [], "mode": mode}

    bundles = [(name, _bundle_for_agent(sol_files, name, prompt)) for name, prompt in vectors]

    findings: list[VectorFinding] = []
    with ThreadPoolExecutor(max_workers=min(8, len(bundles))) as ex:
        futs = [ex.submit(_scan_bundle, b, n) for n, b in bundles]
        for f in futs:
            findings.extend(f.result())

    if mode in ("deep", "deep+adversarial"):
        # lightweight adversarial pass
        extra = []
        for sf in sol_files:
            txt = sf.read_text().lower()
            if "onlyowner" in txt and "upgrade" in txt:
                extra.append(
                    VectorFinding(
                        root_cause="privileged_upgrade_surface",
                        title="Privileged upgrade path review required",
                        confidence=0.68,
                        severity="medium",
                        file=str(sf),
                        evidence="onlyOwner + upgrade keyword pattern",
                        vector="adversarial",
                    )
                )
        findings.extend(extra)

    merged = _dedupe_findings(findings)
    return {
        "mode": mode,
        "files": [str(p) for p in sol_files],
        "findings": [f.__dict__ for f in merged],
        "raw_findings": [f.__dict__ for f in findings],
    }


def write_audit_report(payload: dict[str, Any], out_path: str | Path, confidence_threshold: float = 0.6) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    findings = payload.get("findings", [])
    hi = [f for f in findings if float(f.get("confidence", 0)) >= confidence_threshold]
    lo = [f for f in findings if float(f.get("confidence", 0)) < confidence_threshold]

    md = [
        "# DURO Audit Report",
        f"Mode: {payload.get('mode')}",
        f"Files scanned: {len(payload.get('files', []))}",
        "",
        "## Findings (above confidence threshold)",
    ]

    for i, f in enumerate(hi, start=1):
        md.append(f"{i}. [{f['severity'].upper()}] {f['title']} ({f['confidence']:.2f})")
        md.append(f"   - Root cause: `{f['root_cause']}`")
        md.append(f"   - File: `{f['file']}`")
        md.append(f"   - Evidence: {f['evidence']}")

    md.append("\n---\n")
    md.append("## Below Confidence Threshold")
    for i, f in enumerate(lo, start=1):
        md.append(f"{i}. [{f['severity'].upper()}] {f['title']} ({f['confidence']:.2f})")

    out_path.write_text("\n".join(md) + "\n")
    return out_path


def write_audit_json(payload: dict[str, Any], out_path: str | Path) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    return out_path
