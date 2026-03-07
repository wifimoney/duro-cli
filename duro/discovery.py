from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

EXCLUDE_DIRS = {"interfaces", "lib", "mocks", "test", "node_modules", "out", "cache"}


@dataclass
class FindingCandidate:
    finding_id: str
    title: str
    hypothesis: str
    contract_file: str
    function_hint: str
    impact: str
    preconditions: list[str]
    confidence: str
    source: str = "discovery"


def _is_excluded(path: Path) -> bool:
    parts = set(path.parts)
    if parts & EXCLUDE_DIRS:
        return True
    n = path.name
    if n.endswith('.t.sol') or 'Test' in n or 'Mock' in n:
        return True
    return False


def discover_solidity_files(root: str | Path = '.') -> list[Path]:
    root = Path(root)
    files = []
    for p in root.rglob('*.sol'):
        if _is_excluded(p):
            continue
        files.append(p)
    return sorted(files)


def _mk_candidates(files: Iterable[Path]) -> list[FindingCandidate]:
    out: list[FindingCandidate] = []
    i = 1
    for f in files:
        stem = f.stem
        out.append(
            FindingCandidate(
                finding_id=f"cand_{i:03d}",
                title=f"Review critical state transitions in {stem}",
                hypothesis="A privileged or external call path may allow unsafe state mutation or fund movement.",
                contract_file=str(f),
                function_hint="state-changing external/public functions",
                impact="high",
                preconditions=["attacker controls calldata", "insufficient auth or invariant checks"],
                confidence="medium",
            )
        )
        i += 1
    return out


def write_discovery_bundle(root: str | Path = '.', out_path: str | Path = '.duro/findings.discovery.json') -> dict:
    files = discover_solidity_files(root)
    findings = _mk_candidates(files)
    payload = {
        "version": 1,
        "root": str(Path(root).resolve()),
        "files_scanned": [str(p) for p in files],
        "findings": [f.__dict__ for f in findings],
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2))
    return payload


def synthesize_scenarios(
    findings_path: str | Path = '.duro/findings.discovery.json',
    out_dir: str | Path = 'scenarios/generated',
) -> list[str]:
    data = json.loads(Path(findings_path).read_text())
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for idx, f in enumerate(data.get('findings', []), start=1):
        sid = f"gen-{idx:03d}-{f.get('finding_id', f'cand_{idx:03d}') }"
        yml = f'''id: {sid}
chain: ethereum
rpc_env: MAINNET_RPC_URL
block: 19000000
target:
  protocol: GeneratedFromDiscovery
  contracts:
    - "0x0000000000000000000000000000000000000001"
class_type: generated_hypothesis
success_criteria:
  - type: call_succeeds
    label: exploit_path
invariants:
  - label: safety-gate
    type: safety_ok
steps:
  - type: call
    to: "0x0000000000000000000000000000000000000001"
    method: "TODO_method(bytes)"
    args:
      - "TODO"
notes:
  finding_id: {f.get('finding_id')}
  title: "{str(f.get('title', '')).replace('"', "'")}"
  hypothesis: "{str(f.get('hypothesis', '')).replace('"', "'")}"
  contract_file: "{str(f.get('contract_file', '')).replace('"', "'")}"
'''
        out_file = out_dir / f"{sid}.yaml"
        out_file.write_text(yml)
        written.append(str(out_file))

    return written
