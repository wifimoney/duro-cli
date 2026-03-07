import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

import yaml

from .llm import get_provider
from .models import Scenario

ROOT = Path(".")
RUNS = ROOT / "runs"
REPORTS = ROOT / "reports"
SCENARIOS = ROOT / "scenarios"

REASON_CODES = {
    "confirmed": "CRITERIA_PASS",
    "not_reproducible": "CRITERIA_FAIL",
    "inconclusive": "HARNESS_INCOMPLETE",
    "infra_failed": "INFRA_FAILURE",
}


def ensure_layout():
    for p in [RUNS, REPORTS, SCENARIOS, ROOT / "foundry" / "test", ROOT / ".duro"]:
        p.mkdir(parents=True, exist_ok=True)


def _run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def _hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


def _chain_id_from_rpc(rpc_url: str) -> int | None:
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_chainId",
            "params": [],
        }
        import urllib.request

        req = urllib.request.Request(
            rpc_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            body = json.loads(resp.read().decode("utf-8"))
        return int(body.get("result", "0x0"), 16)
    except Exception:
        return None


def doctor_checks(skip_rpc: bool = False) -> dict:
    ensure_layout()
    out = {}
    out["forge"] = shutil.which("forge") is not None
    out["anvil"] = shutil.which("anvil") is not None
    rpc = os.getenv("MAINNET_RPC_URL")
    out["rpc_env_set"] = bool(rpc)
    if skip_rpc:
        out["rpc_reachable"] = "skipped"
    else:
        out["rpc_reachable"] = bool(_chain_id_from_rpc(rpc)) if rpc else False
    out["writable_runs"] = os.access(RUNS, os.W_OK)
    out["writable_reports"] = os.access(REPORTS, os.W_OK)
    return out


def load_scenario(path: str) -> Scenario:
    data = yaml.safe_load(Path(path).read_text())
    return Scenario.model_validate(data)


def validate_step_safety(steps: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if len(steps) > 30:
        errors.append("Too many steps (>30)")

    for i, st in enumerate(steps, start=1):
        lbl = str(st.get("label", ""))
        target = str(st.get("target", ""))
        calldata = str(st.get("calldata", ""))
        value = str(st.get("value", "0"))

        if not lbl:
            errors.append(f"step[{i}] missing label")
        if not (target.startswith("0x") and len(target) == 42):
            errors.append(f"step[{i}] invalid target")
        if not (calldata.startswith("0x") and all(c in "0123456789abcdefABCDEF" for c in calldata[2:])):
            errors.append(f"step[{i}] invalid calldata hex")
        if any(tok in json.dumps(st).lower() for tok in ["subprocess", "os.system", "curl ", "rm -rf"]):
            errors.append(f"step[{i}] contains forbidden token")
        try:
            if int(value) > 10**22:
                errors.append(f"step[{i}] value too high")
        except Exception:
            errors.append(f"step[{i}] value is not integer-like")

    return (len(errors) == 0, errors)


def _confidence(classification: str, returncode: int, steps_count: int, retries: int = 1) -> tuple[float, dict]:
    base = {
        "confirmed": 0.85,
        "not_reproducible": 0.70,
        "inconclusive": 0.40,
        "infra_failed": 0.20,
    }.get(classification, 0.2)

    step_factor = min(0.1, steps_count * 0.01)
    retry_penalty = 0.05 * max(0, retries - 1)
    rc_penalty = 0.05 if returncode not in (0, 1) else 0.0

    score = max(0.0, min(1.0, base + step_factor - retry_penalty - rc_penalty))
    breakdown = {
        "base": base,
        "step_factor": step_factor,
        "retry_penalty": retry_penalty,
        "returncode_penalty": rc_penalty,
    }
    return score, breakdown


def create_harness(run_dir: Path, scenario: Scenario, steps: list[dict] | None = None) -> Path:
    test_dir = run_dir / "foundry" / "test"
    src_dir = run_dir / "foundry" / "src"
    test_dir.mkdir(parents=True, exist_ok=True)
    src_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "foundry" / "foundry.toml").write_text(
        """[profile.default]\nsrc = \"src\"\ntest = \"test\"\nsolc_version = \"0.8.20\"\n"""
    )

    def _s(x: str) -> str:
        return "".join(ch if ch.isalnum() else "_" for ch in x).upper()

    token_consts = []
    pre_reads = []
    for sym, addr in scenario.tokens.items():
        k = _s(sym)
        token_consts.append(f"address constant TOKEN_{k} = {addr};")
        pre_reads.append(f"uint256 pre_{k} = IERC20(TOKEN_{k}).balanceOf(ATTACKER);")

    criteria_lines = []
    required_success_labels = set()
    for c in scenario.success_criteria:
        ctype = c.get("type")
        if ctype == "balance_increase":
            sym = c["token"]
            k = _s(sym)
            min_amt = c["min_amount_wei"]
            criteria_lines.append(
                f'assertGe(IERC20(TOKEN_{k}).balanceOf(ATTACKER) - pre_{k}, {min_amt}, "balance_increase:{sym}");'
            )
        elif ctype == "call_succeeds":
            label = c.get("label", "exploit_path")
            k = _s(label)
            required_success_labels.add(k)
            criteria_lines.append(f'assertTrue(success_{k}, "call_succeeds:{label}");')

    if not criteria_lines:
        criteria_lines.append('revert("No success criteria");')

    provided_steps = steps or []
    declared_success = []
    exec_lines = []

    for lbl in sorted(required_success_labels):
        declared_success.append(f"bool success_{lbl} = false;")

    for i, st in enumerate(provided_steps, start=1):
        label = _s(str(st.get("label", f"step_{i}")))
        target = st.get("target", "0x0000000000000000000000000000000000000000")
        calldata = st.get("calldata", "0x")
        value = st.get("value", "0")
        expect_success = bool(st.get("expect_success", True))

        if f"bool success_{label} = false;" not in declared_success:
            declared_success.append(f"bool success_{label} = false;")

        exec_lines.append(
            f"(success_{label}, ) = address({target}).call{{value: {value}}}(hex\"{str(calldata).replace('0x','')}\");"
        )
        if expect_success:
            exec_lines.append(f'assertTrue(success_{label}, "step:{label}:expected_success");')

    if not exec_lines:
        exec_lines.append("// no exploit steps provided")

    test_file = test_dir / f"{scenario.id.replace('-', '_')}.t.sol"
    test_file.write_text(
        f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {{
    function balanceOf(address) external view returns (uint256);
}}

contract DuroScenarioTest {{
    address constant ATTACKER = {scenario.attacker.get("address", "0x000000000000000000000000000000000000BEEF")};
    {' '.join(token_consts)}

    function assertTrue(bool cond, string memory why) internal pure {{
        require(cond, why);
    }}

    function assertGe(uint256 a, uint256 b, string memory why) internal pure {{
        require(a >= b, why);
    }}

    function test_exploit_confirmation() public {{
        {' '.join(pre_reads) if pre_reads else '// no token pre-reads'}

        // Exploit sequence
        {' '.join(declared_success) if declared_success else '// no call_succeeds criteria'}
        {' '.join(exec_lines)}

        {' '.join(criteria_lines)}
    }}
}}
'''
    )
    return test_file


def classify(returncode: int, stdout: str, stderr: str):
    txt = (stdout + "\n" + stderr).lower()
    if returncode == 0:
        return "confirmed", "all criteria passed"
    if "no success criteria" in txt or "no exploit steps" in txt:
        return "inconclusive", "harness incomplete"
    if "revert" in txt or "assert" in txt:
        return "not_reproducible", "criteria or exploit path failed"
    return "infra_failed", "toolchain/runtime error"


def extract_trace_summary(stdout: str, stderr: str, max_lines: int = 40) -> list[str]:
    """Best-effort extraction of relevant forge trace/assert/revert lines."""
    lines = (stdout + "\n" + stderr).splitlines()
    needles = ("trace", "revert", "assert", "fail", "error", "panic")
    picked = [ln.strip() for ln in lines if any(n in ln.lower() for n in needles)]
    if not picked:
        return []
    return picked[:max_lines]


def diff_runs(run_a: str, run_b: str) -> dict[str, Any]:
    pa = RUNS / run_a / "result.json"
    pb = RUNS / run_b / "result.json"
    if not pa.exists():
        raise FileNotFoundError(f"run not found: {run_a}")
    if not pb.exists():
        raise FileNotFoundError(f"run not found: {run_b}")

    a = json.loads(pa.read_text())
    b = json.loads(pb.read_text())

    keys = ["classification", "reason_code", "returncode", "steps_count", "confidence", "scenario_id"]
    changes = {}
    for k in keys:
        if a.get(k) != b.get(k):
            changes[k] = {"from": a.get(k), "to": b.get(k)}

    # safety diff
    if a.get("safety") != b.get("safety"):
        changes["safety"] = {"from": a.get("safety"), "to": b.get("safety")}

    return {
        "run_a": run_a,
        "run_b": run_b,
        "changed": bool(changes),
        "changes": changes,
    }


def run_scenario(path: str, llm_provider: str = "mock", llm_model: str = "", fallback_provider: str = "") -> str:
    raw = yaml.safe_load(Path(path).read_text())
    scenario = Scenario.model_validate(raw)
    run_id = str(uuid.uuid4())[:8]
    run_dir = RUNS / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    start = int(time.time())

    step_list = raw.get("steps") or []
    llm_meta = {
        "provider": None,
        "model": None,
        "used": False,
        "error": None,
        "fallback_used": False,
        "latency_ms": None,
        "attempts": 0,
    }

    if not step_list:
        for idx, name in enumerate([llm_provider] + ([fallback_provider] if fallback_provider else []), start=1):
            t0 = time.time()
            llm_meta["attempts"] = idx
            try:
                provider = get_provider(name, llm_model)
                plan = provider.generate_exploit_steps(raw)
                step_list = plan.steps
                llm_meta.update(
                    {
                        "provider": provider.name,
                        "model": llm_model or None,
                        "used": True,
                        "error": None,
                        "fallback_used": idx > 1,
                        "latency_ms": int((time.time() - t0) * 1000),
                    }
                )
                (run_dir / "llm.raw.txt").write_text(plan.raw)
                break
            except Exception as e:
                llm_meta["error"] = str(e)

    safe_ok, safety_errors = validate_step_safety(step_list)
    (run_dir / "safety.json").write_text(json.dumps({"ok": safe_ok, "errors": safety_errors}, indent=2))

    if not safe_ok:
        code, stdout, stderr = 2, "", "safety policy blocked generated steps"
        classification, reason = "infra_failed", "safety policy blocked generated steps"
        test_file = run_dir / "foundry" / "test" / "blocked.t.sol"
        test_file.parent.mkdir(parents=True, exist_ok=True)
        test_file.write_text("// blocked by safety policy\n")
    else:
        test_file = create_harness(run_dir, scenario, steps=step_list)
        code, stdout, stderr = (
            _run(["forge", "test", "-vv"], cwd=run_dir / "foundry") if shutil.which("forge") else (127, "", "forge not found")
        )
        classification, reason = classify(code, stdout, stderr)

    (run_dir / "forge.stdout.log").write_text(stdout)
    (run_dir / "forge.stderr.log").write_text(stderr)
    trace_summary = extract_trace_summary(stdout, stderr)
    (run_dir / "trace.summary.log").write_text("\n".join(trace_summary) + ("\n" if trace_summary else ""))

    confidence, breakdown = _confidence(classification, code, len(step_list), llm_meta.get("attempts", 1))

    result = {
        "run_id": run_id,
        "scenario_id": scenario.id,
        "classification": classification,
        "reason": reason,
        "reason_code": REASON_CODES.get(classification, "UNKNOWN"),
        "returncode": code,
        "started_at": start,
        "ended_at": int(time.time()),
        "steps_count": len(step_list),
        "llm": llm_meta,
        "safety": {"ok": safe_ok, "errors": safety_errors},
        "confidence": confidence,
        "confidence_breakdown": breakdown,
        "trace_summary": trace_summary,
        "artifacts": {
            "harness": str(test_file),
            "stdout": str(run_dir / "forge.stdout.log"),
            "stderr": str(run_dir / "forge.stderr.log"),
            "trace_summary": str(run_dir / "trace.summary.log"),
            "llm_raw": str(run_dir / "llm.raw.txt") if (run_dir / "llm.raw.txt").exists() else None,
            "safety": str(run_dir / "safety.json"),
        },
    }
    (run_dir / "result.json").write_text(json.dumps(result, indent=2))

    manifest = run_dir / "manifest.sha256"
    lines = []
    files = [
        run_dir / "result.json",
        run_dir / "forge.stdout.log",
        run_dir / "forge.stderr.log",
        run_dir / "trace.summary.log",
        run_dir / "safety.json",
    ]
    if test_file.exists():
        files.append(test_file)
    if (run_dir / "llm.raw.txt").exists():
        files.append(run_dir / "llm.raw.txt")

    for p in files:
        rel = p.relative_to(run_dir)
        lines.append(f"{_hash_file(p)}  {rel.as_posix()}")
    manifest.write_text("\n".join(lines) + "\n")

    return run_id


def export_report(run_id: str):
    run_dir = RUNS / run_id
    report_dir = REPORTS / run_id
    report_dir.mkdir(parents=True, exist_ok=True)
    data = json.loads((run_dir / "result.json").read_text())

    md = f"""# DURO Report {run_id}

- Classification: **{data['classification']}**
- Confidence: **{data.get('confidence', 0):.2f}**
- Reason: {data['reason']} ({data.get('reason_code','')})
- Return code: `{data['returncode']}`
- Steps: `{data.get('steps_count', 0)}`
- LLM: `{data.get('llm',{}).get('provider')}` fallback=`{data.get('llm',{}).get('fallback_used')}` latency_ms=`{data.get('llm',{}).get('latency_ms')}`

## Safety
- OK: `{data.get('safety',{}).get('ok')}`
- Errors: `{data.get('safety',{}).get('errors')}`

## Trace Summary (excerpt)
```
{chr(10).join((data.get('trace_summary') or [])[:12])}
```

## Artifacts
- Harness: `{data['artifacts']['harness']}`
- Stdout: `{data['artifacts']['stdout']}`
- Stderr: `{data['artifacts']['stderr']}`
- Trace summary: `{data['artifacts'].get('trace_summary')}`
- Safety: `{data['artifacts'].get('safety')}`
"""
    (report_dir / "summary.md").write_text(md)
    (report_dir / "summary.json").write_text(json.dumps(data, indent=2))


def verify_run(run_id: str) -> bool:
    run_dir = RUNS / run_id
    manifest = run_dir / "manifest.sha256"
    if not manifest.exists():
        return False
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        expected, rel = line.split("  ", 1)
        p = run_dir / rel
        if not p.exists() or _hash_file(p) != expected:
            return False
    return True
