from duro.emit import emit_json_contract
import json
from pathlib import Path

import typer

from .llm import get_provider

from . import __version__
from .core import (
    diff_runs,
    doctor_checks,
    ensure_layout,
    export_report,
    run_scenario,
    verify_run,
)
from .ui import err, ok, section, show_banner, warn

app = typer.Typer(help="DURO CLI — check if a smart-contract issue is actually exploitable")
scenario_app = typer.Typer(help="Validate and inspect scenario files")
report_app = typer.Typer(help="Export human-readable and JSON reports")
llm_app = typer.Typer(help="LLM provider checks and stats")

app.add_typer(scenario_app, name="scenario")
app.add_typer(report_app, name="report")
app.add_typer(llm_app, name="llm")


@app.callback()
def main(
    ctx: typer.Context,
    no_banner: bool = typer.Option(False, "--no-banner", help="Disable ASCII banner"),
):
    if ctx.invoked_subcommand not in [None] and not no_banner:
        show_banner()


@app.command()
def version():
    print(__version__)


@app.command()
def init():
    ensure_layout()
    ok("Initialized workspace layout")


@app.command()
def doctor(
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
    skip_rpc: bool = typer.Option(False, "--skip-rpc", help="Skip RPC connectivity check"),
):
    ensure_layout()
    checks = doctor_checks(skip_rpc=skip_rpc)
    if json_out:
        print(json.dumps(checks, indent=2))
        healthy = all(v is True or v == "skipped" for v in checks.values())
        raise typer.Exit(code=0 if healthy else 1)

    section("DURO DOCTOR")
    for k, v in checks.items():
        if v:
            ok(f"{k}: healthy")
        else:
            err(f"{k}: failed")

    healthy = all(v is True or v == "skipped" for v in checks.values())
    if healthy:
        ok("Status: HEALTHY")
        raise typer.Exit(code=0)
    else:
        warn("Status: ISSUES FOUND")
        raise typer.Exit(code=1)


@scenario_app.command("lint")
def scenario_lint(path: str):
    from .core import load_scenario

    try:
        load_scenario(path)
        ok(f"Scenario valid: {path}")
    except Exception as e:
        err(f"Scenario invalid: {e}")
        raise typer.Exit(code=1)


@app.command("run")
def run_cmd(
    path: str,
    llm_provider: str = typer.Option("mock", "--llm-provider", help="mock|openai|gemini|ollama|anthropic|openrouter|lmstudio"),
    llm_model: str = typer.Option("", "--llm-model", help="Provider model name"),
    llm_fallback: str = typer.Option("", "--llm-fallback", help="Fallback provider"),
):
    run_id = run_scenario(path, llm_provider=llm_provider, llm_model=llm_model, fallback_provider=llm_fallback)
    ok(f"Run completed: {run_id}")
    print(f"Next: duro report export {run_id}")


@app.command()
def show(run_id: str):
    p = Path("runs") / run_id / "result.json"
    if not p.exists():
        err(f"Run not found: {run_id}")
        raise typer.Exit(code=1)
    print(p.read_text())


@report_app.command("export")
def report_export(run_id: str):
    export_report(run_id)
    ok(f"Report exported: reports/{run_id}")


@app.command("diff")
def diff_cmd(run_a: str, run_b: str, json_out: bool = typer.Option(False, "--json", help="JSON output")):
    try:
        out = diff_runs(run_a, run_b)
    except FileNotFoundError as e:
        err(str(e))
        raise typer.Exit(code=1)

    if json_out:
        print(json.dumps(out, indent=2))
        return

    if not out["changed"]:
        ok(f"No material changes between {run_a} and {run_b}")
        return

    section(f"DURO DIFF {run_a} -> {run_b}")
    for k, v in out["changes"].items():
        print(f"- {k}: {v['from']} -> {v['to']}")


@app.command()
def verify(run_id: str = typer.Argument("", help="Run id to verify"), all: bool = typer.Option(False, "--all", help="Verify all runs")):
    if all:
        run_dirs = sorted(Path("runs").glob("*/manifest.sha256"))
        if not run_dirs:
            warn("No runs found to verify")
            return
        failed = 0
        for m in run_dirs:
            rid = m.parent.name
            if verify_run(rid):
                ok(f"{rid}: verified")
            else:
                failed += 1
                err(f"{rid}: verification failed")
        if failed:
            raise typer.Exit(code=1)
        return

    if not run_id:
        err("Provide <run_id> or use --all")
        raise typer.Exit(code=2)

    if verify_run(run_id):
        ok("Artifact integrity verified")
    else:
        err("Artifact verification failed")
        raise typer.Exit(code=1)


@app.command()
def ls():
    runs = sorted(Path("runs").glob("*/result.json"), reverse=True)
    if not runs:
        warn("No runs found")
        return
    for r in runs[:20]:
        data = json.loads(r.read_text())
        print(f"{data['run_id']}  {data['classification']}  scenario={data['scenario_id']}")


@app.command()
def guard(run_id: str, out: str = "foundry/test/regression"):
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    f = out_dir / f"Regression_{run_id}.t.sol"
    f.write_text(
        """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import \"forge-std/Test.sol\";
contract RegressionTest is Test {
    function test_regression_placeholder() public { assertTrue(true); }
}
"""
    )
    ok(f"Guard test generated: {f}")


@llm_app.command("list-providers")
def llm_list_providers():
    print("mock\nopenai\ngemini\nollama\nanthropic\nopenrouter\nlmstudio (stub)")


@llm_app.command("stats")
def llm_stats(limit: int = typer.Option(50, "--limit", help="Max runs to scan")):
    runs = sorted(Path("runs").glob("*/result.json"), reverse=True)[:limit]
    agg = {}
    for r in runs:
        try:
            data = json.loads(r.read_text())
            llm = data.get("llm", {})
            name = llm.get("provider") or "none"
            a = agg.setdefault(name, {"count": 0, "fallbacks": 0, "latencies": []})
            a["count"] += 1
            if llm.get("fallback_used"):
                a["fallbacks"] += 1
            if isinstance(llm.get("latency_ms"), int):
                a["latencies"].append(llm["latency_ms"])
        except Exception:
            continue

    if not agg:
        warn("No telemetry found")
        return

    for k, v in agg.items():
        lat = int(sum(v["latencies"]) / len(v["latencies"])) if v["latencies"] else None
        print(f"{k}: runs={v['count']} fallbacks={v['fallbacks']} avg_latency_ms={lat}")


@llm_app.command("test")
def llm_test(
    provider: str = typer.Option("mock", "--provider", help="Provider name"),
    model: str = typer.Option("", "--model", help="Model name"),
    fallback: str = typer.Option("", "--fallback", help="Fallback provider if primary fails"),
    json_out: bool = typer.Option(False, "--json", help="JSON output"),
):
    """Validate provider wiring/credentials; optional fallback chain and JSON output."""
    import time

    sample = {
        "id": "llm-test",
        "chain": "ethereum",
        "rpc_env": "MAINNET_RPC_URL",
        "block": 1,
        "target": {"protocol": "Test", "contracts": ["0x0000000000000000000000000000000000000001"]},
        "success_criteria": [{"type": "call_succeeds", "label": "exploit_path"}],
    }

    providers = [provider] + ([fallback] if fallback else [])
    last_error = None

    for idx, name in enumerate(providers, start=1):
        t0 = time.time()
        try:
            p = get_provider(name, model)
            plan = p.generate_exploit_steps(sample, context="Provider connectivity test")
            elapsed_ms = int((time.time() - t0) * 1000)
            payload = {
                "ok": True,
                "provider": p.name,
                "attempt": idx,
                "fallback_used": idx > 1,
                "model": model or None,
                "latency_ms": elapsed_ms,
                "steps": len(plan.steps),
                "first_step": plan.steps[0] if plan.steps else None,
                "tokens": None,
            }
            if json_out:
                print(json.dumps(payload, indent=2))
            else:
                ok(f"Provider OK: {p.name} (latency={elapsed_ms}ms, steps={len(plan.steps)})")
                if idx > 1:
                    warn(f"Fallback engaged: primary '{provider}' failed, used '{p.name}'")
                if plan.steps:
                    print(json.dumps(plan.steps[0], indent=2))
            return
        except Exception as e:
            last_error = str(e)
            if not json_out:
                warn(f"Provider '{name}' failed: {e}")

    fail_payload = {
        "ok": False,
        "provider": provider,
        "fallback": fallback or None,
        "error": last_error,
    }
    if json_out:
        print(json.dumps(fail_payload, indent=2))
    else:
        err(f"Provider test failed: {last_error}")
    raise typer.Exit(code=1)
