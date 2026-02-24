#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED = json.loads((ROOT / "scenarios/fixtures/expected.json").read_text())
TEMPLATE_DIR = ROOT / "scenarios/templates"


def run(cmd):
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout)
        print(p.stderr)
        raise RuntimeError(f"command failed: {' '.join(cmd)}")
    return p.stdout.strip()


def main():
    failures = []

    for sc in sorted(TEMPLATE_DIR.glob("*.yaml")):
        # run command
        out = run(["duro", "run", str(sc), "--llm-provider", "mock"])
        # robust parse of run id from stdout variants
        run_id = None
        for line in out.splitlines():
            line = line.strip()
            if "Run completed:" in line:
                run_id = line.split("Run completed:")[-1].strip()
            elif line.startswith("RUN_ID="):
                run_id = line.split("=", 1)[1].strip()
        if not run_id:
            raise RuntimeError(f"unable to parse run id from output:\n{out}")
        result_path = ROOT / "runs" / run_id / "result.json"
        data = json.loads(result_path.read_text())
        got = data.get("classification")
        exp = EXPECTED.get(data.get("scenario_id"))
        if exp is not None and got != exp:
            failures.append((data.get("scenario_id"), exp, got, run_id))

    if failures:
        for f in failures:
            print(f"FAIL scenario={f[0]} expected={f[1]} got={f[2]} run_id={f[3]}")
        sys.exit(1)

    print("Replay check passed")


if __name__ == "__main__":
    main()
