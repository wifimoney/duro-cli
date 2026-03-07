```text
████▄  ██  ██ █████▄  ▄████▄
██  ██ ██  ██ ██▄▄██▄ ██  ██
████▀  ▀████▀ ██   ██ ▀████▀
```

# DURO CLI

**DURO tells you if a smart-contract issue is actually exploitable — not just “maybe vulnerable.”**

If you run audits, bug bounties, or protocol security, DURO helps you move from:
- vague finding ➜ to
- reproducible proof on forked state.

---

## In plain English

Most tools say: **"this might be risky."**

DURO says one of four things after simulation:
- ✅ **CONFIRMED** (exploit worked)
- ❌ **NOT_REPRODUCIBLE** (didn’t work)
- ⚠️ **INCONCLUSIVE** (not enough signal)
- 🛠️ **INFRA_FAILED** (environment issue)

That makes triage faster and reporting cleaner.

---

## Who this is for

- Smart contract auditors
- DeFi security engineers
- Bug bounty / offensive security teams
- Protocol teams validating real exploitability

## Who this is not for

- Non-technical users looking for a one-click scanner
- Unauthorized target testing

---

## 30-second demo

```bash
duro init
duro run scenarios/templates/access-control.yaml --llm-provider mock
duro show <RUN_ID>
```

You can also run the scripted demo:

```bash
bash scripts/demo_30s.sh
```

Optional: add an asciinema/GIF at `docs/assets/duro-30s-demo.gif` and embed:

```md
![DURO 30s demo](docs/assets/duro-30s-demo.gif)
```

## 60-second quickstart

```bash
duro init
duro doctor
duro scenario lint scenarios/oracle-manipulation-demo.yaml
duro run scenarios/oracle-manipulation-demo.yaml --llm-provider mock
duro report export <RUN_ID>
```

---

## What you get per run

Artifacts under `runs/<run_id>/` and `reports/<run_id>/`:
- `result.json`
- `forge.stdout.log`
- `forge.stderr.log`
- `trace.summary.log`
- generated harness (`.t.sol`)
- `safety.json`
- `trace.summary.log`
- `summary.md` / `summary.json`
- `manifest.sha256` (integrity)

---

## Core commands

```bash
duro init
duro doctor [--skip-rpc] [--json]
duro discover . --out .duro/findings.discovery.json
duro synthesize --findings .duro/findings.discovery.json --out-dir scenarios/generated
duro run <scenario.yaml> [--llm-provider ... --llm-model ... --llm-fallback ...]
duro rerun-check <scenario.yaml> --n 3 [--llm-provider ...]
duro rerun-check <scenario.yaml> --n 5 --min-majority-ratio 0.80
duro show <run_id>
duro report export <run_id>
duro verify <run_id>
duro verify --all
duro diff <run_a> <run_b>
duro guard <run_id>
duro ls

duro llm list-providers
duro llm test --provider <name> [--model ...] [--fallback ...] [--json]
duro llm stats
```

---

## LLM provider support

Implemented:
- mock
- openai
- gemini
- ollama
- anthropic
- openrouter

Env vars:
- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `OPENROUTER_API_KEY`
- `OPENROUTER_SITE_URL` (optional)
- `OPENROUTER_APP_NAME` (optional)
- `OLLAMA_HOST` (default `http://127.0.0.1:11434`)
- `GEMINI_API_KEY` or `GOOGLE_API_KEY`

---

## Scenario templates included (6 classes)

In `scenarios/templates/`:
1. access-control
2. oracle-manipulation
3. read-only-reentrancy
4. signature-approval
5. upgradeable-proxy
6. governance-attack

---

## Production hardening already included

- Safety policy gate for generated steps
- Confidence scoring v2 (classification + safety + invariant pass ratio + historical consistency)
- Reason-code classification
- Provider fallback + telemetry
- Integrity manifest + verification
- Trace summary artifact extraction (`trace.summary.log`)
- Invariant evaluation scaffold (`invariants` in scenario)
- CI replay workflows:
  - `replay-smoke` (no RPC dependency)
  - `replay-public-rpc` (uses `MAINNET_RPC_URL` secret)

---

## Install

### Prerequisites
- Python 3.11+
- Foundry (`forge`, `anvil`)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

```bash
git clone https://github.com/0xdefence/duro-cli.git
cd duro-cli
pip install -e .
```

---

## Security notice

Authorized testing only. Don’t use DURO on systems/contracts without explicit permission.

---

## Project docs

- Hybrid workflow: `docs/HYBRID_AUDIT_WORKFLOW.md`
- Discovery schema: `docs/findings.discovery.schema.json`
- Roadmap: `docs/DURO_RELEASE_PLAN.md`
- Issue backlog: `docs/GITHUB_ISSUES_P0_P1.md`
- Board: `docs/PROJECT_BOARD.md`
- Release notes: `docs/RELEASE_NOTES_v0.1.0-alpha.md`
- Changelog: `CHANGELOG.md`

---

## License

MIT
