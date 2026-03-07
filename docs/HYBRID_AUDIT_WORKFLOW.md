# DURO Hybrid Audit Workflow (Discovery → Repro → Gate)

This workflow combines:
1. **Discovery breadth** (Pashov-style skill/checklist approach)
2. **Deterministic exploit confirmation** (DURO runtime)

## Phases

### 0) Context ingestion
- Protocol docs and threat assumptions
- Deployment/fork context
- Privileged roles and trust boundaries

### 1) Discovery
- Run `duro discover` to create a structured discovery bundle
- Review and enrich candidate hypotheses

### 2) Scenario synthesis
- Run `duro synthesize` to convert candidates into runnable DURO scenarios
- Edit generated scenario placeholders (`TODO_method`, target contracts, block)

### 3) Repro execution
- `duro run <scenario>`
- Optional stability check: `duro rerun-check <scenario> --n 5 --min-majority-ratio 0.80`

### 4) Evidence fusion
Merge discovery confidence + reproducibility outcomes:
- discovery confidence
- DURO classification
- DURO confidence
- rerun consistency ratio

### 5) CI gate
Fail CI when:
- confirmed high/critical findings exist
- rerun consistency threshold is not met for critical paths

## New DURO commands in this workflow

```bash
duro discover . --out .duro/findings.discovery.json
duro synthesize --findings .duro/findings.discovery.json --out-dir scenarios/generated
duro audit --from .duro/findings.discovery.json --out-prefix .duro/fused-audit --llm-provider mock --max-runs 20
```

## Notes
- Discovery output is intentionally hypothesis-first.
- Generated scenarios are scaffolds and require analyst edits before final repro runs.
