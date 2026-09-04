# CONTINUITY artifact evaluation guide

## Scope

The artifact evaluates a deterministic security boundary after an agent planner has proposed an action. The planner is modeled as adversarial. The artifact does not query an LLM and therefore does not estimate natural-language attack frequency, semantic reasoning quality, or model-level refusal rates.

## Claims backed by the artifact

1. **Authenticated chain origins.** The full verifier rejects untrusted ingress keys, self-issued roots, excessive origin authority/scope, invalid root field predicates, and revoked or expired grants.
2. **Role-bound composition.** A transition is accepted only when stage, role, signer, contract, predecessor, receipt signer, and output producer match deployment policy.
3. **Leaf-level source binding.** JSON Pointer paths resolve actual nested action values; signed provenance claims bind each path to a source and exact value digest.
4. **Bounded typed release.** External values are admitted only by a trusted, signed, unexpired credential bound to source, manifest, field, exact value, predicate, principal, actor, task, operation, and tool.
5. **Validated semantic change.** Every normal trace resolves a logical destination alias. The change requires a trusted witness, and the verifier independently evaluates the configured alias relation; correctness of the trusted directory mapping remains part of the TCB. A bare `may_transform` declaration is insufficient.
6. **End-to-end effect containment.** The full configuration commits no harmful effect in 2,560 parameterized attacks from 32 faults, four domains, and 128 fault-domain classes.
7. **Structured utility.** It commits all 700 benign tasks, including 300 typed-release tasks, and escalates all 200 unreleased ambiguous tasks.
8. **Lifecycle finality.** The sink checks subject, exact action, current policy, revocation, expiry, nonce, and idempotency immediately before effect.
9. **Targeted mechanism evidence.** The ablation suite records the fault-domain classes reopened by removing each selected invariant.
10. **Prototype overhead.** Recorded latency and proof-size results are in `results/performance.csv` and `results/scaling.csv`; timing is machine-dependent.

These are conformance claims for a generated fault space, not population-level security estimates.

## Recorded environment

- Linux 6.18.35, x86-64
- AMD EPYC 9V74, five visible vCPUs
- Python 3.13.5
- cryptography 46.0.4
- NumPy 2.3.5
- pandas 2.2.3
- matplotlib 3.10.8
- pytest 9.0.2

The implementation supports Python 3.11 or newer.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

## Fast validation

```bash
python -m pytest -q
python scripts/run_experiments.py --quick --output results_quick
```

Expected unit-test result: `30 passed`. Quick mode generates 488 scenarios and 3,416 system-scenario runs. Security/utility proportions are deterministic; timing is not.

## Full reproduction

```bash
python -m pytest -q
python scripts/run_experiments.py --output results
python scripts/make_figures.py --results results --output figures
```

Expected deterministic counts in `results/manifest.json`:

```text
scenarios: 3460
attack_instances: 2560
fault_classes: 32
fault_domain_classes: 128
benign_scenarios: 700
typed_release_scenarios: 300
ambiguous_scenarios: 200
system_scenario_runs: 24220
```

For `CONTINUITY`, `results/summary.csv` should report effect ASR `0`, contained classes `128`, benign auto-completion `1`, ambiguous escalation `1`, and lifecycle correctness `1`.

## Primary outputs

- `results/raw_results.csv`: one row per system-scenario execution, including first/second outcomes and effect count;
- `results/summary.csv`: main security, utility, lifecycle, size, and processing results;
- `results/by_fault.csv`: per-fault effect and lifecycle results;
- `results/ablation_raw.csv`, `ablation_summary.csv`, and `ablation_by_fault.csv`;
- `results/performance.csv` and `scaling.csv`;
- `figures/*.pdf`.

## Implementation map

The trusted-core implementation is in `src/continuity/core.py`. Scenario construction, fault injection, baselines, aggregation, and timing are in `src/continuity/experiment.py`.

The verifier checks:

- trusted ingress and signed root grant;
- root identity, task, policy, provenance/context commitments, authority, scope, tool/server/effect and field bounds;
- signed provenance/context manifests and exact nested value digests;
- signed typed-release credentials and predicates;
- role-bound stage topology and transition receipts;
- actual leaf changes, preservation rules, transformation relations and witnesses;
- assume-guarantee preconditions, postconditions and guarantee flow;
- final authority, scope, trusted tool manifest, policy and expiry;
- subject/action/policy/revocation/replay/idempotency at finality.

## Negative controls and interpretation

The six mechanism-level reference configurations and targeted ablations are intentionally incomplete. They are not reimplementations of named prior systems. The deterministic instances vary identifiers and values but share fault schemas, so do not apply binomial confidence intervals or treat the row count as an estimate of real-world attack prevalence.

## Safety

Effects are written only to an in-memory simulated world. Faults are abstract context transformations and do not contain production exploit payloads. Do not apply active fault injection to real services without authorization and isolation.
