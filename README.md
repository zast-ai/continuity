# CONTINUITY

**Security-Context Contracts for Composable LLM Agent Controls**

This repository is the research artifact accompanying the CONTINUITY paper. It contains a reference implementation of authenticated security-context composition, a deterministic cross-layer fault-injection suite, regression tests, raw experiment results, ablations, performance measurements, and publication figures.

CONTINUITY studies **security-context discontinuity**: an identity, grant, source, policy, transformation, action, or lifecycle fact may be valid at one control but be dropped, widened, rebound, or reinterpreted before an external effect is committed. The prototype carries signed root grants, provenance/context manifests, bounded typed-release credentials, role-bound transition receipts, independently checked transformation witnesses, and state-revalidated finality permits.

## Recorded conformance results

The included full run contains **3,460 deterministic scenarios** and **24,220 system-scenario executions**:

- 2,560 parameterized attack instances from 32 fault classes, four domains, and 128 fault-domain classes;
- 400 direct benign scenarios;
- 300 benign scenarios using signed, predicate-bounded typed releases;
- 200 ambiguous external-field scenarios that should escalate.

For the generated fault space, the full CONTINUITY configuration:

- commits no harmful effect in 2,560 attack instances;
- contains all 128 fault-domain classes;
- completes all 700 benign tasks, including all 300 typed-release tasks;
- escalates all 200 ambiguous tasks;
- preserves correct replay/retry lifecycle behavior.

These are exact conformance results for a deterministic suite, not IID samples and not a population-level estimate of real-world prompt-injection risk.

## Repository map

```text
src/continuity/core.py    Trust objects, contracts, verifier, permits, finality
src/continuity/experiment.py
                          Scenarios, faults, baselines, aggregation, timing
tests/                    30 unit and adversarial regression tests
scripts/                  Experiment and figure commands
results/                  Raw and aggregated recorded results
figures/                  Publication figures
```

## Install

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

Python 3.11 or newer is required. No model API key is needed because the planner is modeled as adversarial and attack actions are instantiated directly.

## Reproduce

Fast validation:

```bash
python -m pytest -q
python scripts/run_experiments.py --quick --output results_quick
```

Full artifact reproduction:

```bash
python -m pytest -q
python scripts/run_experiments.py --output results
python scripts/make_figures.py --results results --output figures
```

## Trust and scope

The trusted computing base includes configured root, provenance, context, release, and transformation issuers; the deployment policy; canonicalization and predicate implementations; the verifier; key management; and every finality sink for a protected effect class. Compromise of a root-authority or validator key can invalidate the corresponding guarantee. The prototype does not prove the semantic correctness of an external validator, enumerate every real effect path, or prevent harmful text that never crosses a mediated sink.

## License and citation

The code is distributed under the MIT License. Citation metadata is provided in `CITATION.cff`.
