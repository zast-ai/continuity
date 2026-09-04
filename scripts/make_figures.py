#!/usr/bin/env python3
from pathlib import Path
import argparse

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    results = Path(args.results)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)

    summary = pd.read_csv(results / "summary.csv")
    ablation = pd.read_csv(results / "ablation_summary.csv")
    scaling = pd.read_csv(results / "scaling.csv")

    display_names = {
        "PassThrough": "Pass-through",
        "ToolAllowlist": "Tool allowlist",
        "GatewayPolicy": "Gateway policy",
        "ProvenanceGateway": "Provenance gate",
        "EffectBoundPermit": "Effect-bound permit",
        "Gateway+Finality": "Gateway + finality",
        "CONTINUITY": "CONTINUITY",
    }

    x = np.arange(len(summary))
    width = 0.36
    fig, axis = plt.subplots(figsize=(9.2, 4.4))
    axis.bar(
        x - width / 2,
        100 * summary.effect_attack_success_rate,
        width,
        label="Effect attack success",
    )
    axis.bar(
        x + width / 2,
        100 * summary.benign_auto_completion_rate,
        width,
        label="Benign auto-completion",
    )
    axis.set_ylabel("Rate (%)")
    axis.set_ylim(0, 105)
    axis.set_xticks(x)
    axis.set_xticklabels(
        [display_names.get(value, value) for value in summary.system],
        rotation=24,
        ha="right",
    )
    axis.grid(axis="y", alpha=0.25)
    axis.legend(frameon=False, ncol=2, loc="upper center")
    fig.tight_layout()
    fig.savefig(output / "main_security_utility.pdf", bbox_inches="tight")
    fig.savefig(
        output / "main_security_utility.png", dpi=220, bbox_inches="tight"
    )
    plt.close(fig)

    labels = {
        "Full": "Full",
        "NoRootAuthentication": "No root authentication",
        "NoComponentRoleBinding": "No component-role binding",
        "NoContractConformance": "No contract conformance",
        "NoTransformWitnessValidation": "No transform-witness validation",
        "NoReleaseValidation": "No release validation",
        "NoFieldProvenance": "No field provenance",
        "NoIdentityBinding": "No identity binding",
        "NoAuthorityMonotonicity": "No authority monotonicity",
        "NoDelegationMonotonicity": "No delegation monotonicity",
        "NoTaintMonotonicity": "No taint monotonicity",
        "NoPolicyFreshness": "No policy freshness",
        "NoContextCommitment": "No context commitment",
        "NoActionBinding": "No action binding",
        "NoSubjectBinding": "No subject binding",
        "NoRevocationRecheck": "No revocation recheck",
        "NoReplayProtection": "No replay protection",
        "IncompleteMediation": "Incomplete mediation",
    }
    # Zero-valued authority/delegation rows are retained in CSV and discussed as
    # redundant controls, but omitted from the visual to keep the figure legible.
    plotted = ablation[
        (ablation.effect_attack_success_rate > 0) | (ablation.ablation == "Full")
    ].iloc[::-1]
    fig, axis = plt.subplots(figsize=(8.4, 6.7))
    values = 100 * plotted.effect_attack_success_rate
    axis.barh([labels.get(value, value) for value in plotted.ablation], values)
    axis.set_xlabel("Effect attack success rate (%)")
    axis.grid(axis="x", alpha=0.25)
    axis.set_xlim(0, max(32, float(values.max() + 3)))
    for index, value in enumerate(values):
        axis.text(value + 0.4, index, f"{value:.1f}", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(output / "ablation.pdf", bbox_inches="tight")
    fig.savefig(output / "ablation.png", dpi=220, bbox_inches="tight")
    plt.close(fig)

    fig, axis = plt.subplots(figsize=(6.4, 3.8))
    axis.plot(scaling.transitions, scaling.p50_ms, marker="o", label="p50")
    axis.plot(scaling.transitions, scaling.p95_ms, marker="s", label="p95")
    axis.set_xlabel("Signed context transitions")
    axis.set_ylabel("Verification latency (ms)")
    axis.set_xticks(scaling.transitions)
    axis.grid(alpha=0.25)
    axis.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(output / "scaling.pdf", bbox_inches="tight")
    fig.savefig(output / "scaling.png", dpi=220, bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    main()
