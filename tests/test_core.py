from dataclasses import replace

import pytest

from continuity.core import (
    SECURITY_ROOT_PATHS,
    ContinuityVerifier,
    FinalitySink,
    NonceLedger,
    RuntimeState,
    SimulatedWorld,
    changed_fields,
    field_value,
    lint_pipeline,
)
from continuity.experiment import (
    NOW,
    build_infrastructure,
    make_scenario,
    materialise,
)


def verifier(infra):
    return ContinuityVerifier(
        infra.keyring,
        infra.contracts,
        infra.deployment,
        infra.signers["verifier"],
    )


def test_json_pointer_resolves_nested_parameter_leaf():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 17, "benign", infra=infra)
    assert field_value(scenario.initial, "/action/parameters/amount_cents") == 1017


def test_changed_fields_reports_leaf_not_parameter_blob():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 17, "benign", infra=infra)
    parameters = dict(scenario.initial.action.parameters)
    parameters["amount_cents"] += 1
    altered = replace(
        scenario.initial,
        action=replace(scenario.initial.action, parameters=parameters),
    )
    changes = changed_fields(scenario.initial, altered)
    assert "/action/parameters/amount_cents" in changes
    assert "/action/parameters" not in changes


def test_pipeline_lint_checks_fields_and_guarantee_flow():
    infra = build_infrastructure()
    contracts = [
        infra.contracts[f"contract:{stage}"]
        for stage in ("memory", "gateway", "adapter")
    ]
    assert lint_pipeline(
        contracts,
        set(SECURITY_ROOT_PATHS),
        set(infra.deployment.initial_guarantees),
    ) == []


def test_valid_alias_transform_is_exercised_and_accepted():
    infra = build_infrastructure()
    scenario = make_scenario("workspace", 23, "benign", infra=infra)
    trace = materialise(scenario, infra)
    assert trace.gateway.action.destination.startswith("alias:")
    assert not trace.final.action.destination.startswith("alias:")
    assert trace.bundle.transformation_witnesses
    assert verifier(infra).verify_bundle(trace.bundle, NOW).allowed


def test_issue_permit_rejects_denied_decision():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 5, "attack", fault="UNTRUSTED_FIELD_BINDING", infra=infra)
    trace = materialise(scenario, infra)
    v = verifier(infra)
    decision = v.verify_bundle(trace.bundle, NOW)
    assert not decision.allowed
    with pytest.raises(ValueError):
        v.issue_permit(decision, trace.final, scenario.sink_id, NOW)


def test_finality_subject_binding():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 9, "benign", infra=infra)
    trace = materialise(scenario, infra)
    v = verifier(infra)
    decision = v.verify_bundle(trace.bundle, NOW)
    permit = v.issue_permit(decision, trace.final, scenario.sink_id, NOW)
    sink = FinalitySink(
        scenario.sink_id,
        infra.keyring,
        infra.signers["verifier"].key_id,
        infra.signers["sink"],
        NonceLedger(),
        SimulatedWorld(),
    )
    ok, reason, _ = sink.execute(
        trace.final.action,
        permit,
        NOW,
        "spiffe://attacker",
        infra.deployment.runtime_state,
    )
    assert not ok and reason == "E_SUBJECT_SUBSTITUTION"


def test_finality_policy_revalidation():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 10, "benign", infra=infra)
    trace = materialise(scenario, infra)
    v = verifier(infra)
    permit = v.issue_permit(
        v.verify_bundle(trace.bundle, NOW), trace.final, scenario.sink_id, NOW
    )
    stale_state = RuntimeState(
        policy_id=infra.deployment.runtime_state.policy_id,
        policy_digest="sha256:new",
        policy_epoch=infra.deployment.runtime_state.policy_epoch + 1,
    )
    sink = FinalitySink(
        scenario.sink_id,
        infra.keyring,
        infra.signers["verifier"].key_id,
        infra.signers["sink"],
        NonceLedger(),
        SimulatedWorld(),
    )
    ok, reason, _ = sink.execute(
        trace.final.action,
        permit,
        NOW,
        trace.final.context.actor or "",
        stale_state,
    )
    assert not ok and reason == "E_STALE_PERMIT_POLICY"


def test_finality_revocation_revalidation():
    infra = build_infrastructure()
    scenario = make_scenario("finance", 11, "benign", infra=infra)
    trace = materialise(scenario, infra)
    v = verifier(infra)
    permit = v.issue_permit(
        v.verify_bundle(trace.bundle, NOW), trace.final, scenario.sink_id, NOW
    )
    revoked = replace(
        infra.deployment.runtime_state,
        revoked_ids=frozenset({scenario.root_grant.grant_id}),
    )
    sink = FinalitySink(
        scenario.sink_id,
        infra.keyring,
        infra.signers["verifier"].key_id,
        infra.signers["sink"],
        NonceLedger(),
        SimulatedWorld(),
    )
    ok, reason, _ = sink.execute(
        trace.final.action,
        permit,
        NOW,
        trace.final.context.actor or "",
        revoked,
    )
    assert not ok and reason == "E_REVOKED_AT_FINALITY"
