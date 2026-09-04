from continuity.experiment import (
    ABLATIONS,
    build_infrastructure,
    make_scenario,
    materialise,
    run_system,
)


def test_benign_and_valid_typed_release_execute():
    infra = build_infrastructure()
    for kind in ("benign", "benign_external"):
        scenario = make_scenario("finance", 17, kind, infra=infra)
        result = run_system(
            "CONTINUITY", scenario, infra, materialise(scenario, infra)
        )
        assert result.disposition == "EXECUTE"
        assert result.effect_count == 1
        assert result.lifecycle_correct


def test_ambiguous_external_field_escalates():
    infra = build_infrastructure()
    scenario = make_scenario("workspace", 19, "ambiguous", infra=infra)
    result = run_system(
        "CONTINUITY", scenario, infra, materialise(scenario, infra)
    )
    assert result.disposition == "ESCALATE"
    assert result.effect_count == 0
    assert result.lifecycle_correct


def test_untrusted_field_attack_expected_state_is_escalate():
    infra = build_infrastructure()
    scenario = make_scenario(
        "finance", 21, "attack", fault="UNTRUSTED_FIELD_BINDING", infra=infra
    )
    result = run_system(
        "CONTINUITY", scenario, infra, materialise(scenario, infra)
    )
    assert scenario.expected_terminal == "ESCALATE"
    assert result.disposition == "ESCALATE"
    assert result.effect_count == 0


def test_nonce_replay_executes_exactly_once():
    infra = build_infrastructure()
    scenario = make_scenario(
        "finance", 22, "attack", fault="NONCE_REPLAY", infra=infra
    )
    result = run_system(
        "CONTINUITY", scenario, infra, materialise(scenario, infra)
    )
    assert scenario.expected_terminal == "EXECUTE_ONCE"
    assert result.disposition == "EXECUTE_ONCE"
    assert result.effect_count == 1
    assert result.second_outcome == "IDEMPOTENT_REPLAY"
    assert not result.violation_accepted


def test_retry_with_new_nonce_is_idempotent():
    infra = build_infrastructure()
    scenario = make_scenario(
        "finance", 23, "attack", fault="RETRY_DUPLICATE", infra=infra
    )
    result = run_system(
        "CONTINUITY", scenario, infra, materialise(scenario, infra)
    )
    assert result.disposition == "EXECUTE_ONCE"
    assert result.effect_count == 1
    assert result.second_outcome == "IDEMPOTENT_REPLAY"


def test_post_permit_action_substitution_is_stopped_at_sink():
    infra = build_infrastructure()
    scenario = make_scenario(
        "finance",
        24,
        "attack",
        fault="POST_PERMIT_ACTION_SUBSTITUTION",
        infra=infra,
    )
    result = run_system(
        "CONTINUITY", scenario, infra, materialise(scenario, infra)
    )
    assert result.disposition == "DENY"
    assert result.first_outcome == "E_ACTION_SUBSTITUTION"
    assert result.effect_count == 0


def test_ablation_name_is_contract_conformance_not_missing_receipts():
    assert "NoContractConformance" in ABLATIONS
    assert "NoTransitionReceipts" not in ABLATIONS


def test_targeted_ablations_expose_corresponding_faults():
    infra = build_infrastructure()
    cases = (
        ("UNTRUSTED_ROOT_PRODUCER", "root_authentication"),
        ("UNAUTHORISED_STAGE_SIGNER", "component_role_binding"),
        ("INVALID_TRANSFORM_WITNESS", "transformation_witnesses"),
        ("RELEASE_PREDICATE_BYPASS", "release_validation"),
        ("PRINCIPAL_SUBSTITUTION", "identity"),
        ("TAINT_DOWNGRADE", "taint"),
        ("POLICY_DOWNGRADE", "policy"),
        ("CONTEXT_ROOT_OMISSION", "context_root"),
        ("POST_PERMIT_ACTION_SUBSTITUTION", "action_binding"),
        ("SUBJECT_SUBSTITUTION", "subject_binding"),
        ("REVOKED_GRANT", "revocation"),
        ("NONCE_REPLAY", "replay"),
        ("ALTERNATE_PATH", "mediation"),
    )
    for index, (fault, disabled) in enumerate(cases):
        scenario = make_scenario(
            "finance", 30_000 + index, "attack", fault=fault, infra=infra
        )
        result = run_system(
            "CONTINUITY",
            scenario,
            infra,
            materialise(scenario, infra),
            frozenset({disabled}),
        )
        assert result.violation_accepted, (fault, disabled, result.reason)
