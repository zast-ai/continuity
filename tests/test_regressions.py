from continuity.core import ContinuityVerifier
from continuity.experiment import (
    ATTACK_FAULTS,
    DOMAINS,
    NOW,
    build_infrastructure,
    make_scenario,
    materialise,
    run_system,
)


def verifier(infra):
    return ContinuityVerifier(
        infra.keyring,
        infra.contracts,
        infra.deployment,
        infra.signers["verifier"],
    )


def reasons_for(fault: str, domain: str = "finance") -> tuple[str, ...]:
    infra = build_infrastructure()
    scenario = make_scenario(domain, 123, "attack", fault=fault, infra=infra)
    return verifier(infra).verify_bundle(materialise(scenario, infra).bundle, NOW).reason_codes


def test_untrusted_component_key_cannot_originate_chain():
    reasons = reasons_for("UNTRUSTED_ROOT_PRODUCER")
    assert "E_UNTRUSTED_ROOT" in reasons
    assert "E_UNTRUSTED_ROOT_ISSUER" in reasons


def test_root_authority_is_checked_against_signed_grant():
    reasons = reasons_for("ROOT_AUTHORITY_EXCEEDED")
    assert "E_ROOT_AUTHORITY_EXCEEDED" in reasons
    assert "E_ROOT_OPERATION_NOT_GRANTED" in reasons


def test_root_scope_is_checked_against_signed_grant():
    assert "E_ROOT_SCOPE_EXCEEDED" in reasons_for("ROOT_SCOPE_EXCEEDED")


def test_root_field_predicate_is_enforced():
    assert any(
        reason.startswith("E_ROOT_FIELD_CONSTRAINT:")
        for reason in reasons_for("ROOT_FIELD_CONSTRAINT_BYPASS")
    )


def test_provenance_claim_binds_actual_nested_value():
    assert any(
        reason.startswith("E_PROVENANCE_VALUE_MISMATCH:")
        for reason in reasons_for("PROVENANCE_VALUE_SUBSTITUTION")
    )


def test_stage_signer_is_bound_to_deployment_role():
    assert any(
        reason.startswith("E_UNAUTHORISED_STAGE_SIGNER:")
        for reason in reasons_for("UNAUTHORISED_STAGE_SIGNER")
    )


def test_receipt_signer_must_equal_output_producer():
    assert any(
        reason.startswith("E_RECEIPT_PRODUCER_MISMATCH:")
        for reason in reasons_for("RECEIPT_PRODUCER_MISMATCH")
    )


def test_missing_transform_witness_is_rejected():
    assert any(
        reason.startswith("E_MISSING_TRANSFORM_WITNESS:")
        for reason in reasons_for("MISSING_TRANSFORM_WITNESS")
    )


def test_invalid_transform_relation_is_rejected():
    reasons = reasons_for("INVALID_TRANSFORM_WITNESS")
    assert any(reason.startswith("E_TRANSFORM_AFTER_MISMATCH:") for reason in reasons)
    assert any(reason.startswith("E_TRANSFORM_RELATION_FALSE:") for reason in reasons)


def test_typed_release_predicate_is_enforced():
    assert any(
        reason.startswith("E_INVALID_RELEASE:")
        for reason in reasons_for("RELEASE_PREDICATE_BYPASS")
    )


def test_typed_release_value_digest_is_enforced():
    assert any(
        reason.startswith("E_INVALID_RELEASE:")
        for reason in reasons_for("RELEASE_VALUE_SUBSTITUTION")
    )


def test_typed_release_expiry_is_enforced():
    assert any(
        reason.startswith("E_EXPIRED_RELEASE:")
        for reason in reasons_for("EXPIRED_RELEASE")
    )


def test_contract_guarantee_predicate_is_evaluated():
    assert any(
        reason.endswith("canonical_destination")
        for reason in reasons_for("CONTRACT_GUARANTEE_VIOLATION")
    )


def test_all_fault_domain_classes_are_contained():
    infra = build_infrastructure()
    for domain in DOMAINS:
        for index, fault in enumerate(ATTACK_FAULTS):
            scenario = make_scenario(
                domain, 10_000 + index, "attack", fault=fault, infra=infra
            )
            result = run_system(
                "CONTINUITY", scenario, infra, materialise(scenario, infra)
            )
            assert not result.violation_accepted, (domain, fault, result.reason)
            assert result.lifecycle_correct, (domain, fault, result.disposition, result.reason)
