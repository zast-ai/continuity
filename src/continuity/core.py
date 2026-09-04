from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import asdict, dataclass, is_dataclass, replace
from enum import Enum, IntEnum
from typing import Any, Callable, FrozenSet, Iterable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


# ---------- Canonical representation and signatures ----------

def _normalise(value: Any) -> Any:
    if is_dataclass(value):
        value = asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(k): _normalise(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (set, frozenset)):
        return sorted((_normalise(v) for v in value), key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":")))
    if isinstance(value, (tuple, list)):
        return [_normalise(v) for v in value]
    if isinstance(value, bytes):
        return {"$bytes": base64.urlsafe_b64encode(value).decode().rstrip("=")}
    if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
        raise ValueError("non-finite float")
    return value


def canonical_bytes(value: Any) -> bytes:
    """Deterministic JSON for the artifact's constrained value domain."""
    return json.dumps(_normalise(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class Signer:
    def __init__(self, key_id: str) -> None:
        self.key_id = key_id
        self._private = Ed25519PrivateKey.generate()

    @property
    def public_bytes(self) -> bytes:
        return self._private.public_key().public_bytes_raw()

    def sign(self, value: Any) -> str:
        return _b64(self._private.sign(canonical_bytes(value)))


class Keyring:
    def __init__(self) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}

    def add(self, signer: Signer) -> None:
        self._keys[signer.key_id] = Ed25519PublicKey.from_public_bytes(signer.public_bytes)

    def verify(self, key_id: str, value: Any, signature: str) -> bool:
        key = self._keys.get(key_id)
        if key is None:
            return False
        try:
            key.verify(_unb64(signature), canonical_bytes(value))
            return True
        except (InvalidSignature, ValueError):
            return False


class SignedObject:
    signature: str

    def unsigned(self) -> Mapping[str, Any]:
        data = asdict(self)
        data["signature"] = ""
        return data


# ---------- RFC-6901-style field paths ----------

_MISSING = object()


def pointer_escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def pointer_unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _pointer_tokens(pointer: str) -> list[str]:
    if not pointer.startswith("/"):
        raise ValueError(f"JSON Pointer must start with '/': {pointer!r}")
    return [] if pointer == "/" else [pointer_unescape(x) for x in pointer[1:].split("/")]


def resolve_pointer(value: Any, pointer: str, default: Any = _MISSING) -> Any:
    current = value
    try:
        for token in _pointer_tokens(pointer):
            if is_dataclass(current):
                current = getattr(current, token)
            elif isinstance(current, Mapping):
                current = current[token]
            elif isinstance(current, (tuple, list)):
                current = current[int(token)]
            else:
                raise KeyError(token)
        return current
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        if default is _MISSING:
            raise
        return default


def _leaf_paths(value: Any, base: str) -> set[str]:
    if isinstance(value, Mapping):
        if not value:
            return {base}
        result: set[str] = set()
        for key, child in value.items():
            result |= _leaf_paths(child, f"{base}/{pointer_escape(str(key))}")
        return result
    if isinstance(value, (tuple, list)):
        if not value:
            return {base}
        result: set[str] = set()
        for index, child in enumerate(value):
            result |= _leaf_paths(child, f"{base}/{index}")
        return result
    return {base}


CONTEXT_ATOMIC_PATHS: FrozenSet[str] = frozenset({
    "/context/principal", "/context/actor", "/context/task_root", "/context/root_grant_id",
    "/context/source_classes", "/context/provenance_root", "/context/protected_field_sources",
    "/context/typed_releases", "/context/authority", "/context/delegation_scope",
    "/context/policy_id", "/context/policy_digest", "/context/policy_epoch", "/context/taint",
    "/context/context_root", "/context/nonce", "/context/expires_at", "/context/approval_digest",
})
ACTION_ATOMIC_PATHS: FrozenSet[str] = frozenset({
    "/action/operation", "/action/tool_id", "/action/server_id", "/action/tool_manifest_digest",
    "/action/function", "/action/resource", "/action/destination", "/action/effect_class",
    "/action/data_classification",
})
SECURITY_ROOT_PATHS: FrozenSet[str] = frozenset(set(CONTEXT_ATOMIC_PATHS) | set(ACTION_ATOMIC_PATHS) | {"/action/parameters"})


def path_within(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip("/") + "/")


# ---------- Security objects ----------

class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


@dataclass(frozen=True)
class PredicateSpec:
    predicate_id: str
    parameters: Mapping[str, Any]


@dataclass(frozen=True)
class FieldConstraint:
    path: str
    predicate: PredicateSpec


@dataclass(frozen=True)
class Action:
    operation: str
    tool_id: str
    server_id: str
    tool_manifest_digest: str
    function: str
    resource: str
    destination: str
    parameters: Mapping[str, Any]
    effect_class: str
    data_classification: int

    @property
    def action_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class RootGrant(SignedObject):
    grant_id: str
    issuer: str
    principal: str
    actor: str
    task_root: str
    authority: FrozenSet[str]
    delegation_scope: FrozenSet[str]
    allowed_tool_ids: FrozenSet[str]
    allowed_server_ids: FrozenSet[str]
    allowed_effect_classes: FrozenSet[str]
    max_data_classification: int
    field_constraints: tuple[FieldConstraint, ...]
    policy_id: str
    policy_digest: str
    policy_epoch: int
    provenance_root: str
    context_root: str
    nonce: str
    expires_at: int
    signature: str = ""

    @property
    def grant_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "RootGrant":
        unsigned = replace(self, issuer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    source_class: str
    content_digest: str


@dataclass(frozen=True)
class FieldProvenance:
    path: str
    source_id: str
    value_digest: str


@dataclass(frozen=True)
class ProvenanceManifest(SignedObject):
    manifest_id: str
    issuer: str
    principal: str
    task_root: str
    sources: tuple[SourceRecord, ...]
    claims: tuple[FieldProvenance, ...]
    expires_at: int
    signature: str = ""

    @property
    def manifest_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "ProvenanceManifest":
        unsigned = replace(self, issuer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class ContextItem:
    item_id: str
    source_id: str
    source_class: str
    content_digest: str


@dataclass(frozen=True)
class ContextManifest(SignedObject):
    manifest_id: str
    issuer: str
    principal: str
    task_root: str
    items: tuple[ContextItem, ...]
    expires_at: int
    signature: str = ""

    @property
    def manifest_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "ContextManifest":
        unsigned = replace(self, issuer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class ReleaseCredential(SignedObject):
    release_id: str
    issuer: str
    principal: str
    actor: str
    task_root: str
    provenance_manifest_digest: str
    source_id: str
    source_digest: str
    target_path: str
    value_digest: str
    predicate: PredicateSpec
    action_operation: str
    tool_id: str
    nonce: str
    expires_at: int
    signature: str = ""

    @property
    def release_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "ReleaseCredential":
        unsigned = replace(self, issuer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class TransformationWitness(SignedObject):
    witness_id: str
    issuer: str
    relation_id: str
    field_path: str
    before_digest: str
    after_digest: str
    principal: str
    task_root: str
    component_signer: str
    contract_id: str
    parameters: Mapping[str, Any]
    expires_at: int
    signature: str = ""

    @property
    def witness_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "TransformationWitness":
        unsigned = replace(self, issuer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class SecurityContext:
    principal: str | None
    actor: str | None
    task_root: str | None
    root_grant_id: str | None
    source_classes: tuple[str, ...]
    provenance_root: str | None
    protected_field_sources: Mapping[str, str]
    typed_releases: FrozenSet[str]
    authority: FrozenSet[str]
    delegation_scope: FrozenSet[str]
    policy_id: str | None
    policy_digest: str | None
    policy_epoch: int | None
    taint: int
    context_root: str | None
    nonce: str | None
    expires_at: int | None
    approval_digest: str | None = None


@dataclass(frozen=True)
class Envelope(SignedObject):
    context: SecurityContext
    action: Action
    representation: Mapping[str, Any]
    producer: str
    sequence: int
    signature: str = ""

    @property
    def envelope_digest(self) -> str:
        return digest(self.unsigned())

    def signed(self, signer: Signer) -> "Envelope":
        unsigned = replace(self, producer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class TransformRule:
    field_path: str
    relation_id: str
    witness_required: bool = True


@dataclass(frozen=True)
class ComponentContract:
    contract_id: str
    version: str
    role: str
    requires_fields: FrozenSet[str]
    requires_guarantees: FrozenSet[str]
    requires_predicates: tuple[PredicateSpec, ...]
    ensures_fields: FrozenSet[str]
    ensures_guarantees: FrozenSet[str]
    ensures_predicates: tuple[PredicateSpec, ...]
    preserves: FrozenSet[str]
    transform_rules: tuple[TransformRule, ...]

    @property
    def contract_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class PipelineStage:
    stage: str
    role: str
    signer_id: str
    contract_id: str


@dataclass(frozen=True)
class TransitionReceipt(SignedObject):
    stage: str
    role: str
    contract_id: str
    contract_digest: str
    input_digest: str
    output_digest: str
    changed_fields: tuple[str, ...]
    transformation_witness_ids: tuple[str, ...]
    assumption_ids: tuple[str, ...]
    guarantee_ids: tuple[str, ...]
    signer: str
    signature: str = ""

    def signed(self, signer: Signer) -> "TransitionReceipt":
        unsigned = replace(self, signer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class ProofBundle:
    root_grant: RootGrant
    provenance_manifest: ProvenanceManifest
    context_manifest: ContextManifest
    release_credentials: tuple[ReleaseCredential, ...]
    transformation_witnesses: tuple[TransformationWitness, ...]
    envelopes: tuple[Envelope, ...]
    receipts: tuple[TransitionReceipt, ...]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason_codes: tuple[str, ...]
    bundle_digest: str
    action_digest: str
    principal: str
    actor: str
    task_root: str
    grant_id: str
    policy_id: str
    policy_digest: str
    policy_epoch: int


@dataclass(frozen=True)
class ExecutionPermit(SignedObject):
    permit_id: str
    principal: str
    subject: str
    task_root: str
    grant_id: str
    audience: str
    action_digest: str
    bundle_digest: str
    policy_id: str
    policy_digest: str
    policy_epoch: int
    nonce: str
    idempotency_key: str
    expires_at: int
    one_time: bool
    signer: str
    signature: str = ""

    def signed(self, signer: Signer) -> "ExecutionPermit":
        unsigned = replace(self, signer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class OutcomeReceipt(SignedObject):
    effect_id: str
    permit_id: str
    principal: str
    subject: str
    action_digest: str
    status: str
    idempotency_key: str
    state_digest: str
    signer: str
    signature: str = ""

    def signed(self, signer: Signer) -> "OutcomeReceipt":
        unsigned = replace(self, signer=signer.key_id, signature="")
        return replace(unsigned, signature=signer.sign(unsigned.unsigned()))


@dataclass(frozen=True)
class RuntimeState:
    policy_id: str
    policy_digest: str
    policy_epoch: int
    revoked_ids: FrozenSet[str] = frozenset()


@dataclass(frozen=True)
class DeploymentPolicy:
    trusted_ingress: FrozenSet[str]
    trusted_root_issuers: FrozenSet[str]
    trusted_provenance_issuers: FrozenSet[str]
    trusted_context_issuers: FrozenSet[str]
    trusted_release_issuers: FrozenSet[str]
    trusted_transform_issuers: Mapping[str, FrozenSet[str]]
    pipeline: tuple[PipelineStage, ...]
    initial_guarantees: FrozenSet[str]
    trusted_tool_manifests: Mapping[str, str]
    runtime_state: RuntimeState


@dataclass(frozen=True)
class TransformResult:
    envelope: Envelope
    witnesses: tuple[TransformationWitness, ...] = ()


def security_paths(envelope: Envelope) -> set[str]:
    return set(CONTEXT_ATOMIC_PATHS) | set(ACTION_ATOMIC_PATHS) | _leaf_paths(envelope.action.parameters, "/action/parameters")


def field_value(envelope: Envelope, pointer: str, default: Any = _MISSING) -> Any:
    if pointer == "/representation":
        return envelope.representation
    if pointer.startswith("/context/") or pointer.startswith("/action/"):
        return resolve_pointer(envelope, pointer, default)
    raise ValueError(f"unsupported field pointer: {pointer}")


def present(envelope: Envelope, pointer: str) -> bool:
    value = field_value(envelope, pointer, _MISSING)
    if value is _MISSING or value is None:
        return False
    if isinstance(value, (set, frozenset, tuple, list, dict)):
        return len(value) > 0
    return True


def changed_fields(before: Envelope, after: Envelope) -> set[str]:
    paths = security_paths(before) | security_paths(after)
    changed = {path for path in paths if field_value(before, path, _MISSING) != field_value(after, path, _MISSING)}
    if before.representation != after.representation:
        changed.add("/representation")
    return changed


# ---------- Predicate and relation semantics ----------

ValuePredicate = Callable[[Any, Mapping[str, Any]], bool]
EnvelopePredicate = Callable[[Envelope, Mapping[str, Any]], bool]
RelationPredicate = Callable[[Any, Any, Mapping[str, Any]], bool]


def _int_range(value: Any, p: Mapping[str, Any]) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and int(p.get("min", -(2**63))) <= value <= int(p.get("max", 2**63 - 1))


def _str_prefix(value: Any, p: Mapping[str, Any]) -> bool:
    return isinstance(value, str) and value.startswith(str(p["prefix"]))


def _equals(value: Any, p: Mapping[str, Any]) -> bool:
    return value == p.get("value")


def _enum(value: Any, p: Mapping[str, Any]) -> bool:
    return value in tuple(p.get("values", ()))


def _hex_length(value: Any, p: Mapping[str, Any]) -> bool:
    length = int(p["length"])
    return isinstance(value, str) and len(value) == length and bool(re.fullmatch(r"[0-9a-fA-F]+", value))


VALUE_PREDICATES: Mapping[str, ValuePredicate] = {
    "int_range": _int_range,
    "str_prefix": _str_prefix,
    "equals": _equals,
    "enum": _enum,
    "hex_length": _hex_length,
}


def evaluate_value_predicate(spec: PredicateSpec, value: Any) -> bool:
    fn = VALUE_PREDICATES.get(spec.predicate_id)
    return bool(fn and fn(value, spec.parameters))


def _identity_complete(env: Envelope, _: Mapping[str, Any]) -> bool:
    c = env.context
    return bool(c.principal and c.actor and c.task_root and c.root_grant_id)


def _provenance_refs_present(env: Envelope, _: Mapping[str, Any]) -> bool:
    c = env.context
    return bool(c.provenance_root and c.context_root and c.protected_field_sources)


def _policy_matches(env: Envelope, p: Mapping[str, Any]) -> bool:
    c = env.context
    return c.policy_id == p.get("policy_id") and c.policy_digest == p.get("policy_digest") and c.policy_epoch == p.get("policy_epoch")


def _action_complete(env: Envelope, _: Mapping[str, Any]) -> bool:
    a = env.action
    return bool(a.operation and a.tool_id and a.server_id and a.tool_manifest_digest and a.function and a.resource and a.destination and a.effect_class)


def _canonical_destination(env: Envelope, _: Mapping[str, Any]) -> bool:
    return bool(env.action.destination) and not env.action.destination.startswith("alias:")


def _parameters_mapping(env: Envelope, _: Mapping[str, Any]) -> bool:
    return isinstance(env.action.parameters, Mapping)


ENVELOPE_PREDICATES: Mapping[str, EnvelopePredicate] = {
    "identity_complete": _identity_complete,
    "provenance_refs_present": _provenance_refs_present,
    "policy_matches": _policy_matches,
    "action_complete": _action_complete,
    "canonical_destination": _canonical_destination,
    "parameters_mapping": _parameters_mapping,
}


def evaluate_envelope_predicate(spec: PredicateSpec, envelope: Envelope) -> bool:
    fn = ENVELOPE_PREDICATES.get(spec.predicate_id)
    return bool(fn and fn(envelope, spec.parameters))


def _alias_resolution(before: Any, after: Any, p: Mapping[str, Any]) -> bool:
    return isinstance(before, str) and isinstance(after, str) and before == p.get("alias") and after == p.get("resolved") and before.startswith("alias:") and not after.startswith("alias:")


RELATION_PREDICATES: Mapping[str, RelationPredicate] = {"alias_resolution": _alias_resolution}


def evaluate_relation(relation_id: str, before: Any, after: Any, parameters: Mapping[str, Any]) -> bool:
    fn = RELATION_PREDICATES.get(relation_id)
    return bool(fn and fn(before, after, parameters))


# ---------- Contract composition and transition production ----------

def lint_pipeline(contracts: Iterable[ComponentContract], initial_fields: set[str], initial_guarantees: set[str]) -> list[str]:
    available_fields = set(initial_fields)
    guarantees = set(initial_guarantees)
    errors: list[str] = []
    for index, contract in enumerate(contracts):
        missing_fields = set(contract.requires_fields) - available_fields
        if missing_fields:
            errors.append(f"stage[{index}] {contract.contract_id}: missing fields {sorted(missing_fields)}")
        missing_guarantees = set(contract.requires_guarantees) - guarantees
        if missing_guarantees:
            errors.append(f"stage[{index}] {contract.contract_id}: missing guarantees {sorted(missing_guarantees)}")
        available_fields |= set(contract.ensures_fields) | set(contract.preserves) | {rule.field_path for rule in contract.transform_rules}
        guarantees |= set(contract.ensures_guarantees)
    return errors


class Component:
    def __init__(self, stage: str, contract: ComponentContract, signer: Signer, transform: Callable[[Envelope], TransformResult | Envelope]) -> None:
        self.stage = stage
        self.contract = contract
        self.signer = signer
        self.transform = transform

    def apply(self, envelope: Envelope) -> tuple[Envelope, TransitionReceipt, tuple[TransformationWitness, ...]]:
        result = self.transform(envelope)
        if isinstance(result, Envelope):
            result = TransformResult(result)
        output = replace(result.envelope, sequence=envelope.sequence + 1, signature="").signed(self.signer)
        changes = tuple(sorted(changed_fields(envelope, output)))
        receipt = TransitionReceipt(
            stage=self.stage,
            role=self.contract.role,
            contract_id=self.contract.contract_id,
            contract_digest=self.contract.contract_digest,
            input_digest=envelope.envelope_digest,
            output_digest=output.envelope_digest,
            changed_fields=changes,
            transformation_witness_ids=tuple(w.witness_id for w in result.witnesses),
            assumption_ids=tuple(p.predicate_id for p in self.contract.requires_predicates),
            guarantee_ids=tuple(p.predicate_id for p in self.contract.ensures_predicates),
            signer=self.signer.key_id,
        ).signed(self.signer)
        return output, receipt, result.witnesses


# ---------- Verifier ----------

class ContinuityVerifier:
    def __init__(self, keyring: Keyring, contracts: Mapping[str, ComponentContract], deployment: DeploymentPolicy, permit_signer: Signer, disabled_checks: FrozenSet[str] = frozenset()) -> None:
        self.keyring = keyring
        self.contracts = dict(contracts)
        self.deployment = deployment
        self.permit_signer = permit_signer
        self.disabled_checks = disabled_checks

    def _path_ignored(self, path: str) -> bool:
        groups = {
            "identity": {"/context/principal", "/context/actor", "/context/task_root", "/context/root_grant_id"},
            "provenance": {"/context/source_classes", "/context/provenance_root", "/context/protected_field_sources", "/context/typed_releases"},
            "context_root": {"/context/context_root"},
            "authority": {"/context/authority"},
            "delegation": {"/context/delegation_scope"},
            "taint": {"/context/taint"},
            "policy": {"/context/policy_id", "/context/policy_digest", "/context/policy_epoch"},
        }
        return any(check in self.disabled_checks and any(path_within(path, root) for root in roots) for check, roots in groups.items())

    def _predicate_disabled(self, predicate_id: str) -> bool:
        return (
            (predicate_id == "identity_complete" and "identity" in self.disabled_checks)
            or (predicate_id == "provenance_refs_present" and ("provenance" in self.disabled_checks or "context_root" in self.disabled_checks))
            or (predicate_id == "policy_matches" and "policy" in self.disabled_checks)
        )

    def _verify_signed(self, key_id: str, obj: SignedObject, signature: str, reason: str, reasons: list[str]) -> None:
        if not self.keyring.verify(key_id, obj.unsigned(), signature):
            reasons.append(reason)

    def _verify_root(self, bundle: ProofBundle, now: int, reasons: list[str]) -> set[str]:
        if not bundle.envelopes:
            reasons.append("E_EMPTY_CHAIN")
            return set()
        root = bundle.envelopes[0]
        grant = bundle.root_grant
        self._verify_signed(root.producer, root, root.signature, "E_BAD_ROOT_ENVELOPE_SIGNATURE", reasons)
        self._verify_signed(grant.issuer, grant, grant.signature, "E_BAD_ROOT_GRANT_SIGNATURE", reasons)

        if "root_authentication" not in self.disabled_checks:
            if root.producer not in self.deployment.trusted_ingress:
                reasons.append("E_UNTRUSTED_ROOT")
            if grant.issuer not in self.deployment.trusted_root_issuers:
                reasons.append("E_UNTRUSTED_ROOT_ISSUER")
            if grant.grant_id in self.deployment.runtime_state.revoked_ids:
                reasons.append("E_REVOKED_ROOT_GRANT")
            if grant.expires_at < now:
                reasons.append("E_EXPIRED_ROOT_GRANT")
            c = root.context
            exact_pairs: list[tuple[Any, Any, str]] = [(c.nonce, grant.nonce, "E_ROOT_NONCE_MISMATCH")]
            if "identity" not in self.disabled_checks:
                exact_pairs.extend([
                    (c.principal, grant.principal, "E_ROOT_PRINCIPAL_MISMATCH"),
                    (c.actor, grant.actor, "E_ROOT_ACTOR_MISMATCH"),
                    (c.task_root, grant.task_root, "E_ROOT_TASK_MISMATCH"),
                    (c.root_grant_id, grant.grant_id, "E_ROOT_GRANT_ID_MISMATCH"),
                ])
            if "policy" not in self.disabled_checks:
                exact_pairs.extend([
                    (c.policy_id, grant.policy_id, "E_ROOT_POLICY_ID_MISMATCH"),
                    (c.policy_digest, grant.policy_digest, "E_ROOT_POLICY_DIGEST_MISMATCH"),
                    (c.policy_epoch, grant.policy_epoch, "E_ROOT_POLICY_EPOCH_MISMATCH"),
                ])
            if "provenance" not in self.disabled_checks:
                exact_pairs.append((c.provenance_root, grant.provenance_root, "E_ROOT_PROVENANCE_MISMATCH"))
            if "context_root" not in self.disabled_checks:
                exact_pairs.append((c.context_root, grant.context_root, "E_ROOT_CONTEXT_MISMATCH"))
            for actual, expected, reason in exact_pairs:
                if actual != expected:
                    reasons.append(reason)

            if "authority" not in self.disabled_checks:
                if not c.authority.issubset(grant.authority):
                    reasons.append("E_ROOT_AUTHORITY_EXCEEDED")
                if root.action.operation not in grant.authority:
                    reasons.append("E_ROOT_OPERATION_NOT_GRANTED")
            if "delegation" not in self.disabled_checks:
                if not c.delegation_scope.issubset(grant.delegation_scope):
                    reasons.append("E_ROOT_SCOPE_EXCEEDED")
                scope = f"{root.action.operation}:{root.action.resource}"
                if scope not in grant.delegation_scope and f"{root.action.operation}:*" not in grant.delegation_scope:
                    reasons.append("E_ROOT_ACTION_SCOPE_EXCEEDED")
            if root.action.tool_id not in grant.allowed_tool_ids:
                reasons.append("E_ROOT_TOOL_NOT_GRANTED")
            if root.action.server_id not in grant.allowed_server_ids:
                reasons.append("E_ROOT_SERVER_NOT_GRANTED")
            if root.action.effect_class not in grant.allowed_effect_classes:
                reasons.append("E_ROOT_EFFECT_NOT_GRANTED")
            if root.action.data_classification > grant.max_data_classification:
                reasons.append("E_ROOT_DATA_CLASS_EXCEEDED")
            for constraint in grant.field_constraints:
                value = field_value(root, constraint.path, _MISSING)
                if value is _MISSING:
                    reasons.append(f"E_ROOT_CONSTRAINT_FIELD_MISSING:{constraint.path}")
                elif not evaluate_value_predicate(constraint.predicate, value):
                    reasons.append(f"E_ROOT_FIELD_CONSTRAINT:{constraint.path}")

        root_prefixes = (
            "E_ROOT_", "E_UNTRUSTED_ROOT", "E_REVOKED_ROOT_GRANT", "E_EXPIRED_ROOT_GRANT",
            "E_BAD_ROOT_GRANT_SIGNATURE", "E_BAD_ROOT_ENVELOPE_SIGNATURE",
        )
        if not any(reason.startswith(root_prefixes) for reason in reasons):
            return {"root-authenticated"}
        return set()

    def _verify_provenance(self, bundle: ProofBundle, now: int, reasons: list[str]) -> set[str]:
        if not bundle.envelopes:
            return set()
        root = bundle.envelopes[0]
        manifest = bundle.provenance_manifest
        context_manifest = bundle.context_manifest
        self._verify_signed(manifest.issuer, manifest, manifest.signature, "E_BAD_PROVENANCE_SIGNATURE", reasons)
        self._verify_signed(context_manifest.issuer, context_manifest, context_manifest.signature, "E_BAD_CONTEXT_MANIFEST_SIGNATURE", reasons)

        if "provenance" not in self.disabled_checks:
            if manifest.issuer not in self.deployment.trusted_provenance_issuers:
                reasons.append("E_UNTRUSTED_PROVENANCE_ISSUER")
            if manifest.expires_at < now:
                reasons.append("E_EXPIRED_PROVENANCE_MANIFEST")
            if manifest.manifest_digest != root.context.provenance_root:
                reasons.append("E_PROVENANCE_ROOT_MISMATCH")
            if manifest.principal != root.context.principal or manifest.task_root != root.context.task_root:
                reasons.append("E_PROVENANCE_SUBJECT_MISMATCH")
            sources = {s.source_id: s for s in manifest.sources}
            claims = {c.path: c for c in manifest.claims}
            if len(sources) != len(manifest.sources):
                reasons.append("E_DUPLICATE_SOURCE_ID")
            if len(claims) != len(manifest.claims):
                reasons.append("E_DUPLICATE_PROVENANCE_PATH")
            if dict(root.context.protected_field_sources) != {path: claim.source_id for path, claim in claims.items()}:
                reasons.append("E_FIELD_SOURCE_MAP_MISMATCH")
            for path, claim in claims.items():
                source = sources.get(claim.source_id)
                if source is None:
                    reasons.append(f"E_UNKNOWN_PROVENANCE_SOURCE:{path}")
                    continue
                value = field_value(root, path, _MISSING)
                if value is _MISSING:
                    reasons.append(f"E_PROVENANCE_FIELD_MISSING:{path}")
                elif digest(value) != claim.value_digest:
                    reasons.append(f"E_PROVENANCE_VALUE_MISMATCH:{path}")
            declared = tuple(sorted(set(root.context.source_classes)))
            actual = tuple(sorted({s.source_class for s in manifest.sources}))
            if declared != actual:
                reasons.append("E_SOURCE_CLASS_MISMATCH")

        if "context_root" not in self.disabled_checks:
            if context_manifest.issuer not in self.deployment.trusted_context_issuers:
                reasons.append("E_UNTRUSTED_CONTEXT_ISSUER")
            if context_manifest.expires_at < now:
                reasons.append("E_EXPIRED_CONTEXT_MANIFEST")
            if context_manifest.manifest_digest != root.context.context_root:
                reasons.append("E_CONTEXT_ROOT_MISMATCH")
            if context_manifest.principal != root.context.principal or context_manifest.task_root != root.context.task_root:
                reasons.append("E_CONTEXT_SUBJECT_MISMATCH")

        provenance_errors = [r for r in reasons if "PROVENANCE" in r or "SOURCE_" in r or "FIELD_SOURCE" in r or "CONTEXT_" in r]
        guarantees: set[str] = set()
        if not any("PROVENANCE" in r or "SOURCE_" in r or "FIELD_SOURCE" in r for r in provenance_errors):
            guarantees.add("provenance-authenticated")
        if not any("CONTEXT_" in r for r in provenance_errors):
            guarantees.add("context-authenticated")
        return guarantees

    def _release_index(
        self, bundle: ProofBundle, now: int, reasons: list[str]
    ) -> dict[str, ReleaseCredential]:
        index: dict[str, ReleaseCredential] = {}
        for release in bundle.release_credentials:
            if release.release_id in index:
                reasons.append("E_DUPLICATE_RELEASE_ID")
            index[release.release_id] = release
            self._verify_signed(
                release.issuer,
                release,
                release.signature,
                f"E_BAD_RELEASE_SIGNATURE:{release.release_id}",
                reasons,
            )
            if "release_validation" not in self.disabled_checks:
                if release.issuer not in self.deployment.trusted_release_issuers:
                    reasons.append(f"E_UNTRUSTED_RELEASE_ISSUER:{release.release_id}")
                if release.release_id in self.deployment.runtime_state.revoked_ids:
                    reasons.append(f"E_REVOKED_RELEASE:{release.release_id}")
                if release.expires_at < now:
                    reasons.append(f"E_EXPIRED_RELEASE:{release.release_id}")
        return index

    def _verify_releases(
        self,
        bundle: ProofBundle,
        release_index: Mapping[str, ReleaseCredential],
        reasons: list[str],
    ) -> None:
        if "provenance" in self.disabled_checks:
            return
        root = bundle.envelopes[0]
        manifest = bundle.provenance_manifest
        sources = {source.source_id: source for source in manifest.sources}
        claims = {claim.path: claim for claim in manifest.claims}
        release_ids = set(root.context.typed_releases)

        for release_id in release_ids:
            if release_id not in release_index:
                reasons.append(f"E_UNKNOWN_RELEASE:{release_id}")

        for path, source_id in root.context.protected_field_sources.items():
            source = sources.get(source_id)
            claim = claims.get(path)
            if source is None or claim is None:
                continue
            if source.source_class not in {"EXTERNAL", "TOOL_RESULT", "MEMORY"}:
                continue
            matching = [
                release_index[release_id]
                for release_id in release_ids
                if release_id in release_index
                and release_index[release_id].target_path == path
                and release_index[release_id].source_id == source_id
            ]
            if not matching:
                reasons.append(f"E_UNRELEASED_FIELD:{path}")
                continue
            if "release_validation" in self.disabled_checks:
                continue

            value = field_value(root, path, _MISSING)
            valid = False
            for release in matching:
                checks = (
                    release.principal == root.context.principal,
                    release.actor == root.context.actor,
                    release.task_root == root.context.task_root,
                    release.provenance_manifest_digest == manifest.manifest_digest,
                    release.source_digest == source.content_digest,
                    release.value_digest == claim.value_digest,
                    value is not _MISSING and digest(value) == release.value_digest,
                    release.action_operation == root.action.operation,
                    release.tool_id == root.action.tool_id,
                    evaluate_value_predicate(release.predicate, value)
                    if value is not _MISSING
                    else False,
                )
                if all(checks):
                    valid = True
                    break
            if not valid:
                reasons.append(f"E_INVALID_RELEASE:{path}")

    def _verify_transition_witness(
        self,
        witness: TransformationWitness,
        before: Envelope,
        after: Envelope,
        rule: TransformRule,
        receipt: TransitionReceipt,
        now: int,
        reasons: list[str],
    ) -> None:
        prefix = f"{receipt.stage}:{rule.field_path}"
        self._verify_signed(
            witness.issuer,
            witness,
            witness.signature,
            f"E_BAD_TRANSFORM_WITNESS_SIGNATURE:{prefix}",
            reasons,
        )
        if "transformation_witnesses" in self.disabled_checks:
            return
        trusted = self.deployment.trusted_transform_issuers.get(
            rule.relation_id, frozenset()
        )
        if witness.issuer not in trusted:
            reasons.append(f"E_UNTRUSTED_TRANSFORM_ISSUER:{prefix}")
        if witness.relation_id != rule.relation_id:
            reasons.append(f"E_TRANSFORM_RELATION_MISMATCH:{prefix}")
        if witness.field_path != rule.field_path:
            reasons.append(f"E_TRANSFORM_FIELD_MISMATCH:{prefix}")
        if witness.component_signer != receipt.signer:
            reasons.append(f"E_TRANSFORM_COMPONENT_MISMATCH:{prefix}")
        if witness.contract_id != receipt.contract_id:
            reasons.append(f"E_TRANSFORM_CONTRACT_MISMATCH:{prefix}")
        if (
            witness.principal != before.context.principal
            or witness.task_root != before.context.task_root
        ):
            reasons.append(f"E_TRANSFORM_SUBJECT_MISMATCH:{prefix}")
        if witness.expires_at < now:
            reasons.append(f"E_EXPIRED_TRANSFORM_WITNESS:{prefix}")
        before_value = field_value(before, rule.field_path, _MISSING)
        after_value = field_value(after, rule.field_path, _MISSING)
        if before_value is _MISSING or after_value is _MISSING:
            reasons.append(f"E_TRANSFORM_FIELD_MISSING:{prefix}")
            return
        if digest(before_value) != witness.before_digest:
            reasons.append(f"E_TRANSFORM_BEFORE_MISMATCH:{prefix}")
        if digest(after_value) != witness.after_digest:
            reasons.append(f"E_TRANSFORM_AFTER_MISMATCH:{prefix}")
        if not evaluate_relation(
            rule.relation_id, before_value, after_value, witness.parameters
        ):
            reasons.append(f"E_TRANSFORM_RELATION_FALSE:{prefix}")

    def _verify_transitions(
        self,
        bundle: ProofBundle,
        now: int,
        initial_guarantees: set[str],
        reasons: list[str],
    ) -> None:
        if len(bundle.envelopes) != len(bundle.receipts) + 1:
            reasons.append("E_CHAIN_LENGTH")
            return
        if len(bundle.receipts) != len(self.deployment.pipeline):
            reasons.append("E_PIPELINE_LENGTH")

        witness_index = {
            witness.witness_id: witness
            for witness in bundle.transformation_witnesses
        }
        if len(witness_index) != len(bundle.transformation_witnesses):
            reasons.append("E_DUPLICATE_TRANSFORM_WITNESS_ID")

        guarantees = set(initial_guarantees)
        for index, receipt in enumerate(bundle.receipts):
            before = bundle.envelopes[index]
            after = bundle.envelopes[index + 1]
            binding = (
                self.deployment.pipeline[index]
                if index < len(self.deployment.pipeline)
                else None
            )
            contract = self.contracts.get(receipt.contract_id)
            stage_reason_start = len(reasons)

            self._verify_signed(
                after.producer,
                after,
                after.signature,
                f"E_BAD_ENVELOPE_SIGNATURE:{index}",
                reasons,
            )
            self._verify_signed(
                receipt.signer,
                receipt,
                receipt.signature,
                f"E_BAD_RECEIPT_SIGNATURE:{index}",
                reasons,
            )
            if after.sequence != before.sequence + 1:
                reasons.append(f"E_SEQUENCE_GAP:{index}")
            if (
                receipt.input_digest != before.envelope_digest
                or receipt.output_digest != after.envelope_digest
            ):
                reasons.append(f"E_BROKEN_TRANSITION_LINK:{index}")
            if receipt.signer != after.producer:
                reasons.append(f"E_RECEIPT_PRODUCER_MISMATCH:{index}")

            if contract is None:
                reasons.append(f"E_UNKNOWN_CONTRACT:{receipt.contract_id}")
                continue
            if receipt.contract_digest != contract.contract_digest:
                reasons.append(f"E_CONTRACT_DIGEST:{index}")
            if receipt.role != contract.role:
                reasons.append(f"E_CONTRACT_ROLE_MISMATCH:{index}")

            if (
                "component_role_binding" not in self.disabled_checks
                and binding is not None
            ):
                if receipt.stage != binding.stage:
                    reasons.append(f"E_STAGE_ORDER:{index}")
                if receipt.role != binding.role:
                    reasons.append(f"E_STAGE_ROLE:{index}")
                if receipt.signer != binding.signer_id:
                    reasons.append(f"E_UNAUTHORISED_STAGE_SIGNER:{index}")
                if receipt.contract_id != binding.contract_id:
                    reasons.append(f"E_UNAUTHORISED_STAGE_CONTRACT:{index}")
                expected_predecessor = (
                    bundle.envelopes[0].producer
                    if index == 0
                    else self.deployment.pipeline[index - 1].signer_id
                )
                if before.producer != expected_predecessor:
                    reasons.append(f"E_UNAUTHORISED_PREDECESSOR:{index}")

            actual_changes = changed_fields(before, after)
            if set(receipt.changed_fields) != actual_changes:
                reasons.append(f"E_FALSE_CHANGESET:{index}")
            expected_assumptions = tuple(
                predicate.predicate_id
                for predicate in contract.requires_predicates
            )
            expected_guarantees = tuple(
                predicate.predicate_id
                for predicate in contract.ensures_predicates
            )
            if receipt.assumption_ids != expected_assumptions:
                reasons.append(f"E_FALSE_ASSUMPTION_SET:{index}")
            if receipt.guarantee_ids != expected_guarantees:
                reasons.append(f"E_FALSE_GUARANTEE_SET:{index}")

            missing_guarantees = set(contract.requires_guarantees) - guarantees
            if missing_guarantees:
                reasons.append(
                    f"E_UNDISCHARGED_ASSUMPTION:{index}:"
                    + ",".join(sorted(missing_guarantees))
                )
            for pointer in contract.requires_fields:
                if self._path_ignored(pointer):
                    continue
                if not present(before, pointer):
                    reasons.append(f"E_REQUIRED_FIELD:{index}:{pointer}")
            for predicate in contract.requires_predicates:
                if self._predicate_disabled(predicate.predicate_id):
                    continue
                if not evaluate_envelope_predicate(predicate, before):
                    reasons.append(
                        f"E_ASSUMPTION_FALSE:{index}:{predicate.predicate_id}"
                    )

            if "contract_conformance" not in self.disabled_checks:
                changed_security = {
                    path
                    for path in actual_changes
                    if path != "/representation" and not self._path_ignored(path)
                }
                used_witnesses: set[str] = set()
                for path in sorted(changed_security):
                    if any(
                        path_within(path, preserved_root)
                        for preserved_root in contract.preserves
                        if not self._path_ignored(preserved_root)
                    ):
                        reasons.append(f"E_NOT_PRESERVED:{index}:{path}")
                        continue
                    rule = next(
                        (
                            candidate
                            for candidate in contract.transform_rules
                            if path_within(path, candidate.field_path)
                        ),
                        None,
                    )
                    if rule is None:
                        reasons.append(f"E_ILLEGAL_TRANSFORM:{index}:{path}")
                        continue
                    candidates = [
                        witness_index[witness_id]
                        for witness_id in receipt.transformation_witness_ids
                        if witness_id in witness_index
                        and witness_index[witness_id].field_path
                        == rule.field_path
                    ]
                    if rule.witness_required and not candidates:
                        reasons.append(
                            f"E_MISSING_TRANSFORM_WITNESS:{index}:{path}"
                        )
                        continue
                    if candidates:
                        witness = candidates[0]
                        used_witnesses.add(witness.witness_id)
                        self._verify_transition_witness(
                            witness,
                            before,
                            after,
                            rule,
                            receipt,
                            now,
                            reasons,
                        )
                supplied = set(receipt.transformation_witness_ids)
                unknown = supplied - set(witness_index)
                if unknown:
                    reasons.append(
                        f"E_UNKNOWN_TRANSFORM_WITNESS:{index}:"
                        + ",".join(sorted(unknown))
                    )
                unused = supplied - used_witnesses - unknown
                if unused:
                    reasons.append(
                        f"E_UNUSED_TRANSFORM_WITNESS:{index}:"
                        + ",".join(sorted(unused))
                    )

            if (
                "authority" not in self.disabled_checks
                and not after.context.authority.issubset(before.context.authority)
            ):
                reasons.append(f"E_AUTHORITY_AMPLIFICATION:{index}")
            if (
                "delegation" not in self.disabled_checks
                and not after.context.delegation_scope.issubset(
                    before.context.delegation_scope
                )
            ):
                reasons.append(f"E_DELEGATION_WIDENING:{index}")
            if (
                "taint" not in self.disabled_checks
                and after.context.taint < before.context.taint
            ):
                reasons.append(f"E_TAINT_DOWNGRADE:{index}")
            if (
                "policy" not in self.disabled_checks
                and before.context.policy_epoch is not None
                and after.context.policy_epoch is not None
                and after.context.policy_epoch < before.context.policy_epoch
            ):
                reasons.append(f"E_POLICY_DOWNGRADE:{index}")

            for pointer in contract.ensures_fields:
                if self._path_ignored(pointer):
                    continue
                if not present(after, pointer):
                    reasons.append(
                        f"E_ENSURED_FIELD_MISSING:{index}:{pointer}"
                    )
            for predicate in contract.ensures_predicates:
                if self._predicate_disabled(predicate.predicate_id):
                    continue
                if not evaluate_envelope_predicate(predicate, after):
                    reasons.append(
                        f"E_GUARANTEE_FALSE:{index}:{predicate.predicate_id}"
                    )

            if len(reasons) == stage_reason_start:
                guarantees |= set(contract.ensures_guarantees)

    def verify_bundle(self, bundle: ProofBundle, now: int) -> Decision:
        reasons: list[str] = []
        if not bundle.envelopes:
            state = self.deployment.runtime_state
            return Decision(
                allowed=False,
                reason_codes=("E_EMPTY_CHAIN",),
                bundle_digest=digest(bundle),
                action_digest="",
                principal="",
                actor="",
                task_root="",
                grant_id="",
                policy_id=state.policy_id,
                policy_digest=state.policy_digest,
                policy_epoch=state.policy_epoch,
            )

        guarantees = self._verify_root(bundle, now, reasons)
        guarantees |= self._verify_provenance(bundle, now, reasons)
        release_index = self._release_index(bundle, now, reasons)
        self._verify_releases(bundle, release_index, reasons)
        self._verify_transitions(bundle, now, guarantees, reasons)

        final = bundle.envelopes[-1]
        context = final.context
        action = final.action
        state = self.deployment.runtime_state

        if "identity" not in self.disabled_checks and not (
            context.principal
            and context.actor
            and context.task_root
            and context.root_grant_id
        ):
            reasons.append("E_IDENTITY_CONTEXT")
        if "provenance" not in self.disabled_checks and not context.provenance_root:
            reasons.append("E_PROVENANCE_CONTEXT")
        if "context_root" not in self.disabled_checks and not context.context_root:
            reasons.append("E_CONTEXT_ROOT")
        if "policy" not in self.disabled_checks and (
            context.policy_id != state.policy_id
            or context.policy_digest != state.policy_digest
            or context.policy_epoch != state.policy_epoch
        ):
            reasons.append("E_STALE_POLICY")
        if context.expires_at is None or context.expires_at < now:
            reasons.append("E_EXPIRED_CONTEXT")
        if context.nonce is None:
            reasons.append("E_MISSING_NONCE")
        if (
            "revocation" not in self.disabled_checks
            and context.root_grant_id in state.revoked_ids
        ):
            reasons.append("E_REVOKED_ROOT_GRANT")
        if (
            "authority" not in self.disabled_checks
            and action.operation not in context.authority
        ):
            reasons.append("E_OPERATION_NOT_AUTHORISED")
        action_scope = f"{action.operation}:{action.resource}"
        if (
            "delegation" not in self.disabled_checks
            and action_scope not in context.delegation_scope
            and f"{action.operation}:*" not in context.delegation_scope
        ):
            reasons.append("E_SCOPE_MISMATCH")
        if (
            "taint" not in self.disabled_checks
            and action.data_classification > context.taint
        ):
            reasons.append("E_UNTRACKED_DATA_CLASS")
        if (
            action.effect_class
            in {"EXTERNAL_WRITE", "STATE_MUTATION", "CODE_EXECUTION"}
            and not action.destination
        ):
            reasons.append("E_MISSING_DESTINATION")
        trusted_manifest = self.deployment.trusted_tool_manifests.get(
            action.tool_id
        )
        if trusted_manifest is None or trusted_manifest != action.tool_manifest_digest:
            reasons.append("E_UNTRUSTED_TOOL_MANIFEST")

        unique_reasons = tuple(sorted(set(reasons)))
        return Decision(
            allowed=not unique_reasons,
            reason_codes=unique_reasons,
            bundle_digest=digest(bundle),
            action_digest=action.action_digest,
            principal=context.principal or "",
            actor=context.actor or "",
            task_root=context.task_root or "",
            grant_id=context.root_grant_id or "",
            policy_id=state.policy_id,
            policy_digest=state.policy_digest,
            policy_epoch=state.policy_epoch,
        )

    def issue_permit(
        self, decision: Decision, final: Envelope, audience: str, now: int
    ) -> ExecutionPermit:
        if not decision.allowed:
            raise ValueError("denied decision")
        context = final.context
        if not (
            context.actor
            and context.task_root
            and context.nonce
            and context.expires_at
        ):
            raise ValueError("incomplete final context")
        permit = ExecutionPermit(
            permit_id=f"permit:{decision.action_digest[-16:]}:{context.nonce}",
            principal=decision.principal,
            subject=decision.actor,
            task_root=decision.task_root,
            grant_id=decision.grant_id,
            audience=audience,
            action_digest=decision.action_digest,
            bundle_digest=decision.bundle_digest,
            policy_id=decision.policy_id,
            policy_digest=decision.policy_digest,
            policy_epoch=decision.policy_epoch,
            nonce=context.nonce,
            idempotency_key=f"{context.task_root}:{decision.action_digest}",
            expires_at=min(context.expires_at, now + 60),
            one_time=True,
            signer=self.permit_signer.key_id,
        )
        return permit.signed(self.permit_signer)


# ---------- Finality and effects ----------

class NonceLedger:
    def __init__(self) -> None:
        self.consumed_nonces: set[str] = set()
        self.outcomes: dict[str, OutcomeReceipt] = {}


class SimulatedWorld:
    def __init__(self) -> None:
        self.effects: list[dict[str, Any]] = []

    def apply(self, action: Action) -> str:
        self.effects.append(
            {
                "ordinal": len(self.effects),
                "operation": action.operation,
                "resource": action.resource,
                "destination": action.destination,
                "parameters": dict(action.parameters),
                "effect_class": action.effect_class,
            }
        )
        return f"effect:{len(self.effects) - 1}"

    @property
    def state_digest(self) -> str:
        return digest(self.effects)


class FinalitySink:
    def __init__(
        self,
        sink_id: str,
        keyring: Keyring,
        trusted_permit_signer: str,
        signer: Signer,
        ledger: NonceLedger,
        world: SimulatedWorld,
        enforce_action_binding: bool = True,
        enforce_subject_binding: bool = True,
        enforce_policy_freshness: bool = True,
        enforce_revocation: bool = True,
        enforce_nonce: bool = True,
        enforce_idempotency: bool = True,
    ) -> None:
        self.sink_id = sink_id
        self.keyring = keyring
        self.trusted_permit_signer = trusted_permit_signer
        self.signer = signer
        self.ledger = ledger
        self.world = world
        self.enforce_action_binding = enforce_action_binding
        self.enforce_subject_binding = enforce_subject_binding
        self.enforce_policy_freshness = enforce_policy_freshness
        self.enforce_revocation = enforce_revocation
        self.enforce_nonce = enforce_nonce
        self.enforce_idempotency = enforce_idempotency

    def execute(
        self,
        action: Action,
        permit: ExecutionPermit,
        now: int,
        caller_subject: str,
        runtime_state: RuntimeState,
    ) -> tuple[bool, str, OutcomeReceipt | None]:
        if permit.signer != self.trusted_permit_signer:
            return False, "E_UNTRUSTED_PERMIT_ISSUER", None
        if not self.keyring.verify(
            permit.signer, permit.unsigned(), permit.signature
        ):
            return False, "E_BAD_PERMIT_SIGNATURE", None
        if permit.audience != self.sink_id:
            return False, "E_WRONG_AUDIENCE", None
        if self.enforce_subject_binding and permit.subject != caller_subject:
            return False, "E_SUBJECT_SUBSTITUTION", None
        if self.enforce_action_binding and permit.action_digest != action.action_digest:
            return False, "E_ACTION_SUBSTITUTION", None
        if self.enforce_policy_freshness and (
            permit.policy_id != runtime_state.policy_id
            or permit.policy_digest != runtime_state.policy_digest
            or permit.policy_epoch != runtime_state.policy_epoch
        ):
            return False, "E_STALE_PERMIT_POLICY", None
        if self.enforce_revocation and (
            permit.grant_id in runtime_state.revoked_ids
            or permit.permit_id in runtime_state.revoked_ids
        ):
            return False, "E_REVOKED_AT_FINALITY", None
        if permit.expires_at < now:
            return False, "E_EXPIRED_PERMIT", None

        previous = (
            self.ledger.outcomes.get(permit.idempotency_key)
            if self.enforce_idempotency
            else None
        )
        if previous is not None:
            return True, "IDEMPOTENT_REPLAY", previous
        if self.enforce_nonce and permit.one_time:
            if permit.nonce in self.ledger.consumed_nonces:
                return False, "E_REPLAY", None
            self.ledger.consumed_nonces.add(permit.nonce)

        effect_id = self.world.apply(action)
        outcome = OutcomeReceipt(
            effect_id=effect_id,
            permit_id=permit.permit_id,
            principal=permit.principal,
            subject=permit.subject,
            action_digest=action.action_digest,
            status="COMMITTED",
            idempotency_key=permit.idempotency_key,
            state_digest=self.world.state_digest,
            signer=self.signer.key_id,
        ).signed(self.signer)
        if self.enforce_idempotency:
            self.ledger.outcomes[permit.idempotency_key] = outcome
        return True, "EXECUTED", outcome


class EffectBroker:
    def __init__(self, sink: FinalitySink, require_permit: bool = True) -> None:
        self.sink = sink
        self.require_permit = require_permit

    def dispatch(
        self,
        action: Action,
        permit: ExecutionPermit | None,
        now: int,
        caller_subject: str,
        runtime_state: RuntimeState,
    ) -> tuple[bool, str, OutcomeReceipt | None]:
        if self.require_permit:
            if permit is None:
                return False, "E_UNMEDIATED_PATH", None
            return self.sink.execute(
                action, permit, now, caller_subject, runtime_state
            )
        effect_id = self.sink.world.apply(action)
        return True, f"BYPASS_EXECUTED:{effect_id}", None
