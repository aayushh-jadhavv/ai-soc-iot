"""Fail-closed Phase 1 policy for already verified, normalized packet evidence.

This is not a PCAP reader or a dataset adapter. Callers must independently verify
clock conversion, annotation interval semantics, original sessions and bindings.
All normalized intervals are half-open and integer nanoseconds.
"""

from dataclasses import dataclass
from decimal import Decimal


def timestamp_ns(value: str, unit: str, offset_ns: int = 0) -> int:
    """Explicit units only; offset is added to the source time, never guessed."""
    factors = {"s": 10**9, "ms": 10**6, "us": 10**3, "ns": 1}
    converted = Decimal(value) * factors[unit]
    if not converted.is_finite() or converted != converted.to_integral_value():
        raise ValueError("Timestamp must resolve exactly to integer nanoseconds")
    if type(offset_ns) is not int:
        raise ValueError("Offset must be integer nanoseconds")
    return int(converted) + offset_ns


@dataclass(frozen=True)
class Packet:
    packet_id: str
    session_id: str
    time_ns: int
    protocol: str
    src: str
    sport: int | None
    dst: str
    dport: int | None


@dataclass(frozen=True)
class Annotation:
    annotation_id: str
    session_id: str
    start_ns: int
    end_ns: int
    protocol: str
    src: str
    sport: int | None
    dst: str
    dport: int | None
    family: str  # benign or a canonical attack family
    verified: bool = False

    def __post_init__(self):
        if not self.session_id or self.end_ns <= self.start_ns:
            raise ValueError("Annotation needs a session and nonempty verified interval")


def match_packet(packet: Packet, annotations: list[Annotation],
                 scope=frozenset({"reconnaissance", "dos"})) -> dict:
    """Preserve both tuple orientations; never use IP/time or file labels alone."""
    hits = []
    if not packet.session_id:
        return {"label": "unknown", "reason": "missing_session", "matches": []}
    for ann in annotations:
        if (not ann.verified or packet.session_id != ann.session_id
                or packet.protocol != ann.protocol
                or not ann.start_ns <= packet.time_ns < ann.end_ns):
            continue
        forward = (packet.src, packet.sport, packet.dst, packet.dport)
        target = (ann.src, ann.sport, ann.dst, ann.dport)
        reverse = (ann.dst, ann.dport, ann.src, ann.sport)
        if forward == target or forward == reverse:
            hits.append({"annotation_id": ann.annotation_id, "family": ann.family,
                         "direction": "forward" if forward == target else "reverse"})
    families = {h["family"] for h in hits}
    if not families:
        label, reason = "unknown", "no_verified_annotation"
    elif len(families) > 1:
        label, reason = "conflict", "contradictory_annotations"
    elif families == {"benign"}:
        label, reason = "benign", "verified_normal_connection"
    elif families <= scope:
        label, reason = "attack", "verified_attack_connection"
    else:
        label, reason = "excluded", "out_of_scope_family"
    return {"label": label, "reason": reason, "matches": hits}


def final_window_label(evidence: list[dict], *, coverage_valid: bool,
                       identity_valid: bool, normal_coverage: bool) -> dict:
    """Evidence must cover only observed packets for this endpoint/final second.

Unknown traffic alongside an unambiguous in-scope attack stays positive. An
out-of-scope family excludes the window conservatively, even if mixed in-scope.
Normal coverage is an independently established complete normal-label regime.
Earlier context labels never enter this function. Victim/attacker role is absent.
"""
    labels = {e["label"] for e in evidence}
    if not labels <= {"attack", "benign", "unknown", "conflict", "excluded"}:
        raise ValueError("Unknown evidence label")
    if not coverage_valid or not identity_valid:
        label, reason = None, "invalid_coverage_or_identity"
    elif "conflict" in labels:
        label, reason = None, "annotation_conflict"
    elif "excluded" in labels:
        label, reason = None, "out_of_scope_family"
    elif "attack" in labels:
        label, reason = 1, "observed_attack_involvement"
    elif "unknown" not in labels and normal_coverage:
        label, reason = 0, "verified_normal_coverage"
    else:
        label, reason = None, "unknown_final_label"
    return {"label": label, "reason": reason,
            "mixed_unknown": "attack" in labels and "unknown" in labels,
            "endpoint_role": "not_inferred"}
