"""KEY001-KEY004 rules. Each returns zero or more findings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .model import Snapshot

ROTATION_DUE_DAYS = 90    # KEY003 window start
STALE_DAYS = 180          # KEY002 threshold


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    user: str
    key_fingerprint: str
    detail: str


def rule_orphaned_key(snapshot: Snapshot, as_of: date) -> list:
    """KEY001 HIGH: ACTIVE key on a non-ACTIVE user."""
    out = []
    for user in snapshot.users:
        if user.is_active():
            continue
        for key in user.api_keys:
            if key.is_active():
                out.append(
                    Finding(
                        rule="KEY001",
                        severity="HIGH",
                        user=user.name,
                        key_fingerprint=key.fingerprint,
                        detail=(
                            f"user lifecycle_state is {user.lifecycle_state} but the key is "
                            f"ACTIVE; a credential on a deactivated user is still usable"
                        ),
                    )
                )
    return out


def rule_stale_key(snapshot: Snapshot, as_of: date) -> list:
    """KEY002 HIGH: ACTIVE key older than STALE_DAYS."""
    out = []
    for user in snapshot.users:
        if not user.is_active():
            continue  # deactivated-user keys are KEY001's job
        for key in user.api_keys:
            if key.is_active() and key.age_days(as_of) > STALE_DAYS:
                out.append(
                    Finding(
                        rule="KEY002",
                        severity="HIGH",
                        user=user.name,
                        key_fingerprint=key.fingerprint,
                        detail=f"key is {key.age_days(as_of)} days old (> {STALE_DAYS}); rotation is overdue",
                    )
                )
    return out


def rule_rotation_due(snapshot: Snapshot, as_of: date) -> list:
    """KEY003 MEDIUM: ACTIVE key between ROTATION_DUE_DAYS and STALE_DAYS old."""
    out = []
    for user in snapshot.users:
        if not user.is_active():
            continue
        for key in user.api_keys:
            age = key.age_days(as_of)
            if key.is_active() and ROTATION_DUE_DAYS < age <= STALE_DAYS:
                out.append(
                    Finding(
                        rule="KEY003",
                        severity="MEDIUM",
                        user=user.name,
                        key_fingerprint=key.fingerprint,
                        detail=f"key is {age} days old; inside the {ROTATION_DUE_DAYS}-{STALE_DAYS} day rotation window",
                    )
                )
    return out


def rule_undocumented_key(snapshot: Snapshot, as_of: date) -> list:
    """KEY004 LOW: ACTIVE key with no description metadata."""
    del as_of  # rule is age-independent; signature kept uniform
    out = []
    for user in snapshot.users:
        for key in user.api_keys:
            if key.is_active() and not key.description.strip():
                out.append(
                    Finding(
                        rule="KEY004",
                        severity="LOW",
                        user=user.name,
                        key_fingerprint=key.fingerprint,
                        detail="key has no description; nobody can tell what it is for or who owns it",
                    )
                )
    return out


ALL_RULES = (
    rule_orphaned_key,
    rule_stale_key,
    rule_rotation_due,
    rule_undocumented_key,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(snapshot: Snapshot, as_of: date) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(snapshot, as_of))
    findings.sort(key=lambda f: (_SEVERITY_RANK[f.severity], f.rule, f.user, f.key_fingerprint))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
