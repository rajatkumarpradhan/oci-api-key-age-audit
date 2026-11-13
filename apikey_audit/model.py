"""Data model + snapshot loading for the API-key age audit."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime


class SnapshotError(ValueError):
    """Raised when a snapshot file is malformed."""


def parse_date(value: str, what: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError) as exc:
        raise SnapshotError(f"invalid date for {what}: {value!r} (expected YYYY-MM-DD)") from exc


@dataclass(frozen=True)
class ApiKey:
    ocid: str
    fingerprint: str
    state: str
    created_at: date
    description: str = ""

    def is_active(self) -> bool:
        return self.state.upper() == "ACTIVE"

    def age_days(self, as_of: date) -> int:
        return (as_of - self.created_at).days


@dataclass(frozen=True)
class User:
    ocid: str
    name: str
    lifecycle_state: str
    api_keys: tuple = field(default_factory=tuple)

    def is_active(self) -> bool:
        return self.lifecycle_state.upper() == "ACTIVE"


@dataclass(frozen=True)
class Snapshot:
    users: tuple


def load_snapshot(path: str) -> Snapshot:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise SnapshotError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("users"), list):
        raise SnapshotError(f"{path}: top level must be an object with a 'users' list")
    users = []
    for i, u in enumerate(raw["users"]):
        where = f"users[{i}]"
        for req in ("ocid", "name", "lifecycle_state"):
            if req not in u:
                raise SnapshotError(f"{where}: missing required field {req!r}")
        keys = []
        for j, k in enumerate(u.get("api_keys", [])):
            kwhere = f"{where}.api_keys[{j}]"
            for req in ("ocid", "fingerprint", "state", "created_at"):
                if req not in k:
                    raise SnapshotError(f"{kwhere}: missing required field {req!r}")
            keys.append(
                ApiKey(
                    ocid=k["ocid"],
                    fingerprint=k["fingerprint"],
                    state=k["state"],
                    created_at=parse_date(k["created_at"], f"{kwhere}.created_at"),
                    description=k.get("description", "") or "",
                )
            )
        users.append(
            User(
                ocid=u["ocid"],
                name=u["name"],
                lifecycle_state=u["lifecycle_state"],
                api_keys=tuple(keys),
            )
        )
    return Snapshot(users=tuple(users))
