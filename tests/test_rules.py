import unittest
from datetime import date

from apikey_audit.model import ApiKey, Snapshot, User
from apikey_audit.rules import (
    exit_code,
    rule_orphaned_key,
    rule_rotation_due,
    rule_stale_key,
    rule_undocumented_key,
    run_all,
)

AS_OF = date(2026, 11, 14)


def make_key(days_old, state="ACTIVE", description="owner noted"):
    from datetime import timedelta

    return ApiKey(
        ocid="ocid1.apikey.oc1..x",
        fingerprint="ff:ee:dd:cc",
        state=state,
        created_at=AS_OF - timedelta(days=days_old),
        description=description,
    )


def make_user(state="ACTIVE", keys=()):
    return User(ocid="ocid1.user.oc1..x", name="u.example", lifecycle_state=state, api_keys=tuple(keys))


class TestKey001OrphanedKey(unittest.TestCase):
    def test_fires_on_active_key_of_inactive_user(self):
        snap = Snapshot(users=(make_user("INACTIVE", [make_key(10)]),))
        findings = rule_orphaned_key(snap, AS_OF)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].rule, "KEY001")

    def test_ignores_inactive_key_of_inactive_user(self):
        snap = Snapshot(users=(make_user("INACTIVE", [make_key(10, state="INACTIVE")]),))
        self.assertEqual(rule_orphaned_key(snap, AS_OF), [])

    def test_ignores_active_user(self):
        snap = Snapshot(users=(make_user("ACTIVE", [make_key(400)]),))
        self.assertEqual(rule_orphaned_key(snap, AS_OF), [])


class TestKey002StaleKey(unittest.TestCase):
    def test_fires_over_180_days(self):
        snap = Snapshot(users=(make_user(keys=[make_key(181)]),))
        self.assertEqual(len(rule_stale_key(snap, AS_OF)), 1)

    def test_boundary_180_days_does_not_fire(self):
        snap = Snapshot(users=(make_user(keys=[make_key(180)]),))
        self.assertEqual(rule_stale_key(snap, AS_OF), [])

    def test_skips_inactive_users(self):
        snap = Snapshot(users=(make_user("INACTIVE", [make_key(400)]),))
        self.assertEqual(rule_stale_key(snap, AS_OF), [])


class TestKey003RotationDue(unittest.TestCase):
    def test_fires_in_window(self):
        snap = Snapshot(users=(make_user(keys=[make_key(120)]),))
        findings = rule_rotation_due(snap, AS_OF)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_boundary_90_days_does_not_fire(self):
        snap = Snapshot(users=(make_user(keys=[make_key(90)]),))
        self.assertEqual(rule_rotation_due(snap, AS_OF), [])

    def test_over_180_is_key002_not_key003(self):
        snap = Snapshot(users=(make_user(keys=[make_key(365)]),))
        self.assertEqual(rule_rotation_due(snap, AS_OF), [])


class TestKey004Undocumented(unittest.TestCase):
    def test_fires_on_blank_description(self):
        snap = Snapshot(users=(make_user(keys=[make_key(10, description="  ")]),))
        self.assertEqual(len(rule_undocumented_key(snap, AS_OF)), 1)

    def test_ignores_documented_key(self):
        snap = Snapshot(users=(make_user(keys=[make_key(10)]),))
        self.assertEqual(rule_undocumented_key(snap, AS_OF), [])


class TestAggregation(unittest.TestCase):
    def test_exit_code_2_on_high(self):
        snap = Snapshot(users=(make_user("INACTIVE", [make_key(10)]),))
        self.assertEqual(exit_code(run_all(snap, AS_OF)), 2)

    def test_exit_code_1_on_medium_only(self):
        snap = Snapshot(users=(make_user(keys=[make_key(120)]),))
        self.assertEqual(exit_code(run_all(snap, AS_OF)), 1)

    def test_exit_code_0_when_clean(self):
        snap = Snapshot(users=(make_user(keys=[make_key(10)]),))
        self.assertEqual(exit_code(run_all(snap, AS_OF)), 0)

    def test_findings_sorted_high_first(self):
        snap = Snapshot(
            users=(
                make_user(keys=[make_key(120)]),                       # KEY003 MEDIUM
                make_user("INACTIVE", [make_key(10, "ACTIVE", "x")]),  # KEY001 HIGH
            )
        )
        findings = run_all(snap, AS_OF)
        self.assertEqual(findings[0].severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
