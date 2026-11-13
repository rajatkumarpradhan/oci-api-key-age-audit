# oci-api-key-age-audit

**Category: custom portfolio tool.** Pure Python command-line auditor. It does **not** wire any
built-in OCI services together - it is the *custom* project in its daily pair (the built-in
services project is `oci-ootb-vulnerability-scan-triage`).

## The problem

OCI IAM users authenticate SDK/CLI calls with **API signing keys**. Keys that are never rotated,
or that stay `ACTIVE` on a user who was deactivated, are a quiet security hole: a leaked old PEM
keeps working until someone explicitly deletes the key. This tool reads an **offline inventory
snapshot** of users and their API keys and flags the keys that need attention, so a reviewer can
prioritise cleanup instead of eyeballing the Console user by user.

## What it does

Reads a JSON snapshot (schema below, synthetic samples included) and applies four rules:

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| KEY001 | HIGH | An `ACTIVE` API key belongs to a user whose lifecycle state is not `ACTIVE` (deactivated/disabled user, live credential). |
| KEY002 | HIGH | An `ACTIVE` key is older than 180 days (long past any sane rotation window). |
| KEY003 | MEDIUM | An `ACTIVE` key is 91-180 days old (rotation due). |
| KEY004 | LOW | An `ACTIVE` key has no description/owner metadata (nobody can say what it is for). |

Exit code: `2` if any HIGH finding, `1` if only MEDIUM/LOW, `0` when clean - so it drops into
cron or a CI gate directly.

## Run it

```bash
python -m apikey_audit.cli samples/users_messy.json --as-of 2026-11-14   # exits 2, all 4 rules fire
python -m apikey_audit.cli samples/users_clean.json --as-of 2026-11-14   # exits 0
```

`--as-of` fixes the reference date so runs are reproducible; omit it to use today (UTC).

## Test it

```bash
python -m unittest discover -s tests -v   # 20 tests, stdlib only
```

## Snapshot schema

```json
{
  "users": [
    {
      "ocid": "ocid1.user.oc1..aaa",
      "name": "svc-ci-publisher",
      "lifecycle_state": "ACTIVE",
      "api_keys": [
        {"ocid": "ocid1.apikey.oc1..k1", "fingerprint": "aa:bb:...",
         "state": "ACTIVE", "created_at": "2025-11-01", "description": "ci runner"}
      ]
    }
  ]
}
```

## Honest limits

- **Offline only**: the snapshot is synthetic and hand-authored. Nothing here calls the OCI IAM
  API, enumerates a tenancy, or touches live credentials. Wiring a real `oci iam user list-api-keys`
  export is future work; the rule engine would not change.
- Age thresholds (90/180 days) are common-sense defaults, not an OCI-enforced policy; make them
  CLI flags before adopting this in a real review process.
- Key *usage* (last-used time) is not modeled because the synthetic schema has no telemetry; a
  key can be old and still daily-used - findings are review candidates, not deletion orders.
- KEY001 keys on deactivated users are candidates for review, not proof they should be deleted.

## Project status

Built as a daily portfolio project. 20 unit tests, all green locally and in CI
(`.github/workflows/ci.yml`, Python 3.10/3.11/3.12). No paid services, no live cloud calls.
