# Detection Rule Authoring Guide

Detection rules live under `backend/detection_rules/` and use YAML so detection logic can be reviewed and tuned without changing application code.

## Required Sections

Each rule should define:

- `rule_id` — stable unique identifier.
- `name` — concise detection name.
- `description` — behavior the rule is intended to detect.
- `category` — detection category such as `reconnaissance`.
- `severity` — operational severity (`LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`).
- `enabled` — whether the rule is active.
- `mitre_attack` — ATT&CK tactic and technique mapping when applicable.
- `detection_logic` — threshold or other supported logic.
- `evidence_collection` — fields retained for investigation.
- `confidence_calculation` — base confidence and behavioral modifiers.
- `response` — alert, correlation, blocking, and cooldown behavior.

## Safe Authoring Checklist

1. Give every rule a unique `rule_id`.
2. Keep thresholds explicit and document the time window where applicable.
3. Collect enough evidence for an analyst to investigate the alert.
4. Prefer `block: false` for new rules until false-positive behavior is validated.
5. Add MITRE ATT&CK mapping only when the technique matches the observed behavior.
6. Tune thresholds against the monitored environment rather than assuming one network baseline.
7. Validate the YAML before enabling a new rule in production-like environments.

## Existing Examples

- `port_scan.yaml` — TCP SYN port-scan detection.
- `icmp_sweep.yaml` — ICMP host-discovery sweep detection.
- `arp_spoofing.yaml` — ARP spoofing detection.
- `dns_anomaly.yaml` — DNS anomaly detection.

Detection rules are indicators, not proof of compromise. Alerts should be correlated with other telemetry and investigated before taking response actions.