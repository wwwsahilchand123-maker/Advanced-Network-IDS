# Detection Rules

This directory contains the YAML detection rules used by the Advanced Network IDS rule set.

## Rule Catalog

| Rule ID | Rule | Category | Severity | Primary Signal |
|---|---|---|---|---|
| `SCAN_001` | Port Scan Detection | Reconnaissance | High | Rapid access to multiple destination ports |
| `SCAN_002` | ICMP Sweep Detection | Reconnaissance | Medium | ICMP echo requests across multiple hosts |

## Rule Lifecycle

Each rule should document:

- a stable `rule_id` and descriptive name
- category, severity, and enabled state
- MITRE ATT&CK mapping where applicable
- detection conditions and thresholds
- evidence fields for investigation
- confidence modifiers when supported
- response behavior and cooldown

## Tuning Guidance

Thresholds should be treated as environment-dependent starting points rather than universal values. Before enabling automated blocking, validate a rule against representative traffic and review false positives. Keep `alert`, `block`, `correlate`, and cooldown behavior explicit so the response policy is easy to audit.

## Adding a Rule

1. Create a new `.yaml` file using the existing rule structure as a template.
2. Assign a unique rule ID.
3. Define the detection signal and time window clearly.
4. Include the evidence required for analyst investigation.
5. Map the behavior to MITRE ATT&CK when an appropriate technique exists.
6. Add the rule to this catalog and document any tuning assumptions.
