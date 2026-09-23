# Detection Pipeline Guide

## Pipeline
1. Collect network telemetry.
2. Normalize fields into a predictable event shape.
3. Apply validation before rule evaluation.
4. Run detection rules against the normalized event.
5. Attach rule metadata, severity, and evidence.
6. Emit an alert without exposing unnecessary sensitive payload data.

## Rule design
Rules should be explicit about the fields they require and should fail safely when optional telemetry is missing. Detection logic should avoid executing attacker-controlled strings as code.

## Testing
Every detection rule should have:
- a positive case that must alert;
- a negative case that must not alert;
- malformed-input coverage;
- metadata validation.

## Review
Changes to detection logic should be reviewed for false positives, false negatives, input handling, and logging behavior before release.
