# Security Regression Checklist

Use this checklist after changes to authentication, detection rules, packet capture, API endpoints, or incident handling. Run it in an isolated, authorized lab environment.

## Authentication and authorization

- [ ] Unauthenticated requests to protected API routes return an authorization error.
- [ ] Invalid or expired JWTs are rejected.
- [ ] Viewer accounts cannot perform analyst/admin actions.
- [ ] Admin-only operations reject lower-privileged roles.
- [ ] Secrets and tokens are absent from application logs and test output.

## Detection correctness

For every changed rule, verify both positive and negative cases:

- [ ] A representative malicious/suspicious fixture triggers the expected rule.
- [ ] Benign traffic with similar characteristics does not trigger the rule unexpectedly.
- [ ] Evidence fields contain the source, destination, timestamp, and rule-specific context needed for investigation.
- [ ] Severity and confidence remain within documented bounds.
- [ ] Repeated identical events do not create unbounded duplicate incidents.

## API and input handling

- [ ] Malformed JSON and missing required fields return controlled 4xx responses.
- [ ] Numeric limits and pagination parameters are validated.
- [ ] User-controlled strings are not interpolated into SQL, shell commands, or log formats without safe handling.
- [ ] CORS remains restricted to explicitly trusted origins.
- [ ] Error responses do not expose stack traces, secrets, or internal credentials.

## Packet and telemetry handling

- [ ] Capture is tested only on an authorized interface.
- [ ] Sensitive packet payloads are not written to logs unless required for the lab scenario.
- [ ] Stored telemetry has an appropriate retention/cleanup plan.
- [ ] Detection behavior is verified with synthetic traffic before using real network data.

## Release gate

A security-sensitive change should not be considered ready until:

```text
change → positive test → negative test → auth/input checks → review → deploy
```

Record the test date, changed rule or component, environment, and any known false-positive/false-negative trade-offs so future tuning can be compared against a reproducible baseline.