# Detection Notes

Detection rules are heuristic indicators and should be validated against the monitored environment.

## ICMP Sweep

An ICMP sweep can indicate host discovery when one source probes many destinations within a short time window. Benign causes include monitoring systems, asset discovery and troubleshooting tools.

## Analyst Workflow

1. Review the alert timestamp and source/destination addresses.
2. Check related events within the correlation window.
3. Identify whether the source is an approved scanner or monitoring host.
4. Correlate with authentication, DNS and flow telemetry where available.
5. Record the investigation result before taking any response action.
