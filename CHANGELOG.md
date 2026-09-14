# Changelog

All notable changes to Advanced Network IDS are documented here.

## [Unreleased]

### Added
- Documented the current detection and SOC workflow.
- Clarified that detection results require analyst investigation before response.

### Security
- Packet capture is intended only for networks where monitoring is authorized.
- Runtime secrets and local database files remain excluded from version control.

## [0.1.0] - Initial portfolio release

- Packet and flow monitoring foundation.
- Detection-rule and event-correlation pipeline.
- Risk scoring and MITRE ATT&CK mapping.
- FastAPI API and React SOC dashboard.
