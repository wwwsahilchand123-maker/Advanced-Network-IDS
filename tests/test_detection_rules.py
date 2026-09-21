from pathlib import Path

import yaml


RULES_DIR = Path(__file__).resolve().parents[1] / "backend" / "detection_rules"
ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def load_documents(path):
    with path.open("r", encoding="utf-8") as handle:
        return [doc for doc in yaml.safe_load_all(handle) if doc]


def test_detection_rules_have_unique_ids_and_safe_response_defaults():
    rule_files = sorted(RULES_DIR.glob("*.yaml"))
    assert rule_files, "No detection rules found"

    rule_ids = []
    for path in rule_files:
        for rule in load_documents(path):
            assert rule.get("rule_id"), f"Missing rule_id in {path}"
            assert rule["rule_id"] not in rule_ids, f"Duplicate rule_id: {rule['rule_id']}"
            rule_ids.append(rule["rule_id"])

            assert rule.get("name"), f"Missing name in {path}"
            assert rule.get("severity") in ALLOWED_SEVERITIES, f"Invalid severity in {path}"

            response = rule.get("response", {})
            assert response.get("alert") is True, f"Rule must alert: {rule['rule_id']}"
            assert response.get("block") is not True, (
                f"Detection rules must not block automatically: {rule['rule_id']}"
            )
            assert response.get("cooldown", 0) > 0, f"Missing cooldown: {rule['rule_id']}"
