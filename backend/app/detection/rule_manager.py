"""
Detection Rule Manager
Loads and manages detection rules
"""
from typing import Dict, List, Optional
from pathlib import Path
import yaml

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.rule import DetectionRule

logger = get_logger(__name__)


class RuleManager:
    """
    Manages detection rules
    """
    
    def __init__(self):
        """Initialize rule manager"""
        self.rules: Dict[str, DetectionRule] = {}
    
    def load_rules_from_directory(self, rules_dir: str) -> int:
        """
        Load rules from YAML files in directory
        
        Args:
            rules_dir: Directory containing rule files
            
        Returns:
            Number of rules loaded
        """
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            logger.warning(f"Rules directory not found: {rules_dir}")
            return 0
        
        count = 0
        
        for rule_file in rules_path.glob("*.yaml"):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    
                    rule = self._create_rule_from_dict(rule_data)
                    self.rules[rule.rule_id] = rule
                    count += 1
                    
                    logger.debug(f"Loaded rule: {rule.rule_id}")
            
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")
        
        logger.info(f"Loaded {count} rules from {rules_dir}")
        return count
    
    def load_rules_from_database(self, db: Session) -> int:
        """
        Load rules from database
        
        Args:
            db: Database session
            
        Returns:
            Number of rules loaded
        """
        try:
            db_rules = db.query(DetectionRule).all()
            
            for rule in db_rules:
                self.rules[rule.rule_id] = rule
            
            logger.info(f"Loaded {len(db_rules)} rules from database")
            return len(db_rules)
        
        except Exception as e:
            logger.error(f"Error loading rules from database: {e}")
            return 0
    
    def _create_rule_from_dict(self, rule_data: dict) -> DetectionRule:
        """
        Create DetectionRule object from dictionary
        
        Args:
            rule_data: Rule data from YAML
            
        Returns:
            DetectionRule object
        """
        # Extract MITRE ATT&CK information
        mitre = rule_data.get("mitre_attack", {})
        
        rule = DetectionRule(
            rule_id=rule_data["rule_id"],
            name=rule_data["name"],
            description=rule_data.get("description"),
            category=rule_data.get("category"),
            severity=rule_data.get("severity", "MEDIUM"),
            enabled=rule_data.get("enabled", True),
            threshold_config=rule_data.get("detection_logic", {}).get("conditions"),
            cooldown_seconds=rule_data.get("response", {}).get("cooldown", 300),
            mitre_attack_id=mitre.get("technique"),
            mitre_technique=mitre.get("technique_name"),
            detection_logic=str(rule_data.get("detection_logic"))
        )
        
        return rule
    
    def get_rule(self, rule_id: str) -> Optional[DetectionRule]:
        """
        Get rule by ID
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            DetectionRule or None
        """
        return self.rules.get(rule_id)
    
    def enable_rule(self, rule_id: str) -> bool:
        """
        Enable a rule
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            True if successful
        """
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = True
            logger.info(f"Enabled rule: {rule_id}")
            return True
        return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """
        Disable a rule
        
        Args:
            rule_id: Rule identifier
            
        Returns:
            True if successful
        """
        rule = self.rules.get(rule_id)
        if rule:
            rule.enabled = False
            logger.info(f"Disabled rule: {rule_id}")
            return True
        return False
    
    def get_rules_by_category(self, category: str) -> List[DetectionRule]:
        """
        Get all rules in a category
        
        Args:
            category: Rule category
            
        Returns:
            List of rules
        """
        return [
            rule for rule in self.rules.values()
            if rule.category == category
        ]
    
    def get_enabled_rules(self) -> List[DetectionRule]:
        """
        Get all enabled rules
        
        Returns:
            List of enabled rules
        """
        return [rule for rule in self.rules.values() if rule.enabled]
