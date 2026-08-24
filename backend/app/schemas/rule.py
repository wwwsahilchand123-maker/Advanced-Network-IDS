"""
Pydantic schemas for Detection Rule
"""
from typing import Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel


class DetectionRuleBase(BaseModel):
    """Base detection rule schema"""
    rule_id: str
    name: str
    description: Optional[str] = None
    category: Optional[str] = None
    severity: str
    enabled: bool = True
    threshold_config: Optional[Dict[str, Any]] = None
    cooldown_seconds: int = 300
    mitre_attack_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    detection_logic: Optional[str] = None


class DetectionRuleCreate(DetectionRuleBase):
    """Schema for creating a detection rule"""
    pass


class DetectionRuleUpdate(BaseModel):
    """Schema for updating a detection rule"""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    threshold_config: Optional[Dict[str, Any]] = None
    cooldown_seconds: Optional[int] = None
    severity: Optional[str] = None


class DetectionRuleInDBBase(DetectionRuleBase):
    """Base schema for detection rule in database"""
    id: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class DetectionRule(DetectionRuleInDBBase):
    """Schema for detection rule response"""
    pass


class DetectionRuleStats(BaseModel):
    """Detection rule statistics"""
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    by_category: Dict[str, int]
    by_severity: Dict[str, int]
