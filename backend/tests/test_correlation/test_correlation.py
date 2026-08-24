"""
Tests for correlation engine and risk scoring
"""
import pytest
from datetime import datetime, timedelta

from app.correlation.engine import CorrelationEngine
from app.scoring.risk_calculator import RiskCalculator
from app.correlation.attack_chains import AttackChainAnalyzer


@pytest.fixture
def risk_calculator():
    return RiskCalculator()


@pytest.fixture
def correlation_engine():
    return CorrelationEngine()


@pytest.fixture
def port_scan_alert():
    return {
        "rule_id": "SCAN_001",
        "title": "Possible Vertical Port Scan Detected",
        "description": "Port scan detected",
        "category": "reconnaissance",
        "severity": "HIGH",
        "confidence": 85,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "mitre_attack_id": "T1046",
        "timestamp": datetime.utcnow(),
        "evidence": {},
    }


@pytest.fixture
def brute_force_alert():
    return {
        "rule_id": "BRUTE_001",
        "title": "Possible Brute Force Attack on SSH",
        "description": "Brute force detected",
        "category": "credential_access",
        "severity": "HIGH",
        "confidence": 90,
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "dst_port": 22,
        "mitre_attack_id": "T1110",
        "timestamp": datetime.utcnow() + timedelta(seconds=30),
        "evidence": {},
    }


class TestRiskCalculator:
    
    def test_single_medium_alert(self, risk_calculator, port_scan_alert):
        """Test scoring a single alert"""
        result = risk_calculator.calculate([port_scan_alert])
        
        assert 0 <= result["total_score"] <= 100
        assert result["severity"] in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert "breakdown" in result
        assert "severity_base" in result["breakdown"]
        assert "confidence" in result["breakdown"]
    
    def test_multi_alert_scores_higher(self, risk_calculator, port_scan_alert, brute_force_alert):
        """Test that correlated alerts score higher"""
        single = risk_calculator.calculate([port_scan_alert])
        multi = risk_calculator.calculate([port_scan_alert, brute_force_alert])
        
        assert multi["total_score"] > single["total_score"]
    
    def test_severity_mapping(self, risk_calculator):
        """Test score to severity mapping"""
        assert risk_calculator._score_to_severity(95) == "CRITICAL"
        assert risk_calculator._score_to_severity(75) == "HIGH"
        assert risk_calculator._score_to_severity(55) == "MEDIUM"
        assert risk_calculator._score_to_severity(30) == "LOW"
        assert risk_calculator._score_to_severity(10) == "INFO"
    
    def test_transparent_breakdown(self, risk_calculator, port_scan_alert):
        """Test that score breakdown is provided"""
        result = risk_calculator.calculate([port_scan_alert])
        
        for component in result["breakdown"].values():
            assert "points" in component
            assert "max_points" in component
            assert "explanation" in component


class TestCorrelationEngine:
    
    def test_single_alert_no_incident(self, correlation_engine, port_scan_alert):
        """Test that single alert doesn't create incident"""
        incident = correlation_engine.process_alert(port_scan_alert.copy())
        
        # Single alert from one rule shouldn't create incident
        assert incident is None
    
    def test_multi_rule_creates_incident(
        self, correlation_engine, port_scan_alert, brute_force_alert
    ):
        """Test that multiple rules trigger incident creation"""
        correlation_engine.process_alert(port_scan_alert.copy())
        incident = correlation_engine.process_alert(brute_force_alert.copy())
        
        assert incident is not None
        assert incident["correlated"] is True
        assert incident["alert_count"] >= 2
        assert 0 <= incident["risk_score"] <= 100
    
    def test_incident_contains_risk_breakdown(
        self, correlation_engine, port_scan_alert, brute_force_alert
    ):
        """Test incident contains explainable risk score"""
        correlation_engine.process_alert(port_scan_alert.copy())
        incident = correlation_engine.process_alert(brute_force_alert.copy())
        
        assert "risk_breakdown" in incident
        assert "calculation_summary" in incident["risk_breakdown"] or \
               "breakdown" in incident
        
        breakdown = incident.get("risk_breakdown", {})
        if isinstance(breakdown, dict) and "breakdown" in breakdown:
            components = breakdown["breakdown"]
            assert len(components) > 0


class TestAttackChainAnalyzer:
    
    def test_recon_to_access_chain(self, port_scan_alert, brute_force_alert):
        """Test detection of recon → brute force chain"""
        analyzer = AttackChainAnalyzer()
        
        alerts = [port_scan_alert, brute_force_alert]
        result = analyzer.analyze(alerts)
        
        assert result["chain_detected"] is True
        assert result["chain_name"] == "Reconnaissance to Brute Force Attack"
        assert "reconnaissance" in result["stages"]
        assert "credential_access" in result["stages"]
        assert result["severity_boost"] > 0
    
    def test_no_chain_single_category(self, port_scan_alert):
        """Test that single-category alerts don't trigger chain"""
        analyzer = AttackChainAnalyzer()
        
        result = analyzer.analyze([port_scan_alert])
        
        assert result["chain_detected"] is False
