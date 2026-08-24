"""
IDS Simulation Script
Generates realistic test alerts, incidents, and network events in real-time
"""
import sys
import os
import time
import random
import uuid
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.db.session import SessionLocal
from app.db.base import Base
from app.models.alert import Alert
from app.models.rule import DetectionRule
from app.models.incident import Incident
from app.models.user import User

TEST_SCENARIOS = [
    {
        "title": "SYN Flood Attack Detected",
        "description": "High volume of SYN packets without ACK from single source (DoS signature)",
        "severity": "CRITICAL",
        "category": "DDOS",
        "src_ip": "192.168.1.105",
        "dst_ip": "192.168.1.1",
        "src_port": 51234,
        "dst_port": 80,
        "protocol": "TCP",
        "confidence": 95,
        "mitre_attack_id": "T1498"
    },
    {
        "title": "Port Scan Activity (Nmap)",
        "description": "Sequential port connection attempts across 100+ ports",
        "severity": "HIGH",
        "category": "RECONNAISSANCE",
        "src_ip": "10.0.0.45",
        "dst_ip": "192.168.1.50",
        "src_port": 54321,
        "dst_port": 22,
        "protocol": "TCP",
        "confidence": 90,
        "mitre_attack_id": "T1046"
    },
    {
        "title": "SSH Brute Force Attempt",
        "description": "Multiple failed SSH authentication attempts (15 failures/min)",
        "severity": "HIGH",
        "category": "BRUTE_FORCE",
        "src_ip": "203.0.113.88",
        "dst_ip": "192.168.1.20",
        "src_port": 49152,
        "dst_port": 22,
        "protocol": "TCP",
        "confidence": 88,
        "mitre_attack_id": "T1110"
    },
    {
        "title": "Suspicious DNS Tunneling Query",
        "description": "High entropy TXT record query exceeding standard length",
        "severity": "MEDIUM",
        "category": "EXFILTRATION",
        "src_ip": "192.168.1.14",
        "dst_ip": "8.8.8.8",
        "src_port": 53535,
        "dst_port": 53,
        "protocol": "UDP",
        "confidence": 75,
        "mitre_attack_id": "T1071"
    },
    {
        "title": "Potential SQL Injection Payload",
        "description": "HTTP GET request containing SQL union select pattern",
        "severity": "HIGH",
        "category": "WEB_ATTACK",
        "src_ip": "198.51.100.23",
        "dst_ip": "192.168.1.10",
        "src_port": 38291,
        "dst_port": 443,
        "protocol": "TCP",
        "confidence": 92,
        "mitre_attack_id": "T1190"
    }
]

def generate_simulation(count=5):
    print("=" * 60)
    print("ADVANCED IDS - TEST TRAFFIC & ALERT SIMULATOR")
    print("=" * 60)
    db = SessionLocal()
    
    try:
        for i in range(count):
            scenario = random.choice(TEST_SCENARIOS)
            alert = Alert(
                alert_uuid=str(uuid.uuid4()),
                title=scenario["title"],
                description=scenario["description"],
                severity=scenario["severity"],
                category=scenario["category"],
                src_ip=scenario["src_ip"],
                dst_ip=scenario["dst_ip"],
                src_port=scenario["src_port"],
                dst_port=scenario["dst_port"],
                protocol=scenario["protocol"],
                confidence=scenario["confidence"],
                mitre_attack_id=scenario["mitre_attack_id"],
                status="new",
                timestamp=datetime.utcnow()
            )
            db.add(alert)
            db.commit()
            db.refresh(alert)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] [+] Generated Alert: {alert.title} | Severity: {alert.severity}")
            time.sleep(0.3)
        
        print("\nSimulation complete! Check the Dashboard and Alerts page in your browser.")
    finally:
        db.close()

if __name__ == "__main__":
    generate_simulation(6)
