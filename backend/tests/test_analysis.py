"""
Tests for SOCratic analysis endpoints.
Run with: pytest tests/ -v
"""
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
from app.main import app

client = TestClient(app)


# ── Sample alerts for testing ─────────────────────────────────────────────────

BRUTE_FORCE_ALERT = """
{
  "rule": {"level": 10, "description": "Multiple authentication failures", "id": "5503"},
  "agent": {"name": "web-server-01", "ip": "10.0.0.50"},
  "data": {
    "srcip": "203.0.113.42",
    "dstuser": "admin",
    "program_name": "sshd"
  },
  "full_log": "sshd: Failed password for admin from 203.0.113.42 port 4521 ssh2 (x47 in 60s)"
}
"""

PRIVILEGE_ESCALATION_ALERT = """
Aug 15 03:22:11 prod-server sudo: unknown user: hacker; TTY=pts/0; PWD=/tmp; USER=root
Aug 15 03:22:13 prod-server su: pam_unix(su:auth): authentication failure; logname=www-data uid=33
Aug 15 03:22:15 prod-server sudo: www-data : command not allowed ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash
"""


def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "SOCratic"


def test_analyze_requires_alert():
    response = client.post("/api/v1/analyze", json={"raw_alert": ""})
    assert response.status_code == 422  # Validation error — min_length not met


def test_explain_requires_alert():
    response = client.post("/api/v1/explain", json={"raw_alert": "x"})
    assert response.status_code == 422  # min_length=10


@patch("app.services.analysis.anthropic.Anthropic")
def test_analyze_brute_force(mock_anthropic):
    """Test full analysis with a mocked Claude response."""
    mock_response = MagicMock()
    mock_response.content = [MagicMock(text='''{
        "summary": "Multiple SSH authentication failures detected from external IP 203.0.113.42 targeting the admin account on web-server-01. This pattern is consistent with an automated brute force attack.",
        "severity": "high",
        "alert_type": "Brute Force - SSH",
        "affected_assets": ["web-server-01", "10.0.0.50"],
        "iocs": ["203.0.113.42"],
        "false_positive": {
            "score": 15,
            "label": "High Priority",
            "reasoning": "47 failures in 60 seconds from a single external IP targeting a privileged account is a strong brute force indicator.",
            "key_indicators": ["47 failures in 60 seconds", "External IP", "Targeting admin account", "SSH service"]
        },
        "mitre_techniques": [{
            "technique_id": "T1110.001",
            "technique_name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "confidence": 0.95,
            "url": "https://attack.mitre.org/techniques/T1110/001/"
        }],
        "investigation_steps": [
            {"step_number": 1, "action": "Block source IP 203.0.113.42 at perimeter firewall", "priority": "immediate", "rationale": "Stop the active attack"},
            {"step_number": 2, "action": "Check if admin account was locked out or compromised", "priority": "immediate", "rationale": "Determine if attack succeeded"},
            {"step_number": 3, "action": "Review successful logins from same IP in the last 24h", "priority": "high", "rationale": "Check for prior successful authentication"}
        ]
    }''')]
    mock_anthropic.return_value.messages.create.return_value = mock_response

    response = client.post("/api/v1/analyze", json={
        "raw_alert": BRUTE_FORCE_ALERT,
        "source": "wazuh"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["severity"] == "high"
    assert data["false_positive"]["score"] == 15
    assert len(data["mitre_techniques"]) == 1
    assert data["mitre_techniques"][0]["technique_id"] == "T1110.001"
    assert "203.0.113.42" in data["iocs"]


def test_score_endpoint_structure():
    """Test that score endpoint returns correct shape (mocked)."""
    with patch("app.services.analysis.anthropic.Anthropic") as mock_anthropic:
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text='''{
            "score": 75,
            "label": "Likely False Positive",
            "reasoning": "Internal IP performing scheduled vulnerability scan.",
            "key_indicators": ["Internal source IP", "Known scan tool signature", "Business hours"]
        }''')]
        mock_anthropic.return_value.messages.create.return_value = mock_response

        response = client.post("/api/v1/score", json={"raw_alert": BRUTE_FORCE_ALERT})
        assert response.status_code == 200
        data = response.json()
        assert "false_positive" in data
        assert 0 <= data["false_positive"]["score"] <= 100
