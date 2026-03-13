from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertSource(str, Enum):
    WAZUH = "wazuh"
    SPLUNK = "splunk"
    ELK = "elk"
    FORTISIEM = "fortisiem"
    MANUAL = "manual"


# ── Request Models ────────────────────────────────────────────────────────────

class AlertAnalysisRequest(BaseModel):
    raw_alert: str = Field(
        ...,
        description="Raw alert text or JSON from your SIEM",
        min_length=10,
        examples=[
            '{"rule":{"level":10,"description":"Multiple authentication failures"},"agent":{"name":"web-server-01"},"data":{"srcip":"192.168.1.100"}}'
        ]
    )
    source: AlertSource = Field(
        default=AlertSource.MANUAL,
        description="Which SIEM this alert came from"
    )
    additional_context: Optional[str] = Field(
        default=None,
        description="Any extra context about your environment"
    )


class ExplainRequest(BaseModel):
    raw_alert: str = Field(..., min_length=10)
    source: AlertSource = AlertSource.MANUAL


class ScoreRequest(BaseModel):
    raw_alert: str = Field(..., min_length=10)
    source: AlertSource = AlertSource.MANUAL


class MitreRequest(BaseModel):
    raw_alert: str = Field(..., min_length=10)


# ── Response Models ───────────────────────────────────────────────────────────

class MitreTechnique(BaseModel):
    technique_id: str = Field(examples=["T1110.001"])
    technique_name: str = Field(examples=["Brute Force: Password Guessing"])
    tactic: str = Field(examples=["Credential Access"])
    confidence: float = Field(ge=0.0, le=1.0)
    url: str = Field(examples=["https://attack.mitre.org/techniques/T1110/001/"])


class InvestigationStep(BaseModel):
    step_number: int
    action: str
    priority: str = Field(examples=["immediate", "high", "medium"])
    rationale: str


class FalsePositiveScore(BaseModel):
    score: int = Field(ge=0, le=100, description="0=definitely malicious, 100=definitely FP")
    label: str = Field(examples=["Likely False Positive", "Investigate", "High Priority"])
    reasoning: str
    key_indicators: list[str]


class AlertAnalysisResponse(BaseModel):
    # Core fields
    summary: str = Field(description="Plain-English one-paragraph explanation")
    severity: Severity
    false_positive: FalsePositiveScore
    mitre_techniques: list[MitreTechnique]
    investigation_steps: list[InvestigationStep]

    # Metadata
    alert_type: str = Field(examples=["Brute Force", "Malware", "Privilege Escalation"])
    affected_assets: list[str] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list, description="IPs, domains, hashes found")

    # Source tracking
    source: AlertSource
    model_used: str


class ExplainResponse(BaseModel):
    summary: str
    severity: Severity
    alert_type: str
    affected_assets: list[str]
    iocs: list[str]
    model_used: str


class ScoreResponse(BaseModel):
    false_positive: FalsePositiveScore
    model_used: str


class MitreResponse(BaseModel):
    techniques: list[MitreTechnique]
    model_used: str


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    model: str
