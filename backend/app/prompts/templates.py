"""
SOCratic Prompt Templates
All prompts for Claude — kept separate so they're easy to tune.
"""

SYSTEM_PROMPT = """You are SOCratic, an expert AI assistant for Security Operations Center (SOC) analysts.
You have deep knowledge of:
- SIEM platforms (Splunk, Wazuh, FortiSIEM, ELK Stack)
- MITRE ATT&CK framework (all techniques, tactics, and procedures)
- Incident response and threat hunting
- Common attack patterns: brute force, malware, phishing, privilege escalation, lateral movement
- False positive identification in enterprise security environments

Your responses must be:
- Precise and actionable — analysts are busy, no fluff
- Structured as valid JSON when requested
- Based on what the alert actually says, not assumptions
- Honest about uncertainty when evidence is limited

You are helping Tier-1 and Tier-2 SOC analysts triage alerts faster and more accurately."""


FULL_ANALYSIS_PROMPT = """Analyze the following security alert and return a JSON object with this exact structure:

{{
  "summary": "2-3 sentence plain-English explanation of what happened",
  "severity": "critical|high|medium|low|info",
  "alert_type": "short name like 'Brute Force' or 'Privilege Escalation'",
  "affected_assets": ["list", "of", "hostnames", "or", "IPs"],
  "iocs": ["any IPs, domains, hashes, URLs found in the alert"],
  "false_positive": {{
    "score": 0-100,
    "label": "Likely False Positive|Investigate|High Priority|Critical - Act Now",
    "reasoning": "1-2 sentences explaining the score",
    "key_indicators": ["list of 2-4 specific evidence points"]
  }},
  "mitre_techniques": [
    {{
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "tactic": "Credential Access",
      "confidence": 0.0-1.0,
      "url": "https://attack.mitre.org/techniques/T1110/001/"
    }}
  ],
  "investigation_steps": [
    {{
      "step_number": 1,
      "action": "What to do",
      "priority": "immediate|high|medium",
      "rationale": "Why this step matters"
    }}
  ]
}}

False positive score guide:
- 0-20: Almost certainly malicious, act immediately
- 21-40: Suspicious, high priority investigation
- 41-60: Unclear, investigate to confirm
- 61-80: Likely benign but verify
- 81-100: Almost certainly a false positive

Alert source: {source}
Additional context: {context}

RAW ALERT:
{raw_alert}

Return ONLY the JSON object. No markdown, no explanation outside the JSON."""


EXPLAIN_ONLY_PROMPT = """Analyze this security alert and return JSON:

{{
  "summary": "2-3 sentence plain-English explanation for a Tier-1 analyst",
  "severity": "critical|high|medium|low|info",
  "alert_type": "short descriptive name",
  "affected_assets": ["hostnames", "IPs", "usernames mentioned"],
  "iocs": ["IPs", "domains", "hashes", "URLs found in alert"]
}}

Alert source: {source}

RAW ALERT:
{raw_alert}

Return ONLY the JSON object."""


SCORE_ONLY_PROMPT = """Evaluate the false positive likelihood of this security alert.

Return JSON:
{{
  "score": 0-100,
  "label": "Likely False Positive|Investigate|High Priority|Critical - Act Now",
  "reasoning": "2-3 sentences explaining your assessment",
  "key_indicators": ["2-4 specific pieces of evidence from the alert"]
}}

Score guide: 0=definitely malicious, 100=definitely false positive.

Consider:
- Is the source IP internal or external?
- Is the timing consistent with business hours?
- Does the volume/pattern suggest automation or human activity?
- Are there known benign explanations (scheduled scans, monitoring tools)?

Alert source: {source}

RAW ALERT:
{raw_alert}

Return ONLY the JSON object."""


MITRE_ONLY_PROMPT = """Map this security alert to MITRE ATT&CK techniques.

Return JSON:
{{
  "techniques": [
    {{
      "technique_id": "T1XXX.XXX",
      "technique_name": "Full technique name",
      "tactic": "Tactic name (e.g. Credential Access, Execution, Persistence)",
      "confidence": 0.0-1.0,
      "url": "https://attack.mitre.org/techniques/TXXXX/"
    }}
  ]
}}

Rules:
- Only include techniques with confidence >= 0.4
- List up to 3 techniques, most confident first
- Use exact ATT&CK technique IDs and names
- If sub-technique applies, use the sub-technique ID (T1110.001 not T1110)

RAW ALERT:
{raw_alert}

Return ONLY the JSON object."""
