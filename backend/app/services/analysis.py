import json
from app.core.config import get_settings
from app.models.schemas import (
    AlertAnalysisRequest, AlertAnalysisResponse,
    ExplainRequest, ExplainResponse,
    ScoreRequest, ScoreResponse,
    MitreRequest, MitreResponse,
    FalsePositiveScore, MitreTechnique, InvestigationStep,
    Severity,
)
from app.prompts.templates import (
    SYSTEM_PROMPT, FULL_ANALYSIS_PROMPT,
    EXPLAIN_ONLY_PROMPT, SCORE_ONLY_PROMPT, MITRE_ONLY_PROMPT,
)


class AnalysisService:
    def __init__(self):
        self.settings = get_settings()
        self.provider = self.settings.ai_provider

        if self.provider == "groq":
            from groq import Groq
            self.client = Groq(api_key=self.settings.groq_api_key)
            self.model = self.settings.groq_model
        else:
            import anthropic
            self.client = anthropic.Anthropic(api_key=self.settings.anthropic_api_key)
            self.model = self.settings.anthropic_model

    def _call_ai(self, prompt: str, max_tokens: int = 1500) -> dict:
        if self.provider == "groq":
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.1,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            )
            raw = response.choices[0].message.content.strip()
        else:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = message.content[0].text.strip()

        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1] if len(parts) > 1 else raw
            if raw.startswith("json"):
                raw = raw[4:]
        return json.loads(raw.strip())

    def analyze(self, request: AlertAnalysisRequest) -> AlertAnalysisResponse:
        prompt = FULL_ANALYSIS_PROMPT.format(
            raw_alert=request.raw_alert,
            source=request.source.value,
            context=request.additional_context or "None provided",
        )
        data = self._call_ai(prompt, max_tokens=2000)
        mitre = [
            MitreTechnique(
                technique_id=t["technique_id"],
                technique_name=t["technique_name"],
                tactic=t["tactic"],
                confidence=float(t["confidence"]),
                url=t.get("url", f"https://attack.mitre.org/techniques/{t['technique_id'].replace('.', '/')}/"),
            )
            for t in data.get("mitre_techniques", [])
        ]
        steps = [
            InvestigationStep(
                step_number=s["step_number"],
                action=s["action"],
                priority=s.get("priority", "medium"),
                rationale=s["rationale"],
            )
            for s in data.get("investigation_steps", [])
        ]
        fp_data = data.get("false_positive", {})
        fp = FalsePositiveScore(
            score=int(fp_data.get("score", 50)),
            label=fp_data.get("label", "Investigate"),
            reasoning=fp_data.get("reasoning", ""),
            key_indicators=fp_data.get("key_indicators", []),
        )
        return AlertAnalysisResponse(
            summary=data["summary"],
            severity=Severity(data.get("severity", "medium")),
            false_positive=fp,
            mitre_techniques=mitre,
            investigation_steps=steps,
            alert_type=data.get("alert_type", "Unknown"),
            affected_assets=data.get("affected_assets", []),
            iocs=data.get("iocs", []),
            source=request.source,
            model_used=self.model,
        )

    def explain(self, request: ExplainRequest) -> ExplainResponse:
        prompt = EXPLAIN_ONLY_PROMPT.format(
            raw_alert=request.raw_alert, source=request.source.value)
        data = self._call_ai(prompt, max_tokens=800)
        return ExplainResponse(
            summary=data["summary"],
            severity=Severity(data.get("severity", "medium")),
            alert_type=data.get("alert_type", "Unknown"),
            affected_assets=data.get("affected_assets", []),
            iocs=data.get("iocs", []),
            model_used=self.model,
        )

    def score(self, request: ScoreRequest) -> ScoreResponse:
        prompt = SCORE_ONLY_PROMPT.format(
            raw_alert=request.raw_alert, source=request.source.value)
        data = self._call_ai(prompt, max_tokens=600)
        fp = FalsePositiveScore(
            score=int(data.get("score", 50)),
            label=data.get("label", "Investigate"),
            reasoning=data.get("reasoning", ""),
            key_indicators=data.get("key_indicators", []),
        )
        return ScoreResponse(false_positive=fp, model_used=self.model)

    def map_mitre(self, request: MitreRequest) -> MitreResponse:
        prompt = MITRE_ONLY_PROMPT.format(raw_alert=request.raw_alert)
        data = self._call_ai(prompt, max_tokens=800)
        techniques = [
            MitreTechnique(
                technique_id=t["technique_id"],
                technique_name=t["technique_name"],
                tactic=t["tactic"],
                confidence=float(t["confidence"]),
                url=t.get("url", f"https://attack.mitre.org/techniques/{t['technique_id'].replace('.', '/')}/"),
            )
            for t in data.get("techniques", [])
        ]
        return MitreResponse(techniques=techniques, model_used=self.model)