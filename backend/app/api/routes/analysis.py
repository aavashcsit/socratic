from fastapi import APIRouter, HTTPException, Depends
from app.models.schemas import (
    AlertAnalysisRequest, AlertAnalysisResponse,
    ExplainRequest, ExplainResponse,
    ScoreRequest, ScoreResponse,
    MitreRequest, MitreResponse,
)
from app.services.analysis import AnalysisService

router = APIRouter(prefix="/api/v1", tags=["Analysis"])


def get_service() -> AnalysisService:
    return AnalysisService()


@router.post(
    "/analyze",
    response_model=AlertAnalysisResponse,
    summary="Full alert analysis",
    description="Complete analysis: explanation, false positive score, MITRE mapping, and investigation steps."
)
def analyze_alert(
    request: AlertAnalysisRequest,
    service: AnalysisService = Depends(get_service)
):
    try:
        return service.analyze(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post(
    "/explain",
    response_model=ExplainResponse,
    summary="Explain alert in plain English",
    description="Get a plain-English explanation of what the alert means."
)
def explain_alert(
    request: ExplainRequest,
    service: AnalysisService = Depends(get_service)
):
    try:
        return service.explain(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")


@router.post(
    "/score",
    response_model=ScoreResponse,
    summary="Score false positive likelihood",
    description="Get a 0-100 false positive probability score with reasoning."
)
def score_alert(
    request: ScoreRequest,
    service: AnalysisService = Depends(get_service)
):
    try:
        return service.score(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scoring failed: {str(e)}")


@router.post(
    "/mitre",
    response_model=MitreResponse,
    summary="Map alert to MITRE ATT&CK",
    description="Automatically map alert to relevant MITRE ATT&CK techniques and tactics."
)
def map_mitre(
    request: MitreRequest,
    service: AnalysisService = Depends(get_service)
):
    try:
        return service.map_mitre(request)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MITRE mapping failed: {str(e)}")
