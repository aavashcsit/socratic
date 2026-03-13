from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import get_settings
from app.api.routes.analysis import router as analysis_router
from app.models.schemas import HealthResponse

settings = get_settings()

app = FastAPI(
    title="SOCratic",
    description="AI-powered SOC alert triage assistant — built by a SOC analyst, for SOC analysts.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# Routers
app.include_router(analysis_router)


@app.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
def health_check():
    return HealthResponse(
        status="ok",
        app=settings.app_name,
        version="0.1.0",
        model=settings.anthropic_model
    )


@app.get("/", include_in_schema=False)
def root():
    return {"message": "SOCratic API is running. Visit /docs for the API explorer."}