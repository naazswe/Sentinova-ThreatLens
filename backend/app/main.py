
from fastapi import FastAPI

from backend.app.schemas import Indicator


app = FastAPI(
    title="Sentinova ThreatLens",
    description="Cyber Threat Intelligence and Analysis Platform",
    version="0.1.0",
)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Sentinova ThreatLens",
    }


@app.post("/indicators", response_model=Indicator, status_code=201)
def create_indicator(indicator: Indicator):
    return indicator
