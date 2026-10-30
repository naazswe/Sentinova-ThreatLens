
from fastapi import FastAPI

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
