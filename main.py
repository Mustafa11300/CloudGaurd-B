"""
FASTAPI SERVER — THE GLUE
==========================
This is the web server that connects:
- The React frontend (what users see)
- The AI agent (the brain)
- Elasticsearch (the memory)

Think of it as a restaurant kitchen:
- Frontend = the dining room (customers)
- API = the waiters (take orders, deliver food)
- Agent = the chefs (do the actual work)
"""

import os, sys

sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.findings import router as findings_router
from api.score import router as score_router
from api.chat import router as chat_router


app = FastAPI(
    title="CloudGuard Security Copilot",
    description="AI-powered cloud security and cost optimization",
    version="1.0.0"
)

# Allow React frontend to call this API (CORS = Cross-Origin Resource Sharing)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route groups
app.include_router(findings_router, prefix="/api/findings", tags=["Findings"])
app.include_router(score_router, prefix="/api/score", tags=["Score"])
app.include_router(chat_router, prefix="/api/chat", tags=["Chat"])


@app.get("/")
def health_check():
    return {"status": "CloudGuard is running", "version": "1.0.0"}


# Run with: uvicorn main:app --reload