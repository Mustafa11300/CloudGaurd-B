"""
CHAT API ENDPOINT
==================
Receives questions from the frontend and routes them to the AI agent.
"""

from fastapi import APIRouter
from pydantic import BaseModel
from agent.copilot import run_copilot

router = APIRouter()


class ChatRequest(BaseModel):
    message: str  # The user's question


@router.post("/")
async def chat(request: ChatRequest):
    """
    POST /api/chat
    Body: {"message": "What should I fix first?"}
    Returns: Agent's reasoning + answer
    """
    result = run_copilot(request.message)
    return result