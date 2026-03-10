from pydantic import BaseModel
from typing import Literal

class GuardrailResult(BaseModel):
    is_injection: bool
    reason: str

class ClassificationResult(BaseModel):
    category: Literal["normal", "insult", "harassment", "threat"]
    confidence_score: float
    reasoning: str

class VerifierResult(BaseModel):
    verified: bool
    category: Literal["normal", "insult", "harassment", "threat"]
    reasoning: str

class ModerationMessage(BaseModel):
    public_message: str
