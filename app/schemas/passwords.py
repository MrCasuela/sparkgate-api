from pydantic import BaseModel, Field


class PasswordEvaluateRequest(BaseModel):
    password: str = Field(..., min_length=1, description="Plain-text password to evaluate")
    context: str | None = Field(default=None, description="Optional context (e.g. 'bank', 'social media')")


class PasswordEvaluateResponse(BaseModel):
    is_compromised: bool
    pwned_count: int
    entropy_bits: float
    entropy_threshold_met: bool
    ai_score: int = Field(..., ge=0, le=100)
    ai_feedback: str
    ai_suggestions: list[str]


class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=12, le=64)
    mode: str = Field(default="ai", pattern="^(ai|random)$")
    context: str | None = None
    complexity_level: str = Field(default="high")
    use_upper: bool = Field(default=True)
    use_lower: bool = Field(default=True)
    use_digits: bool = Field(default=True)
    use_symbols: bool = Field(default=True)
    style: str = Field(default="compound", pattern="^(compound|passphrase|pattern)$")
    word_count: int | None = Field(default=None, ge=2, le=6)
    theme: str | None = None
    personal_words: list[str] | None = None


class PasswordGenerateResponse(BaseModel):
    generated_password: str
    explanation: str
    entropy_bits: float
