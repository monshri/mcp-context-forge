# Third-Party
from pydantic import BaseModel
from typing import Optional

class ModeConfig(BaseModel):
    sanitizers: Optional[dict] = None
    filters: Optional[dict] = None


class LLMGuardConfig(BaseModel):
    input: Optional[ModeConfig] = None
    output: Optional[ModeConfig] = None