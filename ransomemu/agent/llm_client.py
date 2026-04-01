"""Ollama LLM client wrapper with LangChain integration."""

from __future__ import annotations

from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

from ransomemu.core.config import OllamaSettings
from ransomemu.core.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Structured output models
# ---------------------------------------------------------------------------


class TargetAnalysis(BaseModel):
    """LLM analysis of a single target."""

    ip: str
    hostname: str = ""
    recommended_protocol: str = Field(description="SMB, WinRM, or WMI")
    reasoning: str = Field(description="Why this protocol was chosen")
    risk_level: str = Field(description="low, medium, or high")


class PropagationPlan(BaseModel):
    """LLM-generated propagation plan."""

    targets: list[TargetAnalysis]
    attack_order: list[str] = Field(description="Ordered list of target IPs")
    estimated_success_rate: float = Field(ge=0.0, le=1.0)
    strategy_summary: str


class LateralMoveScript(BaseModel):
    """Generated lateral movement script."""

    protocol: str
    target_ip: str
    script_content: str = Field(description="PowerShell or Bash script")
    script_type: str = Field(description="powershell or bash")
    explanation: str


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class LLMClient:
    """Wrapper around Ollama via LangChain with structured output."""

    def __init__(self, settings: OllamaSettings | None = None) -> None:
        settings = settings or OllamaSettings()
        logger.info(f"🤖 Connecting to Ollama at {settings.base_url} (model: {settings.model})")

        self._llm = ChatOllama(
            base_url=settings.base_url,
            model=settings.model,
            temperature=settings.temperature,
            timeout=settings.timeout,
        )

    @property
    def llm(self) -> ChatOllama:
        """Raw LangChain LLM instance."""
        return self._llm

    def invoke(self, prompt: str) -> str:
        """Simple text completion."""
        response = self._llm.invoke(prompt)
        return response.content

    def invoke_structured(self, prompt: str, schema: type[BaseModel]) -> BaseModel:
        """Invoke with structured Pydantic output."""
        structured_llm = self._llm.with_structured_output(schema)
        return structured_llm.invoke(prompt)
