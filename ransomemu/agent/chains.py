"""LangChain chains for recon analysis, lateral move generation, and propagation planning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_core.prompts import ChatPromptTemplate
from jinja2 import Environment, FileSystemLoader

from ransomemu.agent.llm_client import (
    LateralMoveScript,
    LLMClient,
    PropagationPlan,
    TargetAnalysis,
)
from ransomemu.core.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Prompt templates loading
# ---------------------------------------------------------------------------

_PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"
_jinja_env = Environment(loader=FileSystemLoader(_PROMPTS_DIR))

def _load_prompt(template_name: str) -> ChatPromptTemplate:
    """Load a Jinja2 prompt template and construct a ChatPromptTemplate."""
    template = _jinja_env.get_template(template_name).render()
    parts = template.split("[HUMAN]", 1)
    
    if len(parts) == 2:
        system_part = parts[0].replace("[SYSTEM]", "").strip()
        human_part = parts[1].strip()
        # Jinja2 already parsed variables, but LangChain uses {var} for runtime inputs.
        # So we convert Jinja's {{ var }} to LangChain's {var}.
        human_part = human_part.replace("{{ ", "{").replace(" }}", "}")
        
        return ChatPromptTemplate.from_messages([
            ("system", system_part),
            ("human", human_part),
        ])
    return ChatPromptTemplate.from_template(template.replace("{{ ", "{").replace(" }}", "}"))

RECON_ANALYSIS_PROMPT = _load_prompt("recon_analysis.j2")
LATERAL_SMB_PROMPT = _load_prompt("lateral_smb.j2")
LATERAL_WINRM_PROMPT = _load_prompt("lateral_winrm.j2")
LATERAL_WMI_PROMPT = _load_prompt("lateral_wmi.j2")
PROPAGATION_PLAN_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a cybersecurity expert planning a controlled ransomware propagation 
    simulation. Plan the optimal order of lateral movement across targets, considering:
    1. Network topology and trust relationships
    2. Available protocols on each target
    3. Likelihood of success per protocol
    4. Minimize detection (realistic simulation)
    This is a Purple Team exercise — safety first."""),
    ("human", """Plan propagation across these targets:
{targets_json}

Strategy: {strategy}
Max hops from origin: {max_hops}"""),
])


# ---------------------------------------------------------------------------
# Chain functions
# ---------------------------------------------------------------------------


class ReconAnalysisChain:
    """Analyze reconnaissance data and produce a propagation plan."""

    def __init__(self, client: LLMClient) -> None:
        self._client = client
        self._chain = RECON_ANALYSIS_PROMPT | client.llm.with_structured_output(PropagationPlan)

    def run(
        self,
        network_data: list[dict],
        bloodhound_data: dict,
        ad_data: dict,
        scope: str,
        max_hops: int = 3,
        max_targets: int = 10,
    ) -> PropagationPlan:
        logger.info("🧠 LLM analyzing recon data…")
        return self._chain.invoke({
            "network_data": json.dumps(network_data, indent=2),
            "bloodhound_data": json.dumps(bloodhound_data, indent=2),
            "ad_data": json.dumps(ad_data, indent=2),
            "scope": scope,
            "max_hops": max_hops,
            "max_targets": max_targets,
        })


class LateralMoveChain:
    """Generate a lateral movement script adapted to the target."""

    def __init__(self, client: LLMClient) -> None:
        self._client = client
        self._prompts = {
            "SMB": LATERAL_SMB_PROMPT,
            "WinRM": LATERAL_WINRM_PROMPT,
            "WMI": LATERAL_WMI_PROMPT,
        }

    def run(
        self,
        protocol: str,
        target_ip: str,
        target_os: str = "Windows",
        cred_type: str = "password",
        marker_path: str = "C:\\ransomemu_marker.txt",
        script_type: str = "powershell",
        context: str = "",
    ) -> LateralMoveScript:
        logger.info(f"🧠 LLM generating {protocol} script for {target_ip}…")
        prompt = self._prompts.get(protocol, LATERAL_SMB_PROMPT)
        chain = prompt | self._client.llm.with_structured_output(LateralMoveScript)
        
        return chain.invoke({
            "target_ip": target_ip,
            "target_os": target_os,
            "cred_type": cred_type,
            "marker_path": marker_path,
            "context": context,
        })


class PropagationPlanChain:
    """Plan optimal propagation order across targets."""

    def __init__(self, client: LLMClient) -> None:
        self._client = client
        self._chain = PROPAGATION_PLAN_PROMPT | client.llm.with_structured_output(PropagationPlan)

    def run(
        self,
        targets: list[dict[str, Any]],
        strategy: str = "breadth-first",
        max_hops: int = 3,
    ) -> PropagationPlan:
        logger.info("🧠 LLM planning propagation order…")
        return self._chain.invoke({
            "targets_json": json.dumps(targets, indent=2),
            "strategy": strategy,
            "max_hops": max_hops,
        })
