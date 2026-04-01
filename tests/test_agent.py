"""Tests for LLM agent — uses mocked Ollama responses."""

import pytest

from unittest.mock import MagicMock
from langchain_core.messages import AIMessage
from pydantic import BaseModel

from ransomemu.reporting.collector import Event, EventCollector, EventType
from ransomemu.agent.chains import ReconAnalysisChain, LateralMoveChain
from ransomemu.agent.llm_client import LLMClient, PropagationPlan, LateralMoveScript, TargetAnalysis


class TestEventCollector:
    def test_add_and_retrieve(self):
        collector = EventCollector()
        collector.add(Event(event_type=EventType.RECON, message="test scan"))
        events = collector.get_all()
        assert len(events) == 1
        assert events[0].message == "test scan"

    def test_filter_by_type(self):
        collector = EventCollector()
        collector.add(Event(event_type=EventType.RECON, message="scan"))
        collector.add(Event(event_type=EventType.LATERAL_MOVE, message="move"))
        collector.add(Event(event_type=EventType.RECON, message="scan2"))
        recon = collector.get_by_type(EventType.RECON)
        assert len(recon) == 2

    def test_to_list(self):
        collector = EventCollector()
        collector.add(Event(event_type=EventType.INFO, message="hello", target="1.2.3.4"))
        data = collector.to_list()
        assert data[0]["type"] == "INFO"
        assert data[0]["target"] == "1.2.3.4"

    def test_clear(self):
        collector = EventCollector()
        collector.add(Event(event_type=EventType.INFO, message="test"))
        collector.clear()
        assert len(collector.get_all()) == 0


class TestLLMChains:
    def test_recon_analysis_chain(self):
        # Setup mock client
        mock_llm = MagicMock()
        mock_client = MagicMock(spec=LLMClient)
        mock_client.llm = mock_llm
        
        # Setup structured output mock
        mock_structured = MagicMock()
        mock_llm.with_structured_output.return_value = mock_structured
        
        expected_plan = PropagationPlan(
            targets=[TargetAnalysis(ip="10.0.0.1", recommended_protocol="SMB", reasoning="Port 445 open", risk_level="low")],
            attack_order=["10.0.0.1"],
            estimated_success_rate=0.9,
            strategy_summary="Test strategy"
        )
        mock_structured.invoke.return_value = expected_plan
        
        chain = ReconAnalysisChain(mock_client)
        result = chain.run(network_data=[], bloodhound_data={}, ad_data={}, scope="10.0.0.0/24")
        
        assert isinstance(result, PropagationPlan)
        assert result.expected_success_rate == 0.9 if hasattr(result, "expected_success_rate") else getattr(result, "estimated_success_rate", 0) == 0.9
        assert result.targets[0].ip == "10.0.0.1"
        assert result.targets[0].recommended_protocol == "SMB"

    def test_lateral_move_chain(self):
        mock_llm = MagicMock()
        mock_client = MagicMock(spec=LLMClient)
        mock_client.llm = mock_llm
        
        mock_structured = MagicMock()
        mock_llm.with_structured_output.return_value = mock_structured
        
        expected_script = LateralMoveScript(
            protocol="SMB",
            target_ip="10.0.0.1",
            script_content="invoke-webrequest...",
            script_type="powershell",
            explanation="Standard SMB move"
        )
        mock_structured.invoke.return_value = expected_script
        
        chain = LateralMoveChain(mock_client)
        result = chain.run(
            protocol="SMB",
            target_ip="10.0.0.1",
            target_os="Windows",
        )
        
        assert isinstance(result, LateralMoveScript)
        assert result.protocol == "SMB"
        assert result.script_content == "invoke-webrequest..."
