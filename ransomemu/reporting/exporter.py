"""Report exporter — JSON and HTML report generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from ransomemu.core.logger import get_logger
from ransomemu.reporting.collector import EventCollector

logger = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_jinja_env = Environment(loader=FileSystemLoader(_TEMPLATES_DIR))


class ReportExporter:
    """Export simulation events as JSON or HTML reports."""

    def __init__(self, collector: EventCollector | None = None) -> None:
        self._collector = collector or EventCollector()

    def export_json(self, output_path: str | Path) -> Path:
        """Export events as JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "tool": "ransomemu",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "events": self._collector.to_list(),
        }

        path.write_text(json.dumps(data, indent=2))
        logger.info(f"📄 JSON report saved to {path}")
        return path

    def export_html(self, output_path: str | Path) -> Path:
        """Export events as a styled HTML report with timeline."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        events = self._collector.to_list()

        # Statistics
        lateral = [e for e in events if e["type"] == "LATERAL_MOVE"]
        success = [e for e in lateral if "SUCCESS" in e.get("message", "")]
        rate = round(len(success) / len(lateral) * 100) if lateral else 0

        # Build event HTML
        template_events = []
        for evt in events:
            css = "success" if "SUCCESS" in evt.get("message", "") else ""
            if evt["type"] == "ERROR":
                css = "error"

            template_events.append({
                "css_class": css,
                "type": evt["type"],
                "target": evt.get("target", ""),
                "timestamp": evt["timestamp"],
                "message": evt["message"],
            })

        template = _jinja_env.get_template("report.html.j2")
        html = template.render(
            timestamp=datetime.now(timezone.utc).isoformat(),
            total_events=len(events),
            lateral_moves=len(lateral),
            success_count=len(success),
            success_rate=rate,
            events=template_events,
        )

        path.write_text(html)
        logger.info(f"📄 HTML report saved to {path}")
        return path
