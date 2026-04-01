"""RansomEmu CLI — Click-based command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from ransomemu import __version__
from ransomemu.core.config import RansomEmuConfig
from ransomemu.core.logger import get_logger, setup_logging
from ransomemu.core.safety import KillSwitch

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(__version__, prog_name="ransomemu")
@click.option("--config", "-c", "config_path", default=None, help="Path to YAML config file.")
@click.option("--dry-run", is_flag=True, default=None, help="Log actions without executing.")
@click.option("--verbose", "-v", is_flag=True, default=False, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, config_path: str | None, dry_run: bool | None, verbose: bool) -> None:
    """🔒 RansomEmu — Ransomware emulation framework for network resilience testing."""
    setup_logging(verbose=verbose)

    cfg = RansomEmuConfig.from_yaml(config_path)
    if dry_run is not None:
        cfg.dry_run = dry_run
    cfg.verbose = verbose

    ctx.ensure_object(dict)
    ctx.obj["config"] = cfg

    KillSwitch.arm()

    if cfg.dry_run:
        logger.info("⚠️  DRY-RUN mode active — no real actions will be performed")


# ---------------------------------------------------------------------------
# scan — Reconnaissance
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--targets", "-t", required=True, help="Comma-separated IPs or CIDR to scan.")
@click.option("--output", "-o", default=None, help="Save scan results to JSON file.")
@click.pass_context
def scan(ctx: click.Context, targets: str, output: str | None) -> None:
    """🔍 Scan the network for lateral movement targets."""
    import ipaddress

    from ransomemu.modules.recon.network import scan_subnet

    # Expand CIDR notation
    ip_list: list[str] = []
    for item in targets.split(","):
        item = item.strip()
        try:
            network = ipaddress.ip_network(item, strict=False)
            ip_list.extend(str(ip) for ip in network.hosts())
        except ValueError:
            ip_list.append(item)

    results = scan_subnet(ip_list)
    data = [r.to_dict() for r in results]

    if output:
        Path(output).write_text(json.dumps(data, indent=2))
        logger.info(f"Results saved to {output}")
    else:
        click.echo(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# plan — LLM propagation planning
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--scan-file", "-s", required=True, help="Path to scan results JSON.")
@click.option("--strategy", type=click.Choice(["bfs", "dfs"]), default="bfs", help="Propagation strategy.")
@click.pass_context
def plan(ctx: click.Context, scan_file: str, strategy: str) -> None:
    """🧠 Generate a propagation plan using the LLM."""
    cfg: RansomEmuConfig = ctx.obj["config"]

    from ransomemu.agent.chains import ReconAnalysisChain
    from ransomemu.agent.llm_client import LLMClient

    # Load scan data
    scan_data = json.loads(Path(scan_file).read_text())

    client = LLMClient(cfg.ollama)
    chain = ReconAnalysisChain(client)

    plan_result = chain.run(
        network_data=scan_data,
        bloodhound_data={},
        ad_data={},
        scope=",".join(cfg.scope.allowed_subnets),
        max_hops=cfg.max_hops,
        max_targets=cfg.max_targets,
    )

    click.echo("\n📋 Propagation Plan:")
    click.echo(f"  Strategy: {plan_result.strategy_summary}")
    click.echo(f"  Estimated success rate: {plan_result.estimated_success_rate:.0%}")
    click.echo(f"  Attack order: {plan_result.attack_order}")
    click.echo("\n  Targets:")
    for t in plan_result.targets:
        click.echo(f"    → {t.ip} ({t.recommended_protocol}) — risk: {t.risk_level}")
        click.echo(f"      {t.reasoning}")


# ---------------------------------------------------------------------------
# run — Full simulation
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--scan-file", "-s", required=True, help="Path to scan results JSON.")
@click.option("--username", "-u", required=True, help="Username for authentication.")
@click.option("--password", "-p", default="", help="Password (or use --hashes).")
@click.option("--hashes", default="", help="NTLM hash in LM:NT format.")
@click.option("--domain", "-d", default="", help="AD domain name.")
@click.option("--strategy", type=click.Choice(["bfs", "dfs"]), default="bfs")
@click.option("--report", "-r", default="reports/report", help="Report output path (without ext).")
@click.pass_context
def run(
    ctx: click.Context,
    scan_file: str,
    username: str,
    password: str,
    hashes: str,
    domain: str,
    strategy: str,
    report: str,
) -> None:
    """🚀 Run the full propagation simulation."""
    cfg: RansomEmuConfig = ctx.obj["config"]

    from ransomemu.agent.llm_client import LLMClient
    from ransomemu.modules.propagation.engine import PropagationEngine
    from ransomemu.reporting.collector import EventCollector
    from ransomemu.reporting.exporter import ReportExporter

    # Load targets
    targets = json.loads(Path(scan_file).read_text())

    # Build components
    collector = EventCollector()
    collector.clear()

    llm_client = None
    try:
        llm_client = LLMClient(cfg.ollama)
    except Exception as exc:
        logger.warning(f"LLM unavailable, running without AI: {exc}")

    engine = PropagationEngine(cfg, llm_client=llm_client, collector=collector)
    credentials = {
        "username": username,
        "password": password,
        "hashes": hashes,
        "domain": domain,
    }

    # Run
    state = engine.run(targets, credentials, strategy=strategy)

    # Report
    exporter = ReportExporter(collector)
    exporter.export_json(f"{report}.json")
    exporter.export_html(f"{report}.html")

    # Summary
    click.echo(f"\n🏁 Simulation complete:")
    click.echo(f"  Compromised: {len(state.compromised)}")
    click.echo(f"  Failed: {len(state.failed)}")
    click.echo(f"  Duration: {state.to_dict()['duration_s']}s")
    click.echo(f"  Reports: {report}.json / {report}.html")


# ---------------------------------------------------------------------------
# report — Generate report from existing events
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--format", "-f", "fmt", type=click.Choice(["json", "html", "both"]), default="both")
@click.option("--output", "-o", default="reports/report", help="Output path (without ext).")
@click.pass_context
def report(ctx: click.Context, fmt: str, output: str) -> None:
    """📄 Generate a report from collected events."""
    from ransomemu.reporting.collector import EventCollector
    from ransomemu.reporting.exporter import ReportExporter

    exporter = ReportExporter(EventCollector())

    if fmt in ("json", "both"):
        exporter.export_json(f"{output}.json")
    if fmt in ("html", "both"):
        exporter.export_html(f"{output}.html")


# ---------------------------------------------------------------------------
# rollback — Remove markers
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--path", "-p", required=True, help="Directory to rollback markers from.")
@click.option("--recursive", "-r", is_flag=True, default=True)
def rollback(path: str, recursive: bool) -> None:
    """🔄 Remove simulation markers from files."""
    from ransomemu.modules.crypto.simulator import CryptoSimulator

    count = CryptoSimulator.rollback_directory(Path(path), recursive=recursive)
    click.echo(f"🔄 Rolled back {count} files")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
