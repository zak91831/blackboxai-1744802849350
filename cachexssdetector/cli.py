"""
Command Line Interface for CacheXSSDetector.
Handles all CLI commands and options using Click.
"""

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich import print as rprint
from typing import Optional

from .core.scanner import Scanner
from .utils.logger import setup_logger
from .utils.config import load_config

# Initialize Rich console for better formatting
console = Console()
logger = setup_logger()

def print_banner():
    """Display the tool's banner."""
    banner = """
╔═══════════════════════════════════════════╗
║           CacheXSSDetector v0.1.0         ║
║    Cache-based XSS Vulnerability Scanner   ║
╚═══════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold blue"))

@click.group()
@click.version_option(version="0.1.0")
def cli():
    """CacheXSSDetector - A comprehensive Cache-based XSS vulnerability detection tool."""
    print_banner()

@cli.command()
@click.option('--url', '-u', required=True, help='Target URL to scan')
@click.option('--config', '-c', type=click.Path(exists=True), help='Path to configuration file')
@click.option('--output', '-o', type=click.Path(), help='Output file for the scan report')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--proxy', '-p', help='Proxy URL (e.g., http://proxy:8080)')
@click.option('--timeout', '-t', type=int, default=60, help='Timeout in seconds for the scan')
def scan(url: str, config: Optional[str], output: Optional[str], verbose: bool, proxy: Optional[str], timeout: int):
    """Perform a cache-based XSS vulnerability scan on the target URL."""
    import asyncio
    from cachexssdetector.real_time_monitoring.vulnerability_alerting_system import VulnerabilityAlertingSystem
    from cachexssdetector.real_time_monitoring.continuous_monitoring_dashboard import ContinuousMonitoringDashboard
    try:
        # Load configuration
        config_data = load_config(config) if config else {}

        # Initialize scanner
        scanner = Scanner(
            url=url,
            config=config_data,
            proxy=proxy,
            verbose=verbose
        )

        # Setup async event loop and cancellation event
        cancel_event = asyncio.Event()

        # Setup vulnerability alerting system and dashboard
        alert_system = VulnerabilityAlertingSystem()
        dashboard = ContinuousMonitoringDashboard()

        async def run_scan():
            # Run scanner asynchronously with timeout and cancellation
            try:
                results = await asyncio.wait_for(
                    asyncio.to_thread(scanner.run),
                    timeout=timeout
                )
                # Add vulnerabilities to dashboard
                for vuln in results.vulnerabilities:
                    dashboard.add_vulnerability(vuln)
                    await alert_system._alert(vuln)
                return results
            except asyncio.TimeoutError:
                console.print(f"[red]Scan timed out after {timeout} seconds[/red]")
                cancel_event.set()
                return None

        async def main():
            # Run dashboard and scan concurrently
            dashboard_task = asyncio.create_task(dashboard.run())
            scan_task = asyncio.create_task(run_scan())
            results = await scan_task
            dashboard.stop()
            await dashboard_task
            return results

        results = asyncio.run(main())

        if results is None:
            return

        # Display results
        if results.vulnerabilities:
            console.print("\n[red]Vulnerabilities Found:[/red]")
            for vuln in results.vulnerabilities:
                console.print(Panel.fit(
                    f"[bold red]Type:[/bold red] {vuln.type}\n"
                    f"[bold]URL:[/bold] {vuln.url}\n"
                    f"[bold]Description:[/bold] {vuln.description}\n"
                    f"[bold]Severity:[/bold] {vuln.severity}",
                    title="Vulnerability Details",
                    border_style="red"
                ))
        else:
            console.print("\n[green]No vulnerabilities found![/green]")

        # Save report if output file specified
        if output:
            scanner.save_report(output)
            console.print(f"\nReport saved to: {output}")

    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        console.print(f"[red]Error:[/red] {str(e)}")
        raise click.Abort()

@cli.command()
@click.option('--report', '-r', type=click.Path(exists=True), required=True, help='Path to scan report file')
def analyze(report: str):
    """Analyze a previously generated scan report."""
    try:
        import json
        with open(report, 'r') as f:
            data = json.load(f)
        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            console.print("[green]No vulnerabilities found in the report.[/green]")
            return
        console.print(f"[red]Vulnerabilities found: {len(vulnerabilities)}[/red]")
        for vuln in vulnerabilities:
            console.print(Panel.fit(
                f"[bold red]Type:[/bold red] {vuln.get('type')}\n"
                f"[bold]URL:[/bold] {vuln.get('url')}\n"
                f"[bold]Description:[/bold] {vuln.get('description')}\n"
                f"[bold]Severity:[/bold] {vuln.get('severity')}",
                title="Vulnerability Details",
                border_style="red"
            ))
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}")
        console.print(f"[red]Error:[/red] {str(e)}")
        raise click.Abort()

@cli.command()
@click.option('--config', '-c', type=click.Path(), help='Path to configuration file')
@click.option('--set', '-s', multiple=True, help='Set configuration key=value pairs')
def configure(config: str, set: tuple):
    """Configure scanner settings."""
    try:
        from .utils.config import load_config, save_config
        import yaml
        config_data = load_config(config) if config else {}
        if set:
            for item in set:
                if '=' not in item:
                    console.print(f"[red]Invalid format for set option: {item}. Use key=value.[/red]")
                    return
                key, value = item.split('=', 1)
                keys = key.split('.')
                d = config_data
                for k in keys[:-1]:
                    d = d.setdefault(k, {})
                d[keys[-1]] = yaml.safe_load(value)
            if config:
                save_config(config_data, config)
                console.print(f"[green]Configuration saved to {config}[/green]")
            else:
                console.print("[yellow]No configuration file specified to save changes.[/yellow]")
        else:
            console.print(yaml.dump(config_data, default_flow_style=False))
    except Exception as e:
        logger.error(f"Configuration failed: {str(e)}")
        console.print(f"[red]Error:[/red] {str(e)}")
        raise click.Abort()

def main():
    """Main entry point for the CLI."""
    try:
        cli()
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        console.print(f"[red]Fatal Error:[/red] {str(e)}")
        raise click.Abort()

if __name__ == '__main__':
    main()
