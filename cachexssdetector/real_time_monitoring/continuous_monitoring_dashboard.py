"""
Continuous Monitoring Dashboard for CacheXSSDetector.
Provides a terminal-based dashboard for monitoring vulnerabilities continuously.
"""

import asyncio
from typing import List
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from ..core.scanner import Vulnerability
from ..utils.logger import get_logger

logger = get_logger(__name__)
console = Console()

class ContinuousMonitoringDashboard:
    """
    Terminal dashboard to display live scan status and vulnerabilities.
    """

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.active = False

    def add_vulnerability(self, vuln: Vulnerability):
        """Add a new vulnerability to the dashboard."""
        self.vulnerabilities.append(vuln)
        logger.info(f"New vulnerability added: {vuln.type} at {vuln.url}")

    def _generate_table(self) -> Table:
        """Generate a Rich Table of vulnerabilities."""
        table = Table(title="CacheXSSDetector - Vulnerabilities", expand=True)
        table.add_column("Type", style="red", no_wrap=True)
        table.add_column("URL", style="cyan")
        table.add_column("Severity", style="magenta")
        table.add_column("Description", style="green")

        for vuln in self.vulnerabilities:
            table.add_row(
                vuln.type,
                vuln.url,
                vuln.severity,
                vuln.description
            )
        return table

    async def run(self):
        """Run the live dashboard."""
        self.active = True
        with Live(self._generate_table(), refresh_per_second=1, console=console) as live:
            while self.active:
                live.update(self._generate_table())
                await asyncio.sleep(1)

    def stop(self):
        """Stop the dashboard."""
        self.active = False
        logger.info("Continuous Monitoring Dashboard stopped.")

if __name__ == "__main__":
    import time
    from dataclasses import dataclass

    @dataclass
    class DummyVuln:
        type: str
        url: str
        description: str
        severity: str

    async def main():
        dashboard = ContinuousMonitoringDashboard()
        # Start dashboard in background
        asyncio.create_task(dashboard.run())

        # Simulate adding vulnerabilities
        for i in range(5):
            vuln = DummyVuln(
                type="Cache-Based XSS",
                url=f"http://example.com/vuln{i}",
                description="Test vulnerability",
                severity="High"
            )
            dashboard.add_vulnerability(vuln)
            await asyncio.sleep(2)

        dashboard.stop()

    asyncio.run(main())
