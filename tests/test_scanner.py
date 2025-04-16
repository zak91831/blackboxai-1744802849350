import pytest
import asyncio
from cachexssdetector.core.scanner import Scanner

@pytest.mark.asyncio
async def test_scanner_run_async():
    scanner = Scanner("http://example.com")
    result = await scanner.run_async()
    assert result.target_url == "http://example.com"
    assert isinstance(result.vulnerabilities, list)
    assert result.total_requests >= 0

def test_scanner_run_sync():
    scanner = Scanner("http://example.com")
    result = scanner.run()
    assert result.target_url == "http://example.com"
    assert isinstance(result.vulnerabilities, list)
    assert result.total_requests >= 0
