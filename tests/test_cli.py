import subprocess

def test_cli_version():
    result = subprocess.run(['python', '-m', 'cachexssdetector', '--version'], capture_output=True, text=True)
    assert 'CacheXSSDetector' in result.stdout or '0.1.0' in result.stdout

def test_cli_scan_help():
    result = subprocess.run(['python', '-m', 'cachexssdetector', 'scan', '--help'], capture_output=True, text=True)
    assert 'Usage' in result.stdout
    assert '--url' in result.stdout
