# CacheXSSDetector

A comprehensive Python CLI tool for detecting Cache-based XSS vulnerabilities in web applications.

## Features

- Advanced URL path manipulation and testing
- Cache behavior analysis
- XSS payload generation and testing
- Multi-client simulation
- Real-time vulnerability monitoring
- Comprehensive reporting system
- Integration capabilities with various security tools

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/CacheXSSDetector.git
cd CacheXSSDetector
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Basic scan:
```bash
python -m cachexssdetector scan --url https://example.com
```

For more options:
```bash
python -m cachexssdetector --help
```

## Documentation

Detailed documentation is available in the `docs` directory.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
