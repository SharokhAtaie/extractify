# Extractify

Extractify is a powerful tool for extracting endpoints, URLs and secrets from various sources. It can process URLs, files, or directories, making it perfect for security researchers, penetration testers, and developers.

## Features

- **Concurrent Scanning**: Process multiple targets simultaneously for faster results
- **Multiple Data Sources**: Scan URLs, files, or entire directories
- **Multiple Extract Types**:
  - Extract endpoints (paths within content)
  - Extract complete URLs
  - Extract secrets and credentials from source code
- **Custom Secret Patterns**: Define your own secret detection patterns
- **Flexible Output**: Save results to file or display in terminal

## Installation

```bash
go install github.com/SharokhAtaie/extractify@latest
```

## Usage

```
Extractify - A tool for extracting endpoints, URLs, and secrets from various sources

Input Flags:
	-url,      -u       URL for scanning
	-list,     -l       List of URLs for scanning
	-file,     -f       Local file or directory for scanning
	Or list of urls from stdin

Extract Types:
	-endpoints, -ee      Extract endpoints
	-urls,      -eu      Extract URLs
	-secrets,   -es      Extract secrets
	-all,       -ea      Extract all types

Other Options:
	-header,          	-H     Set custom header (e.g., 'Authorization: Bearer token')
	-concurrent,      	-c     Number of concurrent workers [default: 10]
	-timeout,         	-t     Timeout in seconds for HTTP requests [default: 20]
	-output,          	-o     Output file to write results (json)
	-patterns,        	-p     Custom regex patterns file
	-version,         	-V     Show version information
	-no-color,          -nc    Disable colorized output
	-filter-extension,  -fe    Filter extensions in endpoint results (comma-separated)

Examples:
	extractify -u https://example.com
	extractify -l urls.txt -es -o results.json
	extractify -f javascript_files/ -ea
	extractify -f file.js -ea
	cat urls.txt | extractify -ea -c 20
```

### Basic Commands

```bash
# Scan a URL
extractify -u https://example.com

# Scan from a list of URLs
extractify -l urls.txt

# Scan a file
extractify -f /path/to/file.js

# Scan a directory recursively
extractify -f /path/to/directory

# Pipe URLs from another command
cat urls.txt | extractify
```

### Extraction Options

```bash
# Extract only endpoints
extractify -u https://example.com -ee

# Extract only URLs
extractify -u https://example.com -eu

# Extract only secrets
extractify -u https://example.com -es

# Extract all
extractify -u https://example.com -ea
```

### Advanced Options

```bash
# Set custom HTTP header
extractify -u https://example.com -H "Authorization: Bearer token"

# Set concurrency level (10 default)
extractify -l urls.txt -c 20

# Save output to file
extractify -u https://example.com -o results.json
```

## Custom Secret Patterns

You can define your own secret detection patterns in a JSON file:

```json
[
  {
    "Name": "Custom API Key",
    "Description": "Custom API Key Pattern",
    "Regex": "api_key['\"]?\\s*[:=]\\s*['\"]([0-9a-zA-Z]{32})['\"]",
    "FalsePositives": ["example", "test"],
    "Poc": "Proof of concept example"
  }
]
```

Then use it with:

```bash
extractify -u https://example.com -p patterns.json
```

## Examples

Extract all information types from multiple URLs:

```bash
extractify -l urls.txt -ea -o results.json
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Cariddi](https://github.com/edoardottt/cariddi) - For secret detection regex patterns
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) - For endpoint regex patterns
