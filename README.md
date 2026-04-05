# Extractify

Extractify extracts **endpoints**, **URLs**, and **secrets** from JavaScript and other text—via HTTP URLs, local files, or directories. It is aimed at security reviews, reconnaissance, and quick asset discovery.

## Features

- **Concurrent scanning** for URL lists (configurable workers)
- **Multiple inputs**: single URL, URL list file, directory walk, or stdin
- **Selectable extractors**: endpoints (`-ee`), URLs (`-eu`), secrets (`-es`), or all (`-ea` / default)
- **JSON output**: write with `-o` or print to stdout with `-json` (`-j`)
- **Cross-file deduplication** with `-dedup` (first occurrence wins)
- **Custom secret patterns** via JSON (`-p`)
- **Endpoint noise reduction** (post-processing only; core regex unchanged): date masks, IANA timezones, common JS regex artifacts, MIME-like strings, and configurable extension filtering

## Installation

```bash
go install github.com/SharokhAtaie/extractify@latest
```

## Usage

Run `extractify -h` for the full flag list. Common flags:

| Flag | Short | Description |
|------|-------|-------------|
| `-url` | `-u` | Scan one URL |
| `-list` | `-l` | File of URLs (whitespace-separated) |
| `-file` | `-f` | File or directory to scan |
| `-endpoints` | `-ee` | Include endpoints |
| `-urls` | `-eu` | Include URLs |
| `-secrets` | `-es` | Include secrets |
| `-all` | `-ea` | All extract types |
| `-output` | `-o` | Write **JSON** to file |
| `-json` | `-j` | JSON to **stdout** when `-o` is omitted; with `-o`, JSON file only (no human-readable console) |
| `-dedup` | | Deduplicate URLs, endpoints, and secret **match strings** across sources (first occurrence wins; JSON omits rows with nothing left) |
| `-no-color` | `-nc` | Plain terminal output |
| `-concurrent` | `-c` | Workers for URL mode (default `10`) |
| `-timeout` | `-t` | HTTP timeout seconds (default `20`) |
| `-header` | `-H` | Custom request header (`Name: value`) |
| `-patterns` | `-p` | Custom secrets JSON file |
| `-filter-extension` | `-fe` | Comma-separated extensions to drop from endpoint hits (default includes `woff2`) |
| `-version` | `-V` | Print version and exit |

### Extract types

- You can combine `-ee`, `-eu`, and `-es` (e.g. `-ee -es` for endpoints and secrets only).
- If you pass **none** of `-ee`, `-eu`, `-es`, and **not** `-ea`, behavior is the same as **all** types (default).
- `-ea` explicitly enables all three.

### JSON output

- Output is a **JSON array** of objects. Each object has `source` (file path or URL) and only non-empty fields among `urls`, `endpoints`, and `secrets` (for the extract types you enabled).
- Sources with **no** findings for the enabled types are **skipped** in JSON (no empty arrays).
- With **`-dedup`**, values are unique **globally** across the run; each string appears under the **first** source that still lists it after deduplication.

### Human-readable output

- Default (no `-o`, no `-json`): colored sections per source; **empty categories are silent** (no “no results” lines).
- **`-dedup`**: human output is printed **after** the run, using deduplicated data (same ordering rules as JSON).

### Basic examples

```bash
# Scan a URL (all extract types, human output)
extractify -u https://example.com

# Endpoints only, JSON on stdout
extractify -f ./app.js -ee -json

# Directory: secrets only, write JSON file
extractify -f ./dist/ -es -o secrets.json

# All types, dedupe across files, save JSON
extractify -f ./js/ -dedup -o findings.json

# URL list, 20 workers, custom header
extractify -l urls.txt -c 20 -H "Cookie: session=abc"

# Pipe URLs
cat urls.txt | extractify -eu -json
```

## Custom secret patterns

Define patterns in JSON:

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

```bash
extractify -u https://example.com -p patterns.json
```

## Development

```bash
go test ./... -race
go build -o extractify .
```

## License

This project is licensed under the MIT License—see the LICENSE file.

## Acknowledgments

- [Cariddi](https://github.com/edoardottt/cariddi) — secret detection patterns
- [LinkFinder](https://github.com/GerbenJavado/LinkFinder) — endpoint extraction ideas
