# Passive OSINT (minimal)

Minimal passive OSINT script using only Python's standard library.

## What this tool does
This tool performs **non-intrusive** collection of basic public information for a domain:
- Resolve A and AAAA addresses
- Fetch HTTP headers (port 80)
- Fetch HTTPS headers (port 443)
- Extract TLS certificate metadata (issuer, subject CN, SANs, validity)

All operations are passive or standard protocol requests — **do not** perform active scanning.

## Usage

Run directly:
```bash
cd tools/passive_osint
python passive_osint.py --domain example.com

Save output as JSON:
python passive_osint.py --domain example.com --out example_report.json

Example of out put

{
  "domain": "example.com",
  "timestamp_utc": "2025-09-26T18:00:00Z",
  "dns": { "A": ["93.184.216.34"], "AAAA": [] },
  "http_headers": { "Server": "nginx", "Content-Type": "text/html; charset=UTF-8" },
  "https_headers": { "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload" },
  "tls_certificate": {
    "subject_common_name": "example.com",
    "issuer_common_name": "Let's Encrypt",
    "valid_from": "Sep 10 00:00:00 2025 GMT",
    "valid_to": "Dec 9 23:59:59 2025 GMT",
    "subject_alternative_names": ["example.com", "www.example.com"]
  }
}

