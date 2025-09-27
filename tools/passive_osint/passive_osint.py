#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Purpose: Minimal passive OSINT CLI using only Python's standard library.
# Why: Start with a zero-dependency tool that's easy to run anywhere.
# How: Resolve basic DNS (A/AAAA), fetch HTTP/HTTPS headers, and extract TLS certificate info.

import argparse
import json
import socket
import ssl
import http.client
import time
from typing import Dict, List, Tuple


# Purpose: Resolve A/AAAA addresses for a domain using getaddrinfo (stdlib).
# Why: We avoid external DNS libraries to keep the first step dependency-free.
# How: Query AF_UNSPEC to get both IPv4 and IPv6; deduplicate results.
def resolve_addresses(domain: str, timeout: float = 5.0) -> Dict[str, List[str]]:
    socket.setdefaulttimeout(timeout)
    ipv4, ipv6 = set(), set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP):
            if family == socket.AF_INET and sockaddr:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6 and sockaddr:
                ipv6.add(sockaddr[0])
    except Exception:
        # Swallow resolution errors and return empty sets
        pass
    return {"A": sorted(ipv4), "AAAA": sorted(ipv6)}


# Purpose: Perform a HEAD request and capture response headers over HTTP.
# Why: Headers reveal server info and security-related hints (server, redirects, etc.).
# How: Use http.client.HTTPConnection with method="HEAD" and a short timeout.
def fetch_http_headers(domain: str, timeout: float = 5.0) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    try:
        conn = http.client.HTTPConnection(domain, 80, timeout=timeout)
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        for k, v in resp.getheaders():
            headers[k] = v
        conn.close()
    except Exception:
        # Ignore network errors; return empty dict to keep flow simple
        pass
    return headers


# Purpose: Perform a HEAD request and capture response headers over HTTPS.
# Why: Compare HTTP vs HTTPS behavior and note any differences.
# How: Use http.client.HTTPSConnection with method="HEAD" and a short timeout.
def fetch_https_headers(domain: str, timeout: float = 5.0) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    try:
        conn = http.client.HTTPSConnection(domain, 443, timeout=timeout, context=ssl.create_default_context())
        conn.request("HEAD", "/")
        resp = conn.getresponse()
        for k, v in resp.getheaders():
            headers[k] = v
        conn.close()
    except Exception:
        pass
    return headers


# Purpose: Retrieve TLS certificate metadata from the target's HTTPS endpoint.
# Why: Certificates expose issuer, subject, SANs, and validity window — useful for passive recon.
# How: Create an SSL-wrapped socket, connect to :443, call getpeercert() and extract key fields.
def fetch_tls_certificate_info(domain: str, timeout: float = 5.0) -> Dict[str, str]:
    info: Dict[str, str] = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls:
                cert = tls.getpeercert()
                if not cert:
                    return info

                # Extract human-friendly fields
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")
                sans = []
                for typ, val in cert.get("subjectAltName", []):
                    if typ.lower() == "dns":
                        sans.append(val)

                info = {
                    "subject_common_name": subject.get("commonName", ""),
                    "issuer_common_name": issuer.get("commonName", ""),
                    "valid_from": not_before,
                    "valid_to": not_after,
                    "subject_alternative_names": sans,
                }
    except Exception:
        pass
    return info


# Purpose: Aggregate all passive findings into a single structured dict.
# Why: Keep the CLI output predictable for saving/automation later.
# How: Call each helper, add a timestamp, and return a cohesive object.
def collect_passive_osint(domain: str) -> Dict:
    resolved = resolve_addresses(domain)
    http_h = fetch_http_headers(domain)
    https_h = fetch_https_headers(domain)
    cert = fetch_tls_certificate_info(domain)

    return {
        "domain": domain,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dns": resolved,
        "http_headers": http_h,
        "https_headers": https_h,
        "tls_certificate": cert,
    }


# Purpose: Parse CLI arguments and orchestrate execution.
# Why: Provide a clean user interface with --out optional for JSON file.
# How: argparse → run collection → print or save JSON.
def main():
    parser = argparse.ArgumentParser(
        description="Minimal passive OSINT (A/AAAA, HTTP/HTTPS headers, TLS cert) — authorized use only."
    )
    parser.add_argument("--domain", required=True, help="Target domain (authorized only)")
    parser.add_argument("--out", help="Output JSON file (optional)")
    args = parser.parse_args()

    result = collect_passive_osint(args.domain)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"[+] Saved to {args.out}")
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


# Purpose: Standard Python entry point.
# Why: Allow running as a script or via module.
# How: Guarded call to main().
if __name__ == "__main__":
    main()

