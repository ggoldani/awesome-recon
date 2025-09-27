#!/usr/bin/env bash
set -eo pipefail

# Simple wrapper script to perform non-intrusive passive reconnaissance.
# Uses common system tools and saves outputs to a timestamped directory.

if [ -z "$1" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

DOMAIN="$1"
OUTDIR="recon_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

# Save WHOIS information for registrar, creation/expiry dates and possible contacts.
echo "[*] Saving whois..."
whois "$DOMAIN" > "$OUTDIR/whois.txt" 2>/dev/null || echo "whois failed or not installed"

# Collect DNS records: A, AAAA, MX, NS, TXT.
# TXT often contains SPF/DMARC/BIMI which are useful for email and SPF recon.
echo "[*] DNS records (A, AAAA, MX, NS, TXT)..."
dig +noall +answer A "$DOMAIN" > "$OUTDIR/dig_A.txt" || true
dig +noall +answer AAAA "$DOMAIN" > "$OUTDIR/dig_AAAA.txt" || true
dig +noall +answer MX "$DOMAIN" > "$OUTDIR/dig_MX.txt" || true
dig +noall +answer NS "$DOMAIN" > "$OUTDIR/dig_NS.txt" || true
dig +noall +answer TXT "$DOMAIN" > "$OUTDIR/dig_TXT.txt" || true

# Fetch HTTP headers to identify server, redirects, cookies and server-specific headers.
echo "[*] HTTP headers (curl)..."
curl -I --max-time 10 "http://$DOMAIN" > "$OUTDIR/headers_http.txt" 2>/dev/null || echo "http fail or no response"

# Fetch HTTPS headers; check for HSTS and other security-related headers.
echo "[*] HTTPS headers (curl)..."
curl -I --max-time 10 "https://$DOMAIN" > "$OUTDIR/headers_https.txt" 2>/dev/null || echo "https fail or no response"

# Retrieve TLS certificate details using openssl to inspect issuer, subject and SANs.
echo "[*] SSL certificate (openssl)..."
echo | openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text > "$OUTDIR/ssl_cert.txt" || echo "openssl fail or no TLS endpoint"

echo "[*] Done. Results saved in $OUTDIR"

