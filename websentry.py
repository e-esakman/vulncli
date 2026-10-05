"""WebSentry: a small passive web security CLI."""

import argparse
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

import requests

from checks import (check_cookies, check_disclosure, check_headers, check_https,
                    collect_findings)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves(server):
    """Return filtered keyword matches and an explicit lookup status."""
    match = re.search(r"\b(Apache|nginx|Microsoft-IIS)/(\d+(?:\.\d+)+)\b", server, re.I)
    if not match:
        return [], "skipped"
    product, version = match.groups()
    product = {"apache": "Apache HTTP Server", "nginx": "nginx",
               "microsoft-iis": "Microsoft IIS"}[product.lower()]
    product_pattern = {"Apache HTTP Server": r"\bapache\s+(?:http\s+server|httpd)\b",
                       "nginx": r"\bnginx\b", "Microsoft IIS": r"\b(?:microsoft\s+)?iis\b"}[product]
    version_pattern = rf"(?<![\d.]){re.escape(version)}(?![\d.])"
    key = os.getenv("NVD_API_KEY")
    try:
        response = requests.get(NVD_URL, timeout=10,
                                params={"keywordSearch": f"{product} {version}",
                                        "resultsPerPage": 5},
                                headers={"apiKey": key} if key else {})
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            return [], "unavailable"
        results = []
        for item in payload["vulnerabilities"]:
            cve = item["cve"]
            if not isinstance(cve, dict):
                return [], "unavailable"
            description = next((d["value"] for d in cve.get("descriptions", [])
                                if d["lang"] == "en"), "No English description")
            if not (re.search(product_pattern, description, re.I)
                    and re.search(version_pattern, description)):
                continue
            metrics = cve.get("metrics", {})
            if not isinstance(metrics, dict):
                return [], "unavailable"
            scores = (metrics.get("cvssMetricV40") or metrics.get("cvssMetricV31")
                      or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [])
            if not isinstance(scores, list) or any(not isinstance(m, dict) for m in scores):
                return [], "unavailable"
            metric = next((m for m in scores if m.get("type") == "Primary"),
                          scores[0] if scores else {})
            data = metric.get("cvssData", {})
            if not isinstance(data, dict):
                return [], "unavailable"
            results.append({"id": cve["id"], "description": description[:240],
                            "score": data.get("baseScore"),
                            "severity": data.get("baseSeverity", metric.get("baseSeverity"))})
        return results, "complete"
    except (requests.RequestException, KeyError, TypeError):
        return [], "unavailable"


def scan(url):
    """Fetch the target and inspect its final response."""
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(c.isspace() for c in url):
        raise ValueError("Provide a complete http:// or https:// URL")
    parsed.port  # Validate a supplied port before making the request.
    start = time.perf_counter()
    response = requests.get(url, timeout=10, allow_redirects=True)
    duration = round((time.perf_counter() - start) * 1000, 2)
    response.raise_for_status()
    https = check_https(response, url)
    cookie_headers = response.raw.headers.getlist("Set-Cookie")
    checks = {"https": https, "headers": check_headers(response.headers, https["enabled"]),
              "cookies": check_cookies(cookie_headers), "cookie_headers_count": len(cookie_headers),
              "disclosure": check_disclosure(response.headers)}
    cves, nvd_status = lookup_cves(response.headers.get("Server", ""))
    return {"target": url, "final_url": response.url, "status_code": response.status_code,
            "response_time_ms": duration, "response_size_bytes": len(response.content),
            "content_type": response.headers.get("Content-Type", ""), "checks": checks,
            "findings": collect_findings(checks), "potential_cves": cves, "nvd_status": nvd_status}


def print_report(report):
    """Print checks and short explanations."""
    checks = report["checks"]
    print(f"WebSentry\n{'─' * 32}\n\nTarget: {report['target']}\nFinal URL: {report['final_url']}")
    print(f"\nResponse\n  Status: {report['status_code']}\n  Time: {report['response_time_ms']} ms")
    size = report["response_size_bytes"]
    print(f"  Size: {size} B" if size < 1024 else f"  Size: {size / 1024:.1f} KB")
    print(f"  Content-Type: {report['content_type'] or 'not provided'}\n\nHTTPS")
    print("  ✓ HTTPS enabled" if checks["https"]["enabled"] else "  ✗ HTTPS not enabled")
    redirect = checks["https"]["http_redirects_to_https"]
    print("  ℹ HTTP → HTTPS not tested" if redirect is None
          else f"  {'✓' if redirect else '✗'} HTTP → HTTPS")
    print("\nSecurity Headers")
    for name, status in checks["headers"].items():
        symbol = "✓" if status == "present" else "ℹ" if status.startswith("skipped") else "✗"
        print(f"  {symbol} {name}" + ("" if status == "present" else f": {status}"))
    print("\nCookies")
    if not checks["cookies"]:
        print("  No cookies could be parsed" if checks["cookie_headers_count"]
              else "  No cookies set by the final response")
    for cookie in checks["cookies"]:
        print(f"  {cookie['name']}")
        for flag in ("Secure", "HttpOnly", "SameSite"):
            print(f"    {'✓' if cookie[flag] else '✗'} {flag}")
    print("\nInformation Disclosure")
    for name, value in checks["disclosure"].items():
        print(f"  ⚠ {name}: {value}")
    if not checks["disclosure"]:
        print("  No software headers found")
    print("\nPotential CVEs")
    if report["nvd_status"] == "unavailable":
        print("  Not assessed\n\nNVD\n  Lookup unavailable")
    elif report["nvd_status"] == "skipped":
        print("  Not assessed\n\nNVD\n  Lookup skipped: no recognized server product/version")
    elif not report["potential_cves"]:
        print("  No potential matches found")
    for cve in report["potential_cves"]:
        print(f"  Potential matching CVE: {cve['id']}")
        print(f"  CVSS: {cve['score'] if cve['score'] is not None else 'unavailable'} "
              f"{cve['severity'] or ''}\n  Description: {cve['description']}")
    if report["potential_cves"]:
        print("  Version-based match only. This does not confirm exploitability.")
    findings = report["findings"]
    risk = next((s for s in ("HIGH", "MEDIUM", "LOW")
                 if any(f["severity"] == s for f in findings)), "NONE")
    print(f"\n{'─' * 32}\nFindings: {len(findings)}\nRisk: {risk}")
    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['name']}")
        print(f"Why: {finding['description']}\nRecommendation: {finding['recommendation']}")


def main():
    """Parse arguments and handle ordinary request errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Complete HTTP or HTTPS URL")
    parser.add_argument("--json", action="store_true", help="Print JSON")
    args = parser.parse_args()
    try:
        report = scan(args.url)
    except (ValueError, requests.RequestException) as error:
        print(f"WebSentry: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
