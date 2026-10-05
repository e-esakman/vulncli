"""Passive checks of response metadata."""

from http.cookies import CookieError, SimpleCookie
from urllib.parse import urlsplit

from findings import create_finding

SECURITY_HEADERS = {
    "Strict-Transport-Security": "MEDIUM",
    "Content-Security-Policy": "MEDIUM",
    "X-Frame-Options": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "Referrer-Policy": "LOW",
    "Permissions-Policy": "LOW",
}


def check_https(response, target):
    """Check the final scheme; only HTTP input tests an upgrade."""
    enabled = urlsplit(response.url).scheme == "https"
    started_http = urlsplit(target).scheme == "http"
    return {"enabled": enabled,
            "http_redirects_to_https": enabled if started_http else None}


def check_headers(headers, https=True):
    """Validate basic values and skip checks outside their context."""
    headers = {name.lower(): value.strip() for name, value in headers.items()}
    html = headers.get("content-type", "").split(";")[0].lower() in (
        "text/html", "application/xhtml+xml")
    results = {}
    for name in SECURITY_HEADERS:
        value = headers.get(name.lower(), "")
        status = "present" if value else "missing"
        if name in ("Content-Security-Policy", "X-Frame-Options") and not html:
            status = "skipped: response is not HTML"
        elif name == "Strict-Transport-Security" and not https:
            status = "skipped: response is not HTTPS"
        elif value:
            if name == "X-Content-Type-Options" and value.lower() != "nosniff":
                status = "invalid"
            elif name == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
                status = "invalid"
            elif name == "Strict-Transport-Security":
                ages = [p.partition("=")[2].strip() for p in value.split(";")
                        if p.partition("=")[0].strip().lower() == "max-age"]
                if len(ages) != 1 or not ages[0].isascii() or not ages[0].isdigit() or not ages[0].strip("0"):
                    status = "invalid"
        results[name] = status
    return results


def check_cookies(cookie_headers):
    """Parse each Set-Cookie separately, including cookies with Expires."""
    results = []
    for header in cookie_headers:
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except CookieError:
            continue
        for name, value in cookie.items():
            results.append({"name": name, "Secure": bool(value["secure"]),
                            "HttpOnly": bool(value["httponly"]),
                            "SameSite": value["samesite"].lower() in
                            ("lax", "strict", "none")})
    return results


def check_disclosure(headers):
    """Identify fingerprinting clues, not confirmed vulnerabilities."""
    headers = {name.lower(): value.strip() for name, value in headers.items()}
    return {name: headers[name.lower()] for name in ("Server", "X-Powered-By")
            if headers.get(name.lower())}


def collect_findings(checks):
    """Turn failed checks into brief advice."""
    findings = []
    if not checks["https"]["enabled"]:
        findings.append(create_finding("HTTPS not enabled", "MEDIUM",
                        "The final response uses unencrypted HTTP.",
                        "Serve the application over HTTPS."))
    advice = {"Strict-Transport-Security": "Set an appropriate positive max-age over HTTPS.",
              "X-Frame-Options": "Use DENY or SAMEORIGIN where appropriate.",
              "X-Content-Type-Options": "Set X-Content-Type-Options to nosniff."}
    for name, status in checks["headers"].items():
        if status in ("missing", "invalid"):
            findings.append(create_finding(f"{status.capitalize()} {name}", SECURITY_HEADERS[name],
                            f"The response has a {status} {name} header.",
                            advice.get(name, f"Consider defining {name} for this application.")))
    for cookie in checks["cookies"]:
        for flag in ("Secure", "HttpOnly", "SameSite"):
            if not cookie[flag]:
                findings.append(create_finding(
                    f"Cookie {cookie['name']}: missing {flag}",
                    "LOW" if flag == "SameSite" else "MEDIUM",
                    f"The cookie lacks a valid {flag} attribute.",
                    f"Consider setting {flag} for this cookie."))
    for name in checks["disclosure"]:
        findings.append(create_finding(f"{name} disclosure", "LOW",
                        "This header may help fingerprint software; it does not prove a vulnerability.",
                        "Consider minimizing unnecessary version information."))
    return findings
