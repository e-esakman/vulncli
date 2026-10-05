"""Checks use fake metadata and never contact a website."""

from types import SimpleNamespace

import pytest

from checks import check_cookies, check_disclosure, check_headers, check_https, collect_findings
from findings import create_finding


def test_security_headers():
    result = check_headers({"Content-Type": "text/html; charset=utf-8",
                            "content-security-policy": "default-src 'self'",
                            "X-Frame-Options": ""})
    assert result["Content-Security-Policy"] == "present"
    assert result["X-Frame-Options"] == "missing"
    assert result["Strict-Transport-Security"] == "missing"
    result = check_headers({"Content-Type": "application/json"}, https=False)
    assert result["Content-Security-Policy"].startswith("skipped")
    assert result["X-Frame-Options"].startswith("skipped")
    assert result["Strict-Transport-Security"].startswith("skipped")
    assert not any("Content-Security-Policy" in f["name"] for f in collect_findings(
        dict(https={"enabled": False}, headers=result, cookies=[], disclosure={})))


def test_header_values():
    headers = {"Content-Type": "text/html", "Strict-Transport-Security": "max-age=31536000",
               "X-Frame-Options": "SAMEORIGIN", "X-Content-Type-Options": "nosniff"}
    assert all(check_headers(headers)[name] == "present" for name in headers if name != "Content-Type")
    for value in ("max-age=0", "max-age=-1", "includeSubDomains", "max-age=1; max-age=bad"):
        assert check_headers({"Strict-Transport-Security": value})["Strict-Transport-Security"] == "invalid"
    headers.update({"X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "wrong"})
    assert check_headers(headers)["X-Frame-Options"] == "invalid"
    assert check_headers(headers)["X-Content-Type-Options"] == "invalid"


def test_cookie_flags():
    cookies = check_cookies([
        "session=abc; Secure; HttpOnly; SameSite=Lax; Expires=Wed, 09 Jun 2027 10:18:14 GMT",
        "theme=dark; SameSite=invalid",
    ])
    assert cookies[0] == dict(name="session", Secure=True, HttpOnly=True, SameSite=True)
    assert cookies[1] == dict(name="theme", Secure=False, HttpOnly=False, SameSite=False)


def test_information_disclosure():
    assert check_disclosure({"server": "nginx", "X-Powered-By": "Express"}) == {
        "Server": "nginx", "X-Powered-By": "Express"}
    assert check_disclosure({}) == {}


def test_https_detection():
    response = SimpleNamespace(url="https://example.test")
    assert check_https(response, "http://example.test")["http_redirects_to_https"] is True
    assert check_https(response, "https://example.test")["http_redirects_to_https"] is None
    response.url = "http://example.test"
    assert check_https(response, "http://example.test")["http_redirects_to_https"] is False
    assert check_https(response, "https://example.test")["enabled"] is False
