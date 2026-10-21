"""Web and TLS analysis: headers, redirects, security posture, certificate facts.

Uses ``urllib`` from the standard library for the HTTP conversation and a raw
``ssl`` handshake for the certificate, so no third-party package is required.
An optional ``openssl s_client`` path enriches the certificate report when the
binary is available.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from ..core import ui
from ..core.models import CertInfo, Finding, HTTPResult
from ..core.utils import have, run

__all__ = ["WebOptions", "WebResult", "execute", "render", "fetch", "analyse",
           "certificate", "SECURITY_HEADERS", "DISCLOSURE_HEADERS"]

SECURITY_HEADERS: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "medium", "HSTS is missing, so downgrade attacks stay possible."),
    "content-security-policy": (
        "medium", "Without a CSP, injected script executes in your users' browsers."),
    "x-content-type-options": (
        "low", "Missing nosniff lets browsers guess content types."),
    "x-frame-options": (
        "low", "The page may be framed by another site (clickjacking)."),
    "referrer-policy": (
        "low", "Referrer leakage may expose internal URLs."),
    "permissions-policy": (
        "info", "No permissions policy restricts powerful browser features."),
}

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                      "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
                      "x-runtime", "via")

TECH_RULES: list[tuple[str, str, str]] = [
    (r"wp-content|wp-includes|wordpress", "WordPress", "cms"),
    (r"drupal", "Drupal", "cms"),
    (r"joomla", "Joomla", "cms"),
    (r"shopify", "Shopify", "platform"),
    (r"wix\.com", "Wix", "platform"),
    (r"squarespace", "Squarespace", "platform"),
    (r"csrf-token|rails", "Ruby on Rails", "framework"),
    (r"laravel", "Laravel", "framework"),
    (r"django|csrftoken", "Django", "framework"),
    (r"__next_data__|_next/static", "Next.js", "framework"),
    (r"ng-version|angular", "Angular", "framework"),
    (r"react|__react", "React", "framework"),
    (r"vue\.js|__vue__", "Vue.js", "framework"),
    (r"jquery", "jQuery", "library"),
    (r"bootstrap", "Bootstrap", "library"),
    (r"cloudflare", "Cloudflare", "cdn"),
    (r"amazonaws|cloudfront", "AWS", "cloud"),
    (r"azure|azurewebsites", "Microsoft Azure", "cloud"),
    (r"googleusercontent|gstatic", "Google", "cloud"),
    (r"graphql", "GraphQL", "api"),
    (r"swagger|openapi", "Swagger/OpenAPI", "api"),
]


@dataclass
class WebOptions:
    url: str
    timeout: float = 8.0
    follow_redirects: bool = True
    check_tls: bool = True
    user_agent: str = "kmax/1.0 (+authorised security testing)"
    max_body: int = 200_000
    insecure_label: str = ""


@dataclass
class WebResult:
    results: list[HTTPResult] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    endpoints_checked: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0

    @property
    def primary(self) -> HTTPResult | None:
        return self.results[0] if self.results else None


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def normalise_url(raw: str, default_scheme: str = "https") -> str:
    text = raw.strip()
    if not text:
        raise ValueError("empty URL")
    if "://" not in text:
        text = f"{default_scheme}://{text}"
    parts = urllib.parse.urlsplit(text)
    if not parts.hostname:
        raise ValueError(f"could not parse a host from {raw!r}")
    if parts.path == "":
        text = text.rstrip("/") + "/"
    return text


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class _RecordingRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handler that records every hop it follows."""

    def __init__(self) -> None:
        self.chain: list[str] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        self.chain.append(f"{code} {req.full_url} -> {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(opts: WebOptions) -> HTTPResult:
    """Perform one HTTP(S) request and return a populated result."""
    url = normalise_url(opts.url)
    result = HTTPResult(url=url)
    recorder = _RecordingRedirect() if opts.follow_redirects else None

    handlers: list[Any] = []
    if recorder:
        handlers.append(recorder)
    context = ssl.create_default_context()
    if opts.insecure_label:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)

    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": opts.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "close",
    })

    started = time.perf_counter()
    try:
        with opener.open(request, timeout=opts.timeout) as response:
            result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
            result.status = response.status
            result.reason = response.reason or ""
            result.final_url = response.geturl()
            result.headers = {k.lower(): v for k, v in response.headers.items()}
            body = response.read(opts.max_body)
            result.length = len(body)
            result.content_type = result.headers.get("content-type", "")
            result.title = _extract_title(body)
    except urllib.error.HTTPError as exc:
        result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        result.status = exc.code
        result.reason = exc.reason or ""
        result.headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        result.content_type = result.headers.get("content-type", "")
        try:
            body = exc.read(opts.max_body)
            result.length = len(body)
            result.title = _extract_title(body)
        except Exception:
            pass
    except urllib.error.URLError as exc:
        result.reason = f"connection failed: {exc.reason}"
        result.status = 0
    except (socket.timeout, TimeoutError):
        result.reason = f"timed out after {opts.timeout:g}s"
    except Exception as exc:  # pragma: no cover - defensive
        result.reason = f"{type(exc).__name__}: {exc}"

    if recorder and recorder.chain:
        result.redirect_chain = recorder.chain
    result.server = result.headers.get("server", "")
    result.powered_by = result.headers.get("x-powered-by", "")

    if opts.check_tls and url.lower().startswith("https://"):
        host = urllib.parse.urlsplit(url).hostname or ""
        port = urllib.parse.urlsplit(url).port or 443
        result.cert = certificate(host, port, opts.timeout)
    return result


def _extract_title(body: bytes) -> str:
    text = body[:20000].decode("utf-8", "replace")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if match:
        return " ".join(match.group(1).split())[:120]
    match = re.search(r'"title"\s*:\s*"([^"]{1,120})"', text)
    return match.group(1) if match else ""


# --------------------------------------------------------------------------- #
# TLS certificate
# --------------------------------------------------------------------------- #
def _parse_cert_time(value: str) -> datetime | None:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ", "%b %d %H:%M:%S %Y GMT"):
        try:
            parsed = datetime.strptime(value.strip(), fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _flatten_name(name: Any) -> str:
    """Turn an ``ssl`` name tuple into ``k=v, k=v``."""
    try:
        parts: list[str] = []
        for rdn in name:
            for key, value in rdn:
                parts.append(f"{key}={value}")
        return ", ".join(parts)
    except Exception:
        return str(name)


def _openssl_certificate(host: str, port: int, timeout: float) -> tuple[dict[str, str], str]:
    """Handshake facts plus the peer chain, via ``openssl s_client``.

    Returns ``(facts, pem_chain)``. The chain is what ``openssl x509`` needs on
    stdin to describe the leaf certificate when Python has no cryptography
    backend available.
    """
    if not have("openssl"):
        return {}, ""
    code, out, _ = run(
        ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host,
         "-showcerts"],
        timeout=max(5.0, timeout),
        stdin="",
    )
    facts: dict[str, str] = {}
    pem_lines: list[str] = []
    collecting = False
    for line in out.splitlines():
        stripped = line.strip()
        # "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
        if stripped.startswith("New,") and "Cipher is" in stripped:
            parts = [part.strip() for part in stripped.split(",")]
            if len(parts) >= 2 and parts[1] and not parts[1].startswith("Cipher"):
                facts.setdefault("protocol", parts[1])
            cipher = stripped.split("Cipher is", 1)[1].strip()
            if cipher:
                facts.setdefault("cipher", cipher)
            facts.setdefault("protocol_neg", "yes")
        elif stripped.startswith(("Protocol version:", "Protocol :")):
            facts["protocol"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith(("Ciphersuite:", "Cipher    :")):
            facts["cipher"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Signature type:"):
            facts["signature_algorithm"] = stripped.split(":", 1)[1].strip()
        if "-----BEGIN CERTIFICATE-----" in line:
            collecting = True
        if collecting:
            pem_lines.append(line.rstrip())
        if "-----END CERTIFICATE-----" in line:
            collecting = False
            break
    pem = "\n".join(pem_lines)
    if pem:
        pem += "\n"
    return facts, pem


def _parse_x509_text(text: str) -> dict[str, str]:
    """Parse ``openssl x509 -noout ...`` output into a flat dict."""
    facts: dict[str, str] = {}
    key = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            key = ""
            continue
        if stripped.lower().endswith("subject alternative name:"):
            key = "san"
            facts[key] = ""
            continue
        if stripped.lower().startswith(("subject:", "issuer:")) and "=" in stripped:
            label, value = stripped.split(":", 1)
            label = "issuer" if label.strip().lower().startswith("issuer") else "subject"
            if label == "subject":
                _, value = value.split("=", 1)
            else:
                _, value = value.split("=", 1)
            facts[label] = value.strip()
            key = ""
            continue
        if "=" in stripped and not stripped.startswith("-"):
            key, value = stripped.split("=", 1)
            key = key.strip().lower()
            if key in ("notbefore", "notafter", "serial", "sha256 fingerprint"):
                key = key.replace(" ", "_")
            facts[key] = value.strip()
            continue
        if key:
            facts[key] = (facts.get(key, "") + " " + stripped).strip()
    return facts


def _openssl_x509(pem: str, args: list[str], timeout: float) -> dict[str, str]:
    code, out, _ = run(["openssl", "x509", "-noout", *args],
                       timeout=max(5.0, timeout), stdin=pem)
    if code != 0 or not out:
        return {}
    return _parse_x509_text(out)


def _signature_algorithm_from_pem(pem: str, timeout: float) -> str:
    """Read the certificate's own signature algorithm out of ``-text``."""
    code, out, _ = run(["openssl", "x509", "-noout", "-text"],
                       timeout=max(5.0, timeout), stdin=pem)
    if code != 0 or not out:
        return ""
    match = re.search(r"Signature Algorithm:\s*([^\n]+)", out)
    return match.group(1).strip() if match else ""


def _certificate_from_openssl(host: str, port: int, timeout: float) -> tuple[CertInfo | None, dict[str, str]]:
    """Describe the leaf certificate with the ``openssl`` CLI."""
    facts, pem = _openssl_certificate(host, port, timeout)
    if not pem:
        return None, facts
    parsed = _openssl_x509(pem, ["-subject", "-issuer", "-dates", "-serial",
                                 "-fingerprint", "-sha256"], timeout)
    if not parsed.get("subject"):
        parsed = _openssl_x509(pem, ["-subject", "-issuer", "-dates", "-serial"], timeout)
    if not parsed.get("subject"):
        return None, facts
    san_facts = _openssl_x509(pem, ["-ext", "subjectAltName"], timeout)

    info = CertInfo()
    info.subject = parsed.get("subject", "")
    info.issuer = parsed.get("issuer", "")
    info.serial = parsed.get("serial", "")
    info.not_before = parsed.get("notbefore", "")
    info.not_after = parsed.get("notafter", "")
    info.version = 3
    info.signature_algorithm = facts.get("signature_algorithm", "")
    info.protocol = facts.get("protocol", "")
    info.cipher = facts.get("cipher", "")
    info.sans = [entry.strip() for entry in san_facts.get("san", "").split(",")
                 if entry.strip() and "=" not in entry]
    before = _parse_cert_time(info.not_before)
    after = _parse_cert_time(info.not_after)
    if after:
        info.days_remaining = (after - datetime.now(timezone.utc)).days
    info.self_signed = bool(info.subject) and info.subject == info.issuer
    info.wildcard = any(entry.lower().startswith("dns:*.") for entry in info.sans)
    if not info.protocol or not info.cipher:
        negotiate = _negotiated_cipher(host, port, timeout)
        info.protocol = info.protocol or negotiate.get("protocol", "")
        info.cipher = info.cipher or negotiate.get("cipher", "")
    if not info.signature_algorithm:
        info.signature_algorithm = _signature_algorithm_from_pem(pem, timeout)
    return info, facts


def _negotiated_cipher(host: str, port: int, timeout: float) -> dict[str, str]:
    """TLS version/cipher from a plain ``ssl`` handshake (no verification)."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version() or ""
                cipher = tls.cipher()
                return {"protocol": version, "cipher": cipher[0] if cipher else ""}
    except Exception:
        return {}


def certificate(host: str, port: int = 443, timeout: float = 8.0) -> CertInfo:
    """Fetch and describe the X.509 certificate presented by host:port."""
    info, _facts = _certificate_from_openssl(host, port, timeout)
    if info is not None:
        return info

    # Fallback: the standard library. It only decodes names and dates when a
    # cryptography backend is compiled in, so some fields may stay empty.
    info = CertInfo()
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                info.protocol = tls.version() or ""
                cipher = tls.cipher()
                info.cipher = cipher[0] if cipher else ""
                der = tls.getpeercert(binary_form=True) or b""
                decoded = tls.getpeercert() or {}
    except Exception as exc:
        info.subject = f"unavailable ({type(exc).__name__})"
        return info

    if decoded:
        info.subject = _flatten_name(decoded.get("subject", ()))
        info.issuer = _flatten_name(decoded.get("issuer", ()))
        info.serial = str(decoded.get("serialNumber", ""))
        info.version = int(decoded.get("version", 0) or 0) + 1
        info.not_before = decoded.get("notBefore", "")
        info.not_after = decoded.get("notAfter", "")
        before = _parse_cert_time(info.not_before)
        after = _parse_cert_time(info.not_after)
        if after:
            info.days_remaining = (after - datetime.now(timezone.utc)).days
        info.sans = [f"{kind}:{value}" for kind, value in decoded.get("subjectAltName", ())]
        info.self_signed = bool(info.subject) and info.subject == info.issuer
        info.wildcard = any(entry.lower().startswith("dns:*.") for entry in info.sans)
    elif der:
        info.subject = "present but unparsed (no openssl binary and no cryptography backend)"

    if der and not info.signature_algorithm:
        info.signature_algorithm = _signature_algorithm_from_der(der)
    if not info.subject:
        info.subject = "unparsed"
    return info


def _signature_algorithm_from_der(der: bytes) -> str:
    """Very small OID probe for the common signature algorithms."""
    oids = {
        b"\x06\t*\x86H\x86\xf7\r\x01\x01\x0b": "sha256WithRSAEncryption",
        b"\x06\t*\x86H\x86\xf7\r\x01\x01\x0c": "sha384WithRSAEncryption",
        b"\x06\t*\x86H\x86\xf7\r\x01\x01\r": "sha512WithRSAEncryption",
        b"\x06\t*\x86H\x86\xf7\r\x01\x01\x05": "sha1WithRSAEncryption",
        b"\x06\x08*\x86H\xce=\x04\x03\x02": "ecdsa-with-SHA256",
        b"\x06\x08*\x86H\xce=\x04\x03\x03": "ecdsa-with-SHA384",
    }
    for needle, label in oids.items():
        if needle in der[:400]:
            return label
    return ""


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #
def execute(opts: WebOptions) -> WebResult:
    """Check one or more URLs and evaluate web/TLS hardening."""
    started = time.perf_counter()
    result = WebResult()
    for raw in [opts.url]:
        try:
            outcome = fetch(opts)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        result.results.append(outcome)
        result.endpoints_checked.append(outcome.url)
    result.findings = analyse(result)
    result.elapsed_s = round(time.perf_counter() - started, 3)
    return result


def analyse(result: WebResult) -> list[Finding]:
    findings: list[Finding] = []
    for outcome in result.results:
        if outcome.status == 0:
            findings.append(Finding(
                title=f"Could not reach {outcome.url}",
                severity="info",
                detail=outcome.reason or "no response",
                remediation="Confirm the host is up, the port is open and the URL is right.",
                source="webscan",
            ))
            continue

        headers = outcome.headers or {}
        secure = outcome.url.lower().startswith("https://")

        if outcome.status >= 500:
            findings.append(Finding(
                title=f"Server error {outcome.status} at {outcome.url}",
                severity="medium",
                detail=outcome.reason or "upstream failure",
                remediation="Review application logs for the failing request.",
                source="webscan",
            ))
        elif outcome.status in (401, 403):
            findings.append(Finding(
                title=f"Access control active ({outcome.status}) at {outcome.url}",
                severity="good",
                detail="The endpoint requires authentication or is forbidden.",
                source="webscan",
            ))
        elif 300 <= outcome.status < 400:
            findings.append(Finding(
                title=f"Redirect chain of {len(outcome.redirect_chain) or 1} hop(s)",
                severity="info",
                detail="; ".join(outcome.redirect_chain) or f"status {outcome.status}",
                source="webscan",
            ))

        # --- TLS -------------------------------------------------------- #
        if not secure:
            findings.append(Finding(
                title="Site served over plain HTTP",
                severity="high",
                detail="Traffic can be read and modified in transit.",
                remediation="Serve over HTTPS and redirect HTTP with HSTS.",
                source="webscan",
            ))
        elif outcome.cert:
            cert = outcome.cert
            if cert.subject.startswith("unavailable"):
                findings.append(Finding(
                    title="TLS handshake failed",
                    severity="medium",
                    detail=cert.subject,
                    remediation="Check the certificate chain and SNI configuration.",
                    source="webscan",
                ))
            else:
                if cert.days_remaining is not None:
                    if cert.days_remaining < 0:
                        findings.append(Finding(
                            title="Certificate has expired",
                            severity="critical",
                            detail=f"Expired on {cert.not_after} ({-cert.days_remaining} days ago).",
                            remediation="Renew the certificate immediately.",
                            source="webscan",
                        ))
                    elif cert.days_remaining < 14:
                        findings.append(Finding(
                            title="Certificate expires very soon",
                            severity="high",
                            detail=f"{cert.days_remaining} day(s) left (notAfter {cert.not_after}).",
                            remediation="Renew now and automate renewal (ACME).",
                            source="webscan",
                        ))
                    elif cert.days_remaining < 30:
                        findings.append(Finding(
                            title="Certificate expires within 30 days",
                            severity="medium",
                            detail=f"{cert.days_remaining} day(s) left.",
                            remediation="Schedule renewal now.",
                            source="webscan",
                        ))
                    else:
                        findings.append(Finding(
                            title=f"Certificate valid for {cert.days_remaining} day(s)",
                            severity="good",
                            detail=f"Issuer: {cert.issuer or '-'}",
                            source="webscan",
                        ))
                if cert.self_signed:
                    findings.append(Finding(
                        title="Self-signed certificate",
                        severity="medium",
                        detail="Browsers will warn; trust is not anchored to a public CA.",
                        remediation="Use a publicly trusted certificate for user-facing sites.",
                        source="webscan",
                    ))
                if cert.protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                    findings.append(Finding(
                        title=f"Legacy TLS version negotiated ({cert.protocol})",
                        severity="high",
                        detail="TLS 1.0/1.1 are deprecated and insecure.",
                        remediation="Require TLS 1.2+ (ideally 1.3) in the server config.",
                        source="webscan",
                    ))
                elif cert.protocol:
                    findings.append(Finding(
                        title=f"TLS version negotiated: {cert.protocol}",
                        severity="good",
                        detail=f"Cipher: {cert.cipher or '-'}",
                        source="webscan",
                    ))
                if cert.signature_algorithm and "sha1" in cert.signature_algorithm.lower():
                    findings.append(Finding(
                        title="Certificate signed with SHA-1",
                        severity="high",
                        detail=f"Signature algorithm: {cert.signature_algorithm}",
                        remediation="Reissue with SHA-256 or better.",
                        source="webscan",
                    ))
                if cert.wildcard:
                    findings.append(Finding(
                        title="Wildcard certificate in use",
                        severity="info",
                        detail="A wildcard covers every host under the name; scope it tightly.",
                        source="webscan",
                    ))

        # --- security headers ------------------------------------------- #
        if outcome.status and outcome.status < 400:
            missing: list[tuple[str, str, str]] = []
            for header, (severity, detail) in SECURITY_HEADERS.items():
                if header not in headers:
                    missing.append((header, severity, detail))
            if secure:
                for header, severity, detail in missing:
                    findings.append(Finding(
                        title=f"Missing header: {header}",
                        severity=severity, detail=detail,
                        remediation=f"Add the {header} response header.",
                        source="webscan",
                    ))
            present = [h for h in SECURITY_HEADERS if h in headers]
            if present:
                findings.append(Finding(
                    title=f"{len(present)} security header(s) present",
                    severity="good",
                    detail=", ".join(present),
                    source="webscan",
                ))

            hsts = headers.get("strict-transport-security", "")
            if hsts and "max-age" in hsts:
                match = re.search(r"max-age=(\d+)", hsts)
                age = int(match.group(1)) if match else 0
                if age and age < 15552000:
                    findings.append(Finding(
                        title="HSTS max-age is short",
                        severity="low",
                        detail=f"max-age={age}s; 15552000 (180 days) is the usual baseline.",
                        remediation="Raise max-age and consider includeSubDomains; preload.",
                        source="webscan",
                    ))

            csp = headers.get("content-security-policy", "")
            if csp and ("'unsafe-inline'" in csp or "'unsafe-eval'" in csp):
                findings.append(Finding(
                    title="CSP allows unsafe inline/eval",
                    severity="medium",
                    detail="The policy weakens XSS protection significantly.",
                    remediation="Move to nonces or hashes and drop unsafe-inline/unsafe-eval.",
                    source="webscan",
                ))

            if "access-control-allow-origin" in headers and headers["access-control-allow-origin"] == "*":
                findings.append(Finding(
                    title="Permissive CORS (Access-Control-Allow-Origin: *)",
                    severity="medium",
                    detail="Any origin may read responses that do not require credentials.",
                    remediation="Allowlist the specific origins that need access.",
                    source="webscan",
                ))

            cookies = _cookie_lines(headers)
            insecure_cookies = [line for line in cookies if "secure" not in line.lower()]
            if cookies and secure and insecure_cookies:
                findings.append(Finding(
                    title=f"{len(insecure_cookies)} cookie(s) without the Secure flag",
                    severity="medium",
                    detail="; ".join(line.split(";")[0] for line in insecure_cookies[:4]),
                    remediation="Set Secure, HttpOnly and SameSite on session cookies.",
                    source="webscan",
                ))
            if any("httponly" not in line.lower() for line in cookies) and cookies:
                findings.append(Finding(
                    title="Cookie(s) without HttpOnly",
                    severity="low",
                    detail="Script-readable cookies make XSS far more damaging.",
                    remediation="Add HttpOnly to session cookies.",
                    source="webscan",
                ))

        # --- information disclosure ------------------------------------- #
        disclosed = {header: headers[header] for header in DISCLOSURE_HEADERS if header in headers}
        if disclosed:
            detail = ", ".join(f"{key}: {value}" for key, value in disclosed.items())
            severity = "medium" if any(
                re.search(r"\d+\.\d+", value) for value in disclosed.values()
            ) else "low"
            findings.append(Finding(
                title="Technology disclosure in response headers",
                severity=severity, detail=detail,
                remediation="Suppress or genericise version banners (server_tokens off, etc.).",
                source="webscan",
            ))

        for pattern, name, category in TECH_RULES:
            if pattern in (outcome.powered_by or "").lower():
                findings.append(Finding(
                    title=f"Technology detected: {name} ({category})",
                    severity="info",
                    detail="Detected from the X-Powered-By header.",
                    source="webscan",
                ))
                break

        if outcome.length == 0 and outcome.status == 200:
            findings.append(Finding(
                title="Empty 200 response body",
                severity="info",
                detail="The endpoint answered but returned no content (HEAD-like behaviour).",
                source="webscan",
            ))

    return findings


def _cookie_lines(headers: dict[str, str]) -> list[str]:
    raw = headers.get("set-cookie", "")
    return [chunk.strip() for chunk in raw.split(",") if chunk.strip()] if raw else []


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def render(result: WebResult, report=None) -> None:
    ui.section("Web & TLS analysis", "\u25c6")
    for outcome in result.results:
        ui.kv([
            ("URL", outcome.url),
            ("Status", f"{outcome.status} {outcome.reason}".strip() or "no response"),
            ("Final URL", outcome.final_url or outcome.url),
            ("Server", outcome.server or "-"),
            ("Powered by", outcome.powered_by or "-"),
            ("Content type", outcome.content_type or "-"),
            ("Length", outcome.length),
            ("Elapsed", f"{outcome.elapsed_ms:.0f}ms"),
        ])
        if outcome.title:
            ui.plain(f"  {ui.c('Title', 'cyan')} : {outcome.title}")

        if outcome.redirect_chain:
            ui.section("Redirect chain", "\u21b3")
            arrow = ui.c("\u2192", "gray")
            for hop in outcome.redirect_chain:
                ui.plain(f"  {arrow} {hop}")

        if outcome.headers:
            ui.section("Response headers", "\u25c8")
            ui.table(["Header", "Value"],
                     [[key, value[:110]] for key, value in sorted(outcome.headers.items())],
                     limit=140)

        if outcome.cert and not outcome.cert.subject.startswith("unavailable"):
            cert = outcome.cert
            ui.section("TLS certificate", "\u25c8")
            ui.kv([
                ("Subject", cert.subject),
                ("Issuer", cert.issuer),
                ("Valid from/to", f"{cert.not_before} -> {cert.not_after}"),
                ("Days remaining", cert.days_remaining if cert.days_remaining is not None else "-"),
                ("Protocol", cert.protocol or "-"),
                ("Cipher", cert.cipher or "-"),
                ("Signature", cert.signature_algorithm or "-"),
                ("Self-signed", "yes" if cert.self_signed else "no"),
                ("Wildcard", "yes" if cert.wildcard else "no"),
            ])
            if cert.sans:
                ui.plain(f"  {ui.c('SANs', 'cyan')} : " + ", ".join(cert.sans[:12]))

    if result.findings:
        ui.section("Web hardening findings", "\u2691")
        for finding in result.findings:
            ui.plain(f"  {ui.severity_tag(finding.severity)} {finding.title}")
            if finding.detail:
                ui.plain(f"        {ui.c(finding.detail, 'gray')}")

    if report is not None:
        for outcome in result.results:
            report.kv(f"Web & TLS - {outcome.url}", [
                ("Status", f"{outcome.status} {outcome.reason}".strip()),
                ("Final URL", outcome.final_url or outcome.url),
                ("Server", outcome.server or "-"),
                ("Content type", outcome.content_type or "-"),
                ("Length", outcome.length),
                ("Elapsed", f"{outcome.elapsed_ms:.0f}ms"),
            ])
            report.table("Response headers", ["Header", "Value"],
                         [[key, value] for key, value in sorted(outcome.headers.items())],
                         limit=200)
            if outcome.redirect_chain:
                report.text("Redirect chain", "\n".join(outcome.redirect_chain))
            if outcome.cert and not outcome.cert.subject.startswith("unavailable"):
                cert = outcome.cert
                report.table("TLS certificate", ["Field", "Value"], [
                    ["Subject", cert.subject],
                    ["Issuer", cert.issuer],
                    ["Valid from", cert.not_before],
                    ["Valid to", cert.not_after],
                    ["Days remaining", cert.days_remaining],
                    ["Protocol", cert.protocol],
                    ["Cipher", cert.cipher],
                    ["Signature algorithm", cert.signature_algorithm],
                    ["Self-signed", "yes" if cert.self_signed else "no"],
                    ["SANs", ", ".join(cert.sans)],
                ])
        report.findings(result.findings, "Web hardening findings")
        report.note("web", [{
            "url": outcome.url,
            "status": outcome.status,
            "server": outcome.server,
            "tls_days_remaining": outcome.cert.days_remaining if outcome.cert else None,
        } for outcome in result.results])


def probe_paths(base: str, paths: Iterable[str], opts: WebOptions) -> list[HTTPResult]:
    """Check a list of well-known paths (robots.txt, .git/config, ...)."""
    results: list[HTTPResult] = []
    for path in paths:
        target = urllib.parse.urljoin(base, path.lstrip("/"))
        local = WebOptions(**{**opts.__dict__, "url": target, "check_tls": False})
        try:
            results.append(fetch(local))
        except Exception:
            continue
    return results


def header_json(headers: dict[str, str]) -> str:
    return json.dumps(headers, indent=2, sort_keys=True)


def default_tls_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def http_client_for(url: str, timeout: float) -> http.client.HTTPConnection:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        return http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout)
    return http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)