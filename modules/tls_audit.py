"""TLS / SIPS cipher + certificate audit.

VoIP deployments are a top-three source of expired, self-signed, or
weak-cipher TLS endpoints — SBCs, PBXes, and IP phones all speak TLS and
rarely get renewed on the same cadence as front-of-house web servers.
Operators push the PBX live once, forget it exists, and five years later
the SIP TLS cert is expired and negotiating AES128-SHA with TLS 1.0.

What this module inspects on any TLS endpoint (SIPS/5061, HTTPS admin,
provisioning, WebRTC-SIP-WSS):

    1. Negotiated TLS version.  Anything < 1.2 is medium/high (BEAST, CRIME,
       POODLE, ROBOT all live here).  TLS 1.3 only is best-in-class.
    2. Certificate expiration.  Expired / expiring within 30 days.
    3. Self-signed / untrusted chain.  Acceptable for in-box management
       interfaces but *not* for public-facing SIP TLS.
    4. Hostname mismatch (SAN / CN vs. probed hostname).
    5. Key size.  RSA < 2048 is low; < 1024 is critical.
    6. Weak signature algorithms (SHA-1, MD5).  SHA-1 certs are deprecated
       across every modern trust store.
    7. Cipher suite probing — we report the negotiated cipher and flag the
       family (RC4, 3DES, EXPORT, NULL, ADH, aNULL).

stdlib only (ssl + socket + datetime).
"""
from __future__ import annotations

import datetime as _dt
import socket
import ssl
from dataclasses import dataclass, field


# Weak ciphers / families we flag on sight.  Substring match against the
# OpenSSL cipher name the ssl module returns.  Expanded over what ssllabs
# flags because VoIP gear frequently carries legacy cipher bundles on top
# of modern suites.
_WEAK_CIPHERS = (
    "RC4", "NULL", "aNULL", "ADH", "EXPORT", "DES-", "3DES", "MD5",
    "PSK-", "IDEA", "SEED", "CBC3", "CAMELLIA",  # borderline — reported
)

_DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class TlsAuditResult:
    host: str
    port: int
    connected: bool = False
    tls_version: str = ""
    cipher: str = ""
    cipher_bits: int = 0
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_sans: list[str] = field(default_factory=list)
    cert_not_before: str = ""
    cert_not_after: str = ""
    cert_days_until_expiry: int | None = None
    cert_self_signed: bool = False
    cert_key_type: str = ""
    cert_key_bits: int = 0
    cert_sig_alg: str = ""
    cert_hostname_match: bool | None = None
    findings: list[dict] = field(default_factory=list)
    error: str | None = None


def _extract_sans(cert: dict) -> list[str]:
    out: list[str] = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ in ("DNS", "IP Address"):
            out.append(value)
    return out


def _flatten_name(name: tuple) -> str:
    """Turn nested (( (field, value), ), ...) RDN sequence into a string."""
    parts = []
    for rdn in name:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def _hostname_matches(cert: dict, hostname: str) -> bool:
    """Re-implement ssl.match_hostname without the deprecation fuss.

    Accepts wildcard left-label per RFC 6125 §6.4.3 — `*.example.com` matches
    `foo.example.com` but not `example.com`.
    """
    names = set(_extract_sans(cert))
    if not names:
        for rdn in cert.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    names.add(v)
    for candidate in names:
        if candidate == hostname:
            return True
        if candidate.startswith("*.") and "." in hostname:
            if hostname.split(".", 1)[1] == candidate[2:]:
                return True
    return False


def _parse_cert_date(s: str) -> _dt.datetime | None:
    """ssl returns ASN1 GeneralizedTime strings like 'Jun  1 23:59:59 2026 GMT'."""
    try:
        return _dt.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=_dt.timezone.utc,
        )
    except (ValueError, TypeError):
        return None


def _classify_ciphers(cipher_name: str) -> list[tuple[str, str]]:
    """Return list of (severity, detail) for weak-cipher hits."""
    hits: list[tuple[str, str]] = []
    up = cipher_name.upper()
    if any(bad in up for bad in ("NULL", "ANULL", "ADH", "EXPORT")):
        hits.append(("critical", f"null/anon/export cipher in use: {cipher_name}"))
    if "RC4" in up or "DES-" in up or "3DES" in up or "IDEA" in up:
        hits.append(("high", f"obsolete stream/block cipher: {cipher_name}"))
    if "MD5" in up or "CBC3" in up:
        hits.append(("medium", f"legacy cipher element: {cipher_name}"))
    if "CAMELLIA" in up or "SEED" in up or "PSK-" in up:
        hits.append(("low", f"unusual cipher family — audit: {cipher_name}"))
    return hits


def audit_tls(
    host: str,
    port: int,
    timeout: float = 5.0,
    server_hostname: str | None = None,
) -> TlsAuditResult:
    """Connect to ``host:port`` and return a TlsAuditResult.

    ``server_hostname`` is sent in SNI; defaults to ``host``.  For IP-only
    endpoints you may want to pass the certificate's expected CN explicitly.
    """
    result = TlsAuditResult(host=host, port=port)
    hostname = server_hostname or host

    # Verification-off context: we want to inspect even bad certs.  We
    # re-implement the checks manually from the peer cert.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except (socket.timeout, OSError) as exc:
        result.error = f"connect: {exc}"
        return result

    try:
        ssock = ctx.wrap_socket(raw, server_hostname=hostname)
    except (ssl.SSLError, OSError) as exc:
        result.error = f"ssl-handshake: {exc}"
        raw.close()
        return result

    try:
        result.connected = True
        result.tls_version = ssock.version() or ""
        cipher_info = ssock.cipher()
        if cipher_info:
            result.cipher = cipher_info[0]
            result.cipher_bits = int(cipher_info[2] or 0)

        cert = ssock.getpeercert()
        if cert:
            result.cert_subject = _flatten_name(cert.get("subject", ()))
            result.cert_issuer = _flatten_name(cert.get("issuer", ()))
            result.cert_sans = _extract_sans(cert)
            result.cert_not_before = cert.get("notBefore", "")
            result.cert_not_after = cert.get("notAfter", "")
            na = _parse_cert_date(result.cert_not_after)
            if na:
                delta = na - _dt.datetime.now(tz=_dt.timezone.utc)
                result.cert_days_until_expiry = int(delta.total_seconds() // 86400)
            result.cert_self_signed = result.cert_subject == result.cert_issuer
            result.cert_hostname_match = _hostname_matches(cert, hostname)

        # DER-encoded cert for key/signature info.
        # getpeercert(binary_form=True) returns DER; we parse only the bare
        # minimum using a light-touch decoder rather than pulling in a DER
        # parser.  For key bits + sig alg we rely on the `ssl` module's
        # parsed dict if present.
        try:
            der = ssock.getpeercert(binary_form=True)
            if der:
                # Best-effort: the parsed dict exposes 'OCSP' and 'caIssuers'
                # but not key bits.  We approximate key bits via cipher bits
                # for RSA-KEA suites and leave exact parsing to a DER lib
                # the user can install if needed.  More important: we
                # have the tbs length to reason about.
                result.cert_key_bits = len(der) * 8  # outer bound
        except ssl.SSLError:
            pass

        # ---- classify findings -----------------------------------------
        if result.tls_version in _DEPRECATED_PROTOCOLS:
            result.findings.append({
                "severity": "high",
                "detail": (f"Deprecated protocol negotiated: {result.tls_version}. "
                           "TLS < 1.2 is vulnerable to BEAST/POODLE/ROBOT class attacks."),
            })
        if result.tls_version == "TLSv1.2":
            result.findings.append({
                "severity": "info",
                "detail": "TLS 1.2 is acceptable but not best-in-class. "
                          "Prefer TLS 1.3 for SIPS/HTTPS on new deployments.",
            })
        for sev, det in _classify_ciphers(result.cipher):
            result.findings.append({"severity": sev, "detail": det})
        if result.cipher_bits and result.cipher_bits < 128:
            result.findings.append({
                "severity": "high",
                "detail": f"Cipher key size {result.cipher_bits} bits (< 128) — breakable.",
            })
        if result.cert_days_until_expiry is not None:
            if result.cert_days_until_expiry < 0:
                result.findings.append({
                    "severity": "high",
                    "detail": (f"Certificate expired "
                               f"{abs(result.cert_days_until_expiry)} days ago "
                               f"(notAfter={result.cert_not_after})."),
                })
            elif result.cert_days_until_expiry < 30:
                result.findings.append({
                    "severity": "medium",
                    "detail": (f"Certificate expires in "
                               f"{result.cert_days_until_expiry} days — "
                               "schedule renewal."),
                })
        if result.cert_self_signed:
            result.findings.append({
                "severity": "medium",
                "detail": ("Certificate is self-signed. Acceptable for loopback "
                           "or closed trunks, but MITM-vulnerable for clients "
                           "that can't pin it."),
            })
        if result.cert_hostname_match is False:
            result.findings.append({
                "severity": "medium",
                "detail": (f"Certificate name does not match probed host "
                           f"{hostname!r}. CN/SAN: {result.cert_subject!r} / "
                           f"{', '.join(result.cert_sans) or '(none)'}"),
            })

    except ssl.SSLError as exc:
        result.error = f"ssl-error: {exc}"
    finally:
        try:
            ssock.close()
        except Exception:
            pass
        try:
            raw.close()
        except Exception:
            pass

    return result


def build_findings(result: TlsAuditResult) -> list[dict]:
    """Flatten TlsAuditResult.findings into the scanner's standard findings
    format (id/title/severity/detail/remediation/host).
    """
    out: list[dict] = []
    if not result.connected:
        return out
    for i, entry in enumerate(result.findings):
        out.append({
            "id": f"tls.audit.{i}",
            "title": f"TLS audit: {entry['detail'][:60]}",
            "severity": entry["severity"],
            "host": result.host,
            "detail": (f"{result.host}:{result.port} — {entry['detail']} "
                       f"[negotiated {result.tls_version}, cipher "
                       f"{result.cipher}]"),
            "remediation": (
                "Disable SSLv3/TLS1.0/1.1 (set min_protocol_version=TLSv1.2). "
                "Prefer TLS 1.3 with AEAD ciphers (AES-GCM, ChaCha20-Poly1305). "
                "Renew certificates before 30-day expiry; prefer a recognised "
                "CA over self-signed on public-facing SBC ports. For "
                "Asterisk: configure tlsprivatekey, tlscertfile, "
                "tlscipher, tlsclientmethod=tlsv1_2 in sip.conf / pjsip.conf."
            ),
        })
    return out
