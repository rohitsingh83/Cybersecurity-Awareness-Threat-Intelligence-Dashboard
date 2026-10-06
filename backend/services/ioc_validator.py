"""Syntax-only IOC validation. This module never resolves, visits, or contacts indicators."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_HASH_LENGTHS = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)


def _domain_is_valid(domain: str) -> bool:
    domain = domain.rstrip(".")
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    if any(not label or len(label) > 63 or not _LABEL_RE.fullmatch(label) for label in labels):
        return False
    # Accept reserved demo TLDs such as .invalid and common internationalized A-labels.
    return len(labels[-1]) >= 2


def _canonical_type(value: str | None, raw: str) -> str:
    if value:
        key = value.strip().upper().replace("-", "_")
        aliases = {
            "IP": "IP ADDRESS", "IPV4": "IP ADDRESS", "IPV6": "IP ADDRESS",
            "IP_ADDRESS": "IP ADDRESS", "DOMAIN_NAME": "DOMAIN", "FQDN": "DOMAIN",
            "FILE_HASH": "FILE HASH", "HASH": "FILE HASH", "SHA1": "FILE HASH",
            "SHA_1": "FILE HASH", "SHA256": "FILE HASH", "SHA_256": "FILE HASH",
            "MD5": "FILE HASH", "CVE": "CVE ID", "CVE_ID": "CVE ID",
            "EMAIL": "EMAIL/SENDER DOMAIN", "EMAIL/SENDER DOMAIN": "EMAIL/SENDER DOMAIN",
            "EMAIL_SENDER_DOMAIN": "EMAIL/SENDER DOMAIN",
        }
        return aliases.get(key, key)
    candidate = raw.strip()
    if _CVE_RE.fullmatch(candidate):
        return "CVE ID"
    if len(candidate) in _HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", candidate):
        return "FILE HASH"
    if candidate.lower().startswith(("http://", "https://")):
        return "URL"
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        return "IP ADDRESS"
    except ValueError:
        pass
    if "@" in candidate:
        return "EMAIL/SENDER DOMAIN"
    return "DOMAIN"


def validate_indicator(value: str, indicator_type: str | None = None) -> dict:
    """Return syntactic validity and a canonical value; validity is not reputation."""
    raw = (value or "").strip()
    kind = _canonical_type(indicator_type, raw)
    result = {
        "valid": False,
        "indicator_type": kind,
        "normalized_value": raw,
        "validation_notes": "Syntax check only; this does not determine whether the value is malicious.",
    }
    if not raw:
        result["validation_notes"] = "A value is required. No network lookup was performed."
        return result

    if kind == "IP ADDRESS":
        candidate = raw.strip("[]")
        try:
            parsed = ipaddress.ip_address(candidate)
            result.update(valid=True, normalized_value=parsed.compressed)
            result["validation_notes"] = f"Syntactically valid IPv{parsed.version}; no connection was attempted."
        except ValueError:
            result["validation_notes"] = "Not a valid IPv4 or IPv6 address. No network lookup was performed."
    elif kind == "DOMAIN":
        normalized = raw.lower().rstrip(".")
        result.update(valid=_domain_is_valid(normalized), normalized_value=normalized)
        result["validation_notes"] = (
            "Syntactically valid domain; reputation and ownership were not checked."
            if result["valid"] else "Invalid domain syntax. No DNS lookup was performed."
        )
    elif kind == "EMAIL/SENDER DOMAIN":
        candidate = raw.lower()
        if "@" in candidate:
            parts = candidate.rsplit("@", 1)
            local, domain = parts[0], parts[1]
            valid = bool(local) and len(local) <= 64 and " " not in local and _domain_is_valid(domain)
            normalized = f"{local}@{domain.rstrip('.')}"
        else:
            domain = candidate
            valid = _domain_is_valid(domain)
            normalized = domain.rstrip(".")
        result.update(valid=valid, normalized_value=normalized)
        result["validation_notes"] = (
            "Syntactically valid sender/domain value; mailbox ownership was not checked."
            if valid else "Invalid sender/domain syntax. No email or DNS lookup was performed."
        )
    elif kind == "URL":
        try:
            parsed = urlsplit(raw)
            host = parsed.hostname or ""
            port = parsed.port  # Access forces malformed port validation.
            host_valid = False
            host_is_ipv6 = False
            try:
                parsed_ip = ipaddress.ip_address(host)
                host_valid = True
                host_is_ipv6 = parsed_ip.version == 6
            except ValueError:
                host_valid = _domain_is_valid(host)
            valid = parsed.scheme.lower() in {"http", "https"} and host_valid and not parsed.username and not parsed.password
            if port is not None and not (1 <= port <= 65535):
                valid = False
            if valid:
                netloc = f"[{host.lower()}]" if host_is_ipv6 else host.lower()
                if port is not None:
                    netloc = f"{netloc}:{port}"
                normalized = urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, parsed.fragment))
                result.update(valid=True, normalized_value=normalized)
                result["validation_notes"] = "URL syntax is valid; the URL was not opened or contacted."
            else:
                result["validation_notes"] = "Invalid or unsupported URL syntax; only http/https syntax is accepted. It was not contacted."
        except (ValueError, UnicodeError):
            result["validation_notes"] = "Malformed URL syntax. It was not contacted."
    elif kind == "FILE HASH":
        normalized = raw.lower()
        digest_name = _HASH_LENGTHS.get(len(normalized))
        valid = digest_name is not None and bool(re.fullmatch(r"[0-9a-f]+", normalized))
        result.update(valid=valid, normalized_value=normalized)
        result["validation_notes"] = (
            f"Syntactically valid {digest_name} digest; no file was opened or executed."
            if valid else "Hash must be 32, 40, or 64 hexadecimal characters (MD5/SHA-1/SHA-256 format)."
        )
    elif kind == "CVE ID":
        normalized = raw.upper()
        valid = bool(_CVE_RE.fullmatch(normalized))
        result.update(valid=valid, normalized_value=normalized)
        result["validation_notes"] = (
            "CVE identifier syntax is valid; existence and vulnerability status were not checked."
            if valid else "Expected CVE-YYYY-NNNN… format. Syntax does not confirm a real CVE record."
        )
    else:
        result["validation_notes"] = "Unsupported indicator type. No external lookup was performed."
    return result
