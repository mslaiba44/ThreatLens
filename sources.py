"""
sources.py
==========
Threat-intelligence source layer for ThreatLens.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

import requests
import streamlit as st

try:
    import whois as whois_lib
except ImportError:
    whois_lib = None


def make_result(
    source_verdict: str = "unknown",
    risk_source: str = "unknown",
    raw_data: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "source_verdict": source_verdict,
        "risk_source": risk_source,
        "raw_data": raw_data or {},
        "error": error,
    }


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_url(value: str) -> bool:
    if "://" not in value:
        return False
    try:
        parsed = urlparse(value)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except ValueError:
        return False


def _is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value))


def detect_ioc_type(value: str) -> str:
    value = value.strip()
    if not value:
        return "unknown"
    if _is_url(value):
        return "url"
    if _is_ip(value):
        return "ip"
    if _is_domain(value):
        return "domain"
    return "unknown"


def is_valid_ioc(value: str, ioc_type: str) -> bool:
    value = value.strip()
    if not value:
        return False
    if ioc_type == "ip":
        return _is_ip(value)
    if ioc_type == "domain":
        return _is_domain(value)
    if ioc_type == "url":
        return _is_url(value)
    return False


def extract_domain(value: str) -> Optional[str]:
    value = value.strip()
    if _is_ip(value):
        return None
    if _is_url(value):
        parsed = urlparse(value)
        hostname = parsed.hostname
        return hostname.lower() if hostname else None
    if _is_domain(value):
        return value.lower()
    return None


_VT_BASE_URL = "https://www.virustotal.com/api/v3"


def _get_vt_api_key() -> Optional[str]:
    try:
        return st.secrets["api_keys"]["virustotal"]
    except Exception:
        return None


def _vt_risk_from_stats(stats: Dict[str, int]) -> tuple[str, str]:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return "unknown", "unknown"
    if malicious >= 5:
        return "malicious", "critical"
    if malicious >= 1:
        return "malicious", "high"
    if suspicious >= 3:
        return "suspicious", "medium"
    if suspicious >= 1:
        return "suspicious", "low"
    return "safe", "low"


def get_virustotal(ioc: str, ioc_type: str) -> Dict[str, Any]:
    api_key = _get_vt_api_key()
    if not api_key:
        return make_result(error="VirusTotal API key is missing from secrets.")

    headers = {"x-apikey": api_key}

    try:
        if ioc_type == "ip":
            url = f"{_VT_BASE_URL}/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"{_VT_BASE_URL}/domains/{ioc}"
        elif ioc_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{_VT_BASE_URL}/urls/{url_id}"
        else:
            return make_result(error=f"Unsupported IOC type for VirusTotal: {ioc_type}")

        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code == 401:
            return make_result(error="VirusTotal API key is invalid or unauthorized.")
        if response.status_code == 429:
            return make_result(error="VirusTotal rate limit exceeded. Try again later.")
        if response.status_code == 404:
            return make_result(
                source_verdict="unknown",
                risk_source="unknown",
                raw_data={"note": "No existing VirusTotal record found for this IOC."},
            )
        if not response.ok:
            return make_result(error=f"VirusTotal API returned HTTP {response.status_code}.")

        payload = response.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        verdict, risk = _vt_risk_from_stats(stats)

        raw_data = {
            "last_analysis_stats": stats,
            "reputation": attributes.get("reputation"),
            "categories": attributes.get("categories"),
            "last_analysis_date": attributes.get("last_analysis_date"),
        }
        raw_data = {k: v for k, v in raw_data.items() if v not in (None, {}, [])}

        return make_result(source_verdict=verdict, risk_source=risk, raw_data=raw_data)

    except requests.exceptions.Timeout:
        return make_result(error="VirusTotal request timed out.")
    except requests.exceptions.ConnectionError:
        return make_result(error="Could not connect to VirusTotal (network error).")
    except requests.exceptions.RequestException as exc:
        return make_result(error=f"VirusTotal request failed: {exc}")
    except (ValueError, KeyError) as exc:
        return make_result(error=f"VirusTotal returned an unexpected response: {exc}")
    except Exception as exc:
        return make_result(error=f"Unexpected VirusTotal error: {exc}")


def _whois_risk_from_record(record: Dict[str, Any]) -> tuple[str, str]:
    if not record:
        return "unknown", "unknown"
    return "unknown", "unknown"


def get_whois(ioc: str, ioc_type: str) -> Dict[str, Any]:
    try:
        if ioc_type == "ip":
            raw_data: Dict[str, Any] = {}
            try:
                host, _, _ = socket.gethostbyaddr(ioc)
                raw_data["reverse_dns"] = host
            except (socket.herror, socket.gaierror):
                raw_data["reverse_dns"] = None
                raw_data["note"] = "No reverse DNS record found for this IP."
            return make_result(source_verdict="unknown", risk_source="unknown", raw_data=raw_data)

        domain = ioc if ioc_type == "domain" else extract_domain(ioc)
        if not domain:
            return make_result(error="Could not extract a domain for WHOIS lookup.")


        if whois_lib is None:
            return make_result(error="WHOIS lookup library is not installed on the server.")

        record = whois_lib.whois(domain)
        if not record or not getattr(record, "domain_name", None):
            return make_result(
                source_verdict="unknown",
                risk_source="unknown",
                raw_data={"note": "No WHOIS record found for this domain."},
            )

        def _stringify(value: Any) -> Any:
            if isinstance(value, list):
                return [str(v) for v in value]
            if value is None:
                return None
            return str(value)

        raw_data = {
            "domain_name": _stringify(record.domain_name),
            "registrar": _stringify(getattr(record, "registrar", None)),
            "creation_date": _stringify(getattr(record, "creation_date", None)),
            "expiration_date": _stringify(getattr(record, "expiration_date", None)),
            "updated_date": _stringify(getattr(record, "updated_date", None)),
            "name_servers": _stringify(getattr(record, "name_servers", None)),
            "status": _stringify(getattr(record, "status", None)),
            "org": _stringify(getattr(record, "org", None)),
            "country": _stringify(getattr(record, "country", None)),
        }
        raw_data = {k: v for k, v in raw_data.items() if v not in (None, "", [])}

        verdict, risk = _whois_risk_from_record(raw_data)
        return make_result(source_verdict=verdict, risk_source=risk, raw_data=raw_data)

    except Exception as exc:
        return make_result(error=f"WHOIS lookup failed: {exc}")


SourceFunction = Callable[[str, str], Dict[str, Any]]

SOURCES: Dict[str, SourceFunction] = {
    "VirusTotal": get_virustotal,
    "WHOIS": get_whois,
}
