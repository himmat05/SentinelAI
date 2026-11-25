"""
SentinelAI - Security Guards & Operator Authentication
====================================================
Provides SSRF-safe upstream URL validation, constant-time operator API-key
verification, and security helper utilities.
"""

import hmac
import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urlparse

from fastapi import Header, HTTPException, Request, status

_FORBIDDEN_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.goog",
    "169.254.169.254",
    "0.0.0.0",
}


def _is_unsafe_ip(ip_str: str) -> bool:
    """Return True if IP address belongs to loopback, private, link-local, or reserved space."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def validate_upstream_url(url: str, allow_private: Optional[bool] = None) -> str:
    """
    Validate and normalize an external HTTP/HTTPS upstream or webhook URL.
    Prevents SSRF attacks targeting localhost, RFC1918 networks, or cloud metadata APIs.
    """
    raw = (url or "").strip()
    if not raw:
        raise ValueError("URL cannot be empty.")

    if "://" in raw:
        if not raw.lower().startswith(("http://", "https://")):
            raise ValueError("Only http:// and https:// URLs are permitted.")
    else:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are permitted.")

    if not parsed.netloc or not parsed.hostname:
        raise ValueError("URL must include a valid hostname.")

    if parsed.username or parsed.password:
        raise ValueError("Embedded URL credentials are not permitted.")

    hostname = parsed.hostname.lower().strip(".")
    if not hostname:
        raise ValueError("Invalid hostname.")

    if allow_private is None:
        allow_private = os.environ.get("SENTINEL_ALLOW_PRIVATE_UPSTREAM", "false").lower() == "true"

    if not allow_private:
        if hostname in _FORBIDDEN_HOSTNAMES or hostname.endswith(".local") or hostname.endswith(".internal"):
            raise ValueError(f"Blocked potentially unsafe internal hostname: '{hostname}'.")

        # Direct IP literal check
        try:
            ipaddress.ip_address(hostname)
            if _is_unsafe_ip(hostname):
                raise ValueError(f"Blocked private/loopback/link-local upstream IP: '{hostname}'.")
        except ValueError as exc:
            if "Blocked private" in str(exc):
                raise
            # Hostname: resolve DNS if reachable and verify all resolved A/AAAA records
            try:
                addr_infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
                for info in addr_infos:
                    resolved_ip = info[4][0]
                    if _is_unsafe_ip(resolved_ip):
                        raise ValueError(
                            f"Hostname '{hostname}' resolves to unsafe non-public IP '{resolved_ip}'."
                        )
            except socket.gaierror:
                # If DNS cannot resolve (e.g., offline sandbox test), hostname lexical checks already ran
                pass

    return raw.rstrip("/")


def get_configured_admin_token() -> str:
    """Fetch configured operator authentication token from environment."""
    return os.environ.get("SENTINEL_ADMIN_TOKEN", "").strip()


def extract_request_token(
    x_sentinel_token: Optional[str] = None,
    authorization: Optional[str] = None,
) -> str:
    """Extract token from X-Sentinel-Token or Bearer Authorization header."""
    if x_sentinel_token:
        return x_sentinel_token.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def is_local_dev_client(request: Request) -> bool:
    """Check whether TCP peer is direct localhost (never trusting spoofable X-Forwarded-For)."""
    host = request.client.host if request.client else ""
    return host in {"127.0.0.1", "::1", "localhost", "testclient"}


async def require_operator_auth(
    request: Request,
    x_sentinel_token: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> str:
    """
    FastAPI dependency enforcing operator authentication on administrative mutations.
    - When SENTINEL_ADMIN_TOKEN is set: strictly validates token via constant-time compare.
    - When unset: permits direct localhost developer access only; blocks remote peers with 403.
    """
    configured_token = get_configured_admin_token()
    provided_token = extract_request_token(x_sentinel_token, authorization)

    if configured_token:
        if not provided_token or not hmac.compare_digest(provided_token, configured_token):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing SentinelAI operator token (set X-Sentinel-Token header).",
            )
        return "token"

    allow_local_dev = os.environ.get("SENTINEL_ALLOW_LOCALHOST_DEV", "true").lower() == "true"
    if allow_local_dev and is_local_dev_client(request):
        return "localhost-dev"

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Remote operator access requires SENTINEL_ADMIN_TOKEN to be configured on the server.",
    )
