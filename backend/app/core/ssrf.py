import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple
from app.core.config import settings


# Cloud metadata IP addresses and endpoints
CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, OpenStack
    "fd00:ec2::254",     # AWS IPv6 IMDS
    "100.100.100.200",   # Alibaba Cloud
    "192.0.0.192",       # Oracle Cloud
}

BLOCKED_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
}


class SSRFValidationError(Exception):
    """Raised when an outbound URL violates SSRF safety policy."""
    pass


def is_ip_private_or_restricted(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is in a private, loopback, link-local, 
    cloud-metadata, or multicast range.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, "Invalid IP address format."

    if str(ip) in CLOUD_METADATA_IPS:
        return True, "Access to Cloud Metadata service IP is strictly blocked."

    if ip.is_loopback:
        return True, "Loopback address (127.0.0.0/8 or ::1) is restricted."

    if ip.is_link_local:
        return True, "Link-local address (169.254.0.0/16 or fe80::/10) is restricted."

    if ip.is_multicast:
        return True, "Multicast address is restricted."

    if ip.is_private:
        return True, "RFC 1918 / RFC 4193 Private IP space is restricted."

    if ip.is_reserved:
        return True, "Reserved IP space is restricted."

    if ip.is_unspecified:
        return True, "Unspecified 0.0.0.0 IP is restricted."

    return False, ""


def validate_target_url(url: str, allow_local_override: bool = False) -> Tuple[bool, str]:
    """
    Strictly validates target URL before any outbound network probe or scan.
    Enforces scheme checking, hostname resolution, and SSRF filtering.
    """
    if not url or not isinstance(url, str):
        return False, "URL is missing or invalid."

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {str(e)}"

    # 1. Enforce HTTP/HTTPS only
    if parsed.scheme.lower() not in ("http", "https"):
        return False, f"Forbidden URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

    hostname = parsed.hostname
    if not hostname:
        return False, "URL must contain a valid hostname."

    hostname_lower = hostname.lower()

    # 2. Block known cloud metadata hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Destination hostname '{hostname}' is blocked for SSRF protection."

    # 3. Check blocked domains from settings
    if hostname_lower in settings.BLOCKED_DOMAINS:
        return False, f"Destination hostname '{hostname}' is in the platform blocklist."

    # 4. Check allowed domains if allowlist is configured
    if settings.ALLOWED_DOMAINS and hostname_lower not in settings.ALLOWED_DOMAINS:
        return False, f"Destination hostname '{hostname}' is not in the allowed scanning domains list."

    # 5. Local development / demo test mode handling
    allow_local = allow_local_override or settings.ALLOW_LOCAL_TARGETS
    if allow_local and hostname_lower in ("localhost", "127.0.0.1", "::1", "demo-api", "host.docker.internal"):
        return True, "Target approved under local development / authorized demo policy."

    # 6. Resolve DNS and inspect resolved IPs
    try:
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        resolved_ips = {res[4][0] for res in addr_info}
    except socket.gaierror:
        return False, f"DNS resolution failed for hostname '{hostname}'."
    except Exception as e:
        return False, f"Network inspection error: {str(e)}"

    if not resolved_ips:
        return False, f"No IP addresses resolved for hostname '{hostname}'."

    # Check each resolved IP
    for resolved_ip in resolved_ips:
        is_restricted, reason = is_ip_private_or_restricted(resolved_ip)
        if is_restricted:
            if allow_local and (resolved_ip.startswith("127.") or resolved_ip == "::1"):
                continue
            return False, f"SSRF Protection triggered: Host '{hostname}' resolved to restricted IP '{resolved_ip}'. Reason: {reason}"

    return True, "Target URL passed SSRF safety checks."
