import re
from typing import Optional

from ..FileCache import FileCache
from .curl import send_query


# Regex to match IPv4 addresses
REGEX_IP = re.compile(
    r"(?!0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)


def get_device_ip(
    cache_timeout: Optional[int] = 300000, timeout: int = 30000, verbose: bool = False
) -> str:
    """Get the current device public IP using multiple IP services.

    This function caches the discovered IP to `tmp/device-ip.json` using
    `FileCache`. It tries a list of well-known IP endpoints and returns the
    first successful match. On failure returns an empty string.

    Parameters
    ----------
    cache_timeout: Optional[int]
        Cache TTL in milliseconds for the discovered IP. Default 300000 (5 minutes).
    timeout: int
        Per-request timeout in milliseconds passed to `send_query`.
    verbose: bool
        Enable verbose output for underlying requests.
    """
    cache = FileCache("tmp/device-ip.json")

    cached = cache.read_cache()
    if cached:
        return cached

    ip_services = [
        "https://api64.ipify.org",
        "https://ipinfo.io/ip",
        "https://api.myip.com",
        "https://ip.42.pl/raw",
        "https://ifconfig.me/ip",
        "https://cloudflare.com/cdn-cgi/trace",
        "https://httpbin.org/ip",
        "https://api.ipify.org",
    ]

    resp = None
    for url in ip_services:
        resp = send_query(url=url, timeout=timeout, verbose=verbose)
        if resp and not getattr(resp, "error", False):
            break
    if not resp or getattr(resp, "error", False):
        return ""

    match = REGEX_IP.search(resp.response or "")
    if match:
        ip = match.group(0)
        # FileCache expects seconds; convert milliseconds -> seconds
        expires_seconds = int((cache_timeout or 300000) / 1000)
        cache.write_cache(ip, expires_seconds)
        return ip

    return resp.response or ""
