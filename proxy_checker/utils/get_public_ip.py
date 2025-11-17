import os
import json
import time
import hashlib
import re
import tempfile
from typing import Optional, Dict, Any, List
from .curl import send_query, QueryResult


IP_REGEX = re.compile(
    r"(?!0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)

IP_SERVICES = [
    "http://api64.ipify.org",
    "http://ipinfo.io/ip",
    "http://api.myip.com",
    "http://ip.42.pl/raw",
    "http://ifconfig.me/ip",
    "http://httpbin.org/ip",
    "http://api.ipify.org",
]


# Replaced _curl_request with calls to shared send_query (returns QueryResult)


def get_public_ip(
    cache: bool = False,
    cache_timeout: int = 300,
    proxy_info: Dict[str, Any] = {},
    verbose: bool = False,
) -> str:

    # ------------ CACHE HANDLING ------------
    cache_dir = os.path.join("/tmp", "runners", "public-ip")
    os.makedirs(cache_dir, exist_ok=True)

    proxy_key = (
        proxy_info.get("proxy", "")
        + proxy_info.get("type", "")
        + (proxy_info.get("username") or "")
        + (proxy_info.get("password") or "")
    )

    cache_key = hashlib.md5(proxy_key.encode()).hexdigest() if proxy_key else ""
    cache_file = os.path.join(cache_dir, f"{cache_key}.cache")

    # Prefer FileCache when available to centralize cache logic; fall back to JSON
    fc = None
    if cache and cache_key:
        try:
            from ..FileCache import FileCache

            fc = FileCache(cache_file)
            cached = fc.read_cache()
            if cached:
                return cached
        except Exception:
            # fallback to legacy JSON file check
            try:
                if os.path.exists(cache_file):
                    data = json.load(open(cache_file))
                    if (
                        "ip" in data
                        and "expires" in data
                        and data["expires"] > time.time()
                    ):
                        return data["ip"]
            except Exception:
                pass

    # ------------ PROXY HANDLING ------------
    proxy_types = proxy_info.get("type", "")
    if proxy_types:
        proxy_types = [proxy_types]
    else:
        proxy_types = ["http", "socks4", "socks5", "socks4a", "socks5h"]

    proxy = proxy_info.get("proxy")
    username = proxy_info.get("username")
    password = proxy_info.get("password")

    response = None

    # ------------ TRY ALL SERVICES ------------
    for url in IP_SERVICES:
        if proxy:
            for ptype in proxy_types:
                if verbose:
                    print(f"Trying {url} using proxy {proxy} type={ptype}")

                # convert proxy and type to proxy URL for send_query
                proxy_url = f"{ptype}://{proxy}"
                qr: QueryResult = send_query(
                    url=url,
                    proxy=proxy_url,
                    user=username,
                    password=password,
                    timeout=5000,
                    verbose=verbose,
                )
                response = qr.response if (qr and not qr.error) else None

                if response:
                    if verbose:
                        print(f"Response (proxy {ptype}): {response[:80]}")
                    break

            if response:
                break

        else:
            if verbose:
                print(f"Trying {url} without proxy")

            qr: QueryResult = send_query(url=url, timeout=5000, verbose=verbose)
            response = qr.response if (qr and not qr.error) else None

            if response:
                if verbose:
                    print(f"Response: {response[:80]}")
                break

    if not response:
        return ""

    # ------------ PARSE IP ------------
    match = IP_REGEX.search(response)
    if not match:
        return ""

    ip = match.group(0)

    # ------------ SAVE CACHE ------------
    if cache and cache_key:
        try:
            if fc:
                try:
                    fc.write_cache(ip, expires_in=cache_timeout)
                except Exception:
                    # fallback to JSON write
                    json.dump(
                        {"ip": ip, "expires": time.time() + cache_timeout},
                        open(cache_file, "w"),
                    )
            else:
                json.dump(
                    {"ip": ip, "expires": time.time() + cache_timeout},
                    open(cache_file, "w"),
                )
        except Exception:
            pass

    return ip
