import os
import json
import time
import hashlib
import re
from typing import Optional, Dict, Any, List
import pycurl
from io import BytesIO
import certifi


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


def _curl_request(
    url: str,
    proxy: Optional[str],
    proxy_type: Optional[str],
    username: Optional[str],
    password: Optional[str],
    timeout: int = 5,
) -> Optional[str]:

    buffer = BytesIO()
    curl = pycurl.Curl()
    curl.setopt(pycurl.URL, url)
    curl.setopt(pycurl.USERAGENT, "Mozilla/5.0 (Python Proxy IP Checker)")
    curl.setopt(pycurl.TIMEOUT, timeout)
    curl.setopt(pycurl.CONNECTTIMEOUT, timeout)
    curl.setopt(pycurl.WRITEDATA, buffer)
    curl.setopt(pycurl.CAINFO, certifi.where())

    # Proxy setup
    if proxy:
        curl.setopt(pycurl.PROXY, proxy)

        if proxy_type:
            proxy_type = proxy_type.lower()
            if proxy_type == "http":
                curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_HTTP)
            elif proxy_type == "socks4":
                curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
            elif proxy_type == "socks5":
                curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
            elif proxy_type == "socks4a":
                curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4A)
            elif proxy_type == "socks5h":
                curl.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)

        if username and password:
            curl.setopt(pycurl.PROXYUSERPWD, f"{username}:{password}")

    try:
        curl.perform()
        http_code = curl.getinfo(pycurl.RESPONSE_CODE)
    except Exception:
        curl.close()
        return None

    curl.close()

    if http_code != 200:
        return None

    return buffer.getvalue().decode(errors="ignore").strip()


def get_public_ip(
    cache: bool = False,
    cache_timeout: int = 300,
    proxy_info: Dict[str, Any] = {},
    debug: bool = False,
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

    if cache and cache_key and os.path.exists(cache_file):
        try:
            data = json.load(open(cache_file))
            if "ip" in data and "expires" in data and data["expires"] > time.time():
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
                if debug:
                    print(f"Trying {url} using proxy {proxy} type={ptype}")

                response = _curl_request(url, proxy, ptype, username, password)

                if response:
                    if debug:
                        print(f"Response (proxy {ptype}): {response[:80]}")
                    break

            if response:
                break

        else:
            if debug:
                print(f"Trying {url} without proxy")

            response = _curl_request(url, None, None, None, None)

            if response:
                if debug:
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
            json.dump(
                {"ip": ip, "expires": time.time() + cache_timeout},
                open(cache_file, "w"),
            )
        except Exception:
            pass

    return ip
