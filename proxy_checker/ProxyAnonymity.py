import re
from typing import Optional, Literal, cast
from .utils.get_public_ip import get_public_ip
from .utils.get_device_ip import get_device_ip
from .utils.curl import send_query
from .AnonymityResult import AnonymityResult

PRIVACY_HEADERS = {
    "VIA",
    "X-FORWARDED-FOR",
    "X-FORWARDED",
    "FORWARDED-FOR",
    "FORWARDED-FOR-IP",
    "FORWARDED",
    "CLIENT-IP",
    "PROXY-CONNECTION",
}

# Compile regex once for speed
PRIVACY_REGEX = re.compile(
    r"(?i)\b(" + "|".join(re.escape(h) for h in PRIVACY_HEADERS) + r")\b"
)


class ProxyAnonymity:
    def __init__(self):
        self.proxy_judges = [
            "http://wfuchs.de/azenv.php",
            "http://mojeip.net.pl/asdfa/azenv.php",
            "http://httpheader.net/azenv.php",
            "http://pascal.hoez.free.fr/azenv.php",
            "http://azenv.net/",
            "http://sh.webmanajemen.com/data/azenv.php",
        ]

    def get_anonymity(
        self, proxy: str, verbose: bool = False, timeout: int = 60000
    ) -> AnonymityResult:
        if "://" in proxy:
            proxy = proxy.split("://", 1)[1]
        public_ip = get_public_ip(proxy_info={"proxy": proxy})
        device_ip = get_device_ip()
        proxy_ip = proxy.split(":", 1)[0].split("://", 1)[-1]
        if verbose:
            print(
                f"Checking anonymity for proxy {proxy} (public_ip={public_ip}, device_ip={device_ip}, proxy_ip={proxy_ip})"
            )

        body = None
        protocols = ["http", "socks4", "socks5", "https"]
        tls_versions = ["1.0", "1.1", "1.2", "1.3"]

        # Try all protocols / TLS / judges until one returns body
        for protocol in protocols:
            proxy_url = f"{protocol}://{proxy}"

            for tls in tls_versions:
                for judge in self.proxy_judges:
                    if verbose:
                        print(f"Query {judge} via {proxy_url} TLS {tls}")

                    result = send_query(
                        url=judge,
                        proxy=proxy_url,
                        timeout=timeout,
                        tls=cast(Literal["1.3", "1.2", "1.1", "1.0"], tls),
                    )

                    if not result or result.error:
                        continue

                    if result.response:
                        body = result.response
                        break
                if body:
                    break
            if body:
                break

        if not body:
            return AnonymityResult(
                anonymity=None, remote_addr=None, device_ip=device_ip
            )

        # ---- DETECT PRIVACY HEADERS DIRECTLY IN RAW BODY ----
        has_privacy = bool(PRIVACY_REGEX.search(body))

        # ---- SIMPLE ANONYMITY RULES ----
        if public_ip == device_ip:
            # Proxy reveals your real IP → Transparent
            anonymity = "Transparent"
        else:
            # Proxy hides your real IP
            if has_privacy:
                anonymity = "Anonymous"  # Leaks proxy headers
            else:
                anonymity = "Elite"  # No IP leak, no header leak
        if verbose:
            minified_body = body.replace("\n", " ").replace("\r", " ")
            print(
                f"Anonymity result for proxy {proxy}: {anonymity} (public_ip={public_ip}, device_ip={device_ip}, has_privacy_headers={has_privacy}), body={minified_body}..."
            )

        return AnonymityResult(
            anonymity=anonymity,
            remote_addr=None,  # Removed, as you asked
            device_ip=device_ip,
        )
