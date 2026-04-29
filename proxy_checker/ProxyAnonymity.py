import re
from typing import Dict, Literal, Optional, cast

from .AnonymityResult import AnonymityResult
from .utils.curl import send_query
from .utils.get_device_ip import get_device_ip
from .utils.get_public_ip import get_public_ip


# ==============================
# Privacy headers (fallback only)
# ==============================
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

PRIVACY_REGEX = re.compile(
    r"(?i)\b(" + "|".join(re.escape(h) for h in PRIVACY_HEADERS) + r")\b"
)


# ==============================
# AZENV PARSER
# ==============================
def parse_azenv_to_dict(response: str) -> Dict[str, str]:
    match = re.search(r"<pre>(.*?)</pre>", response, re.S)
    if not match:
        return {}

    headers: Dict[str, str] = {}

    for line in match.group(1).splitlines():
        if "=" not in line:
            continue

        k, v = line.split("=", 1)
        key = k.strip().upper()
        value = v.strip()

        # ✅ keep only REMOTE_ADDR and HTTP_* headers
        if key != "REMOTE_ADDR" and not key.startswith("HTTP_"):
            continue

        # 🚫 skip noisy/heavy headers
        if key == "HTTP_COOKIE":
            continue

        headers[key] = value

    return headers


def extract_first_ip(value: str) -> str:
    return value.split(",")[0].strip()


def classify_proxy_from_azenv(
    response: str,
    expected_ip: Optional[str] = None,
) -> AnonymityResult:
    headers = parse_azenv_to_dict(response)

    # ❌ Not AZEnv response
    if not headers:
        return AnonymityResult(anonymity=None)

    remote_ip = headers.get("REMOTE_ADDR")
    xff = headers.get("HTTP_X_FORWARDED_FOR", "")
    real_ip = extract_first_ip(xff) if xff else None

    # CDN fallback (Cloudflare etc.)
    cf_ip = headers.get("HTTP_CF_CONNECTING_IP")

    proxy_headers = [
        "HTTP_VIA",
        "HTTP_CF_RAY",
        "HTTP_CDN_LOOP",
        "HTTP_X_FORWARDED_PROTO",
    ]

    has_proxy_header = any(h in headers for h in proxy_headers)

    # Best guess of real/public IP
    public_ip = real_ip or cf_ip or remote_ip

    result = AnonymityResult(
        anonymity=None,
        remote_addr=remote_ip,
        public_ip=public_ip,
    )

    # ==============================
    # 🚨 Transparent (real IP leaked)
    # ==============================
    if real_ip:
        if expected_ip:
            if real_ip != expected_ip:
                result.anonymity = "Transparent"
                return result
        else:
            result.anonymity = "Transparent"
            return result

    # ==============================
    # 🟡 Anonymous (proxy detected)
    # ==============================
    if has_proxy_header:
        result.anonymity = "Anonymous"
        return result

    # ==============================
    # 🟢 Elite (clean)
    # ==============================
    if expected_ip:
        if remote_ip == expected_ip:
            result.anonymity = "Elite"
        else:
            result.anonymity = "Anonymous"
    else:
        result.anonymity = "Elite"

    return result


# ==============================
# MAIN CLASS
# ==============================
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

        # Normalize proxy
        if "://" in proxy:
            proxy = proxy.split("://", 1)[1]

        proxy_ip = proxy.split(":", 1)[0]

        device_ip = get_device_ip()
        public_ip = get_public_ip(proxy_info={"proxy": proxy})

        if verbose:
            print(
                f"[INFO] proxy={proxy} device_ip={device_ip} public_ip={public_ip} proxy_ip={proxy_ip}"
            )

        body = None
        protocols = ["http", "socks4", "socks5", "https"]
        tls_versions = ["1.0", "1.1", "1.2", "1.3"]

        # ==============================
        # Try all combinations
        # ==============================
        for protocol in protocols:
            proxy_url = f"{protocol}://{proxy}"

            for tls in tls_versions:
                for judge in self.proxy_judges:
                    if verbose:
                        print(f"[TRY] {judge} via {proxy_url} TLS {tls}")

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

        # ❌ No response at all
        if not body:
            return AnonymityResult(
                anonymity=None,
                remote_addr=None,
                device_ip=device_ip,
                public_ip=public_ip,
            )

        return self.parse_anonymity(
            body=body,
            proxy=proxy,
            public_ip=public_ip,
            device_ip=device_ip,
            verbose=verbose,
        )

    # ==============================
    # CORE PARSER
    # ==============================
    def parse_anonymity(
        self,
        body: str,
        proxy: str,
        public_ip: Optional[str] = None,
        device_ip: Optional[str] = None,
        verbose: bool = False,
    ) -> AnonymityResult:

        if public_ip is None:
            public_ip = get_public_ip(proxy_info={"proxy": proxy})
        if device_ip is None:
            device_ip = get_device_ip()

        proxy_ip = proxy.split(":", 1)[0]

        # ==============================
        # 🚀 Primary: AZEnv classification
        # ==============================
        result = classify_proxy_from_azenv(
            response=body,
            expected_ip=proxy_ip,
        )

        # Inject known values
        result.device_ip = device_ip

        # Prefer detected public_ip, fallback to external
        if not result.public_ip:
            result.public_ip = public_ip

        # ==============================
        # 🧠 Fallback (only if AZEnv failed)
        # ==============================
        if result.anonymity is None:
            has_privacy = bool(PRIVACY_REGEX.search(body))

            if public_ip == device_ip:
                result.anonymity = "Transparent"
            else:
                result.anonymity = "Anonymous" if has_privacy else "Elite"

        if verbose:
            minified = body.replace("\n", " ").replace("\r", " ")
            print(
                f"[RESULT] proxy={proxy} → {result.anonymity} "
                f"(remote={result.remote_addr}, public={result.public_ip}, device={result.device_ip}) "
                f"body={minified[:300]}..."
            )

        return result
