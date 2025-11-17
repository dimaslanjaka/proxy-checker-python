import random
import re
from typing import Optional, Union, Literal
from .FileCache import FileCache
from .ProxyChekerResult import ProxyChekerResult
from .utils.curl import send_query


# Precompile regexes once
REGEX_IP = re.compile(
    r"(?!0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
REMOTE_ADDR_REGEX = re.compile(r"REMOTE_ADDR = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

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


class ProxyChecker:
    def __init__(self, timeout: int = 30000, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose
        self.proxy_judges = [
            "https://wfuchs.de/azenv.php",
            "http://mojeip.net.pl/asdfa/azenv.php",
            "http://httpheader.net/azenv.php",
            "http://pascal.hoez.free.fr/azenv.php",
            "https://www.cooleasy.com/azenv.php",
            "http://azenv.net/",
            "http://sh.webmanajemen.com/data/azenv.php",
        ]

        self.ip = self.get_device_ip()
        if not self.ip:
            print("ERROR: cannot get device ip")

        self.check_proxy_judges()

    def change_timeout(self, timeout: int) -> None:
        self.timeout = timeout

    def change_verbose(self, value: bool) -> None:
        self.verbose = value

    def check_proxy_judges(self) -> None:
        checked = []
        for url in self.proxy_judges:
            res = send_query(url=url, timeout=self.timeout, verbose=self.verbose)
            if res and not getattr(res, "error", False):
                checked.append(url)

        self.proxy_judges = checked

        count = len(checked)
        if count == 0:
            print(
                "ERROR: JUDGES ARE OUTDATED. CREATE A GIT BRANCH AND UPDATE SELF.PROXY_JUDGES"
            )
            exit()
        if count == 1:
            print("WARNING! THERE'S ONLY 1 JUDGE!")

    def get_device_ip(self, cache_timeout: Optional[int] = 3600) -> str:
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
            resp = send_query(
                url=url,
                timeout=self.timeout,
                verbose=self.verbose,
            )
            if resp and not getattr(resp, "error", False):
                break
        if not resp or getattr(resp, "error", False):
            return ""

        match = REGEX_IP.search(resp.response or "")
        if match:
            ip = match.group(0)
            cache.write_cache(ip, cache_timeout or 3600)
            return ip

        return resp.response or ""

    # `send_query` moved to `proxy_checker.utils.curl.send_query`

    def parse_anonymity(
        self, response: str
    ) -> Literal["Transparent", "Anonymous", "Elite", ""]:
        if not self.ip:
            return ""

        if self.ip in response:
            return "Transparent"

        if any(header in response for header in PRIVACY_HEADERS):
            return "Anonymous"

        return "Elite"

    def get_country(self, ip: str) -> list:
        r = send_query(
            url="https://ip2c.org/" + ip,
            timeout=self.timeout,
            verbose=self.verbose,
        )
        if r and not getattr(r, "error", False) and (r.response or "").startswith("1"):
            fields = (r.response or "").split(";")
            return [fields[3], fields[1]]
        return ["-", "-"]

    def check_proxy(
        self,
        proxy: str,
        check_country: bool = True,
        check_address: bool = False,
        check_all_protocols: bool = False,
        protocol: Optional[Union[str, list]] = None,
        retries: int = 1,
        tls: Literal["1.3", "1.2", "1.1", "1.0"] = "1.3",
        user: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ProxyChekerResult:
        """Check a proxy for working protocols, anonymity, latency and country.

        Parameters
        ----------
        proxy : str
            Proxy address in the form 'host:port'. For protocol testing the method
            will prefix this value with protocol scheme (e.g. 'http://host:port').
        check_country : bool, default=True
            If True, query the IP geolocation service to get country and country code.
        check_address : bool, default=False
            If True, attempt to parse REMOTE_ADDR from the judge response.
        check_all_protocols : bool, default=False
            If True, test all protocols listed; otherwise stop after the first success.
        protocol : Optional[Union[str, list]], default=None
            A single protocol name (e.g. 'http') or a list of protocols to test.
            When None all supported protocols ('http','https','socks4','socks5') are used.
        retries : int, default=1
            How many times to retry protocol checks.
        tls : float, default=1.3
            Maximum TLS version to allow when using an HTTPS proxy (1.3,1.2,1.1,1.0).
        user, password : Optional[str]
            Optional proxy authentication credentials.
        timeout : Optional[int], default=None
            Per-request timeout in milliseconds (ms). If None the instance
            default `self.timeout` is used.

        Returns
        -------
        ProxyChekerResult
            Dataclass with fields: protocols (List[str]), anonymity (Literal), latency (ms int),
            country, country_code, proxy (remote address when check_address=True), and error flag.

        Notes
        -----
        - The timeout parameter is in milliseconds to match the underlying pycurl usage.
        - The method will return a `ProxyChekerResult` with `error=True` when no protocol
          succeeds.

        Example
        -------
        >>> checker = ProxyChecker()
        >>> result = checker.check_proxy('1.2.3.4:8080', timeout=10000)
        >>> print(result.to_json())
        """
        all_protocols = ["http", "https", "socks4", "socks5"]

        if isinstance(protocol, list):
            protocols_to_test = [
                p for p in protocol if p in all_protocols
            ] or all_protocols
        elif protocol in all_protocols:
            protocols_to_test = [protocol]
        else:
            protocols_to_test = all_protocols

        protocols = {}
        latencies = []

        for _ in range(retries):
            for proto in protocols_to_test:
                anonymity_response = send_query(
                    proxy=f"{proto}://{proxy}",
                    user=user,
                    password=password,
                    tls=tls,
                    timeout=timeout if timeout is not None else self.timeout,
                    verbose=self.verbose,
                    url=random.choice(self.proxy_judges),
                )
                if not anonymity_response or getattr(
                    anonymity_response, "error", False
                ):
                    continue

                protocols[proto] = anonymity_response
                t = getattr(anonymity_response, "total_time", None)
                if t is not None:
                    latencies.append(t * 1000)

                if not check_all_protocols:
                    break

        if not protocols:
            return ProxyChekerResult(
                protocols=[],
                anonymity="",
                latency=0,
                country=None,
                country_code=None,
                proxy=None,
                error=True,
            )

        sample_response = random.choice(list(protocols.values())).response or ""

        country = (
            self.get_country(proxy.split(":")[0]) if check_country else [None, None]
        )

        anonymity = self.parse_anonymity(sample_response)

        # Compute average latency (ms) from collected per-protocol latencies
        latency = 0
        if latencies:
            latency = int(round(sum(latencies) / len(latencies)))

        remote_addr = None
        if check_address:
            match = REMOTE_ADDR_REGEX.search(sample_response)
            if match:
                remote_addr = match.group(1)

        return ProxyChekerResult(
            protocols=list(protocols.keys()),
            anonymity=anonymity,
            latency=latency,
            country=country[0],
            country_code=country[1],
            proxy=remote_addr,
            error=False,
        )
