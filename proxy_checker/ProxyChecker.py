# removed random dependency: use a fixed probe URL
import re
from typing import Dict, Optional, Union, Literal, cast
from .FileCache import FileCache
from .ProxyChekerResult import ProxyChekerResult
from .utils.curl import send_query, QueryResult
from .utils.get_device_ip import get_device_ip
from .ProxyAnonymity import ProxyAnonymity
from .AnonymityResult import AnonymityResult


# Precompile regexes once
REGEX_IP = re.compile(
    r"(?!0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
)
REMOTE_ADDR_REGEX = re.compile(r"REMOTE_ADDR = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

PROBE_URL = "https://www.google.com"


class ProxyChecker:
    def __init__(self, timeout: int = 30000, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose

        self.ip = get_device_ip(timeout=self.timeout, verbose=self.verbose)
        if not self.ip:
            print("ERROR: cannot get device ip")

        # ProxyAnonymity helper used for parsing judge responses
        self.anonymity_helper = ProxyAnonymity()

    def change_timeout(self, timeout: int) -> None:
        self.timeout = timeout

    def change_verbose(self, value: bool) -> None:
        self.verbose = value

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

        protocols: Dict[str, QueryResult] = {}
        latencies = []

        for _ in range(retries):
            for proto in protocols_to_test:
                # Query a fixed probe URL using the protocol-prefixed proxy URL
                proxy_url = f"{proto}://{proxy}"
                result = send_query(
                    url=PROBE_URL,
                    proxy=proxy_url,
                    user=user,
                    password=password,
                    tls=tls,
                    timeout=timeout if timeout is not None else self.timeout,
                    verbose=self.verbose,
                )
                if not result or result.error:
                    continue

                protocols[proto] = result
                t = getattr(result, "total_time", None)
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

        sample_result = next(iter(protocols.values()))
        sample_response = sample_result.response or ""

        country = (
            self.get_country(proxy.split(":")[0]) if check_country else [None, None]
        )

        # Use ProxyAnonymity helper to parse anonymity and remote_addr
        anonymity_result = self.anonymity_helper.get_anonymity(
            proxy=proxy, verbose=self.verbose
        )
        anonymity = anonymity_result.anonymity or ""

        # Compute average latency (ms) from collected per-protocol latencies
        latency = 0
        if latencies:
            latency = int(round(sum(latencies) / len(latencies)))

        remote_addr = None
        if check_address:
            # prefer the remote_addr discovered by the anonymity helper
            remote_addr = anonymity_result.remote_addr
            if not remote_addr:
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
