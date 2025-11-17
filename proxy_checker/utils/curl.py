from dataclasses import dataclass
from io import BytesIO
from typing import Optional, Literal, Union

import certifi
import pycurl


@dataclass
class QueryResult:
    error: bool
    message: str
    timeout: Optional[int] = None
    response: Optional[str] = None
    total_time: Optional[float] = None

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)

    def to_json(self) -> str:
        import json

        return json.dumps(self.to_dict())

    def __str__(self) -> str:
        return self.to_json()


def send_query(
    url: str,
    proxy: Optional[str] = None,
    tls: Union[Literal["1.3", "1.2", "1.1", "1.0"], str] = "1.3",
    user: Optional[str] = None,
    password: Optional[str] = None,
    timeout: int = 30000,
    verbose: bool = False,
) -> QueryResult:
    """Perform an HTTP(S) request using pycurl and return timing + response.

    This function executes a single request to `url` optionally using an HTTP(S) proxy.
    It returns a QueryResult dataclass containing whether the call succeeded, a human
    readable message, measured connect timeout in milliseconds, the response body (decoded
    as ISO-8859-1) and the total transfer time in seconds.

    Parameters
    ----------
    url : str
        Target URL to request (e.g., "http://example.com" or "https://example.com").
    proxy : Optional[str], default=None
        Proxy URL (e.g., "http://proxy:3128" or "https://proxy:443"). If provided, the
        request will be routed through this proxy.
    tls : Literal["1.3", "1.2", "1.1", "1.0"], default="1.3"
        Maximum TLS version to allow when using an HTTPS proxy. Supported values are the
        string literals "1.3", "1.2", "1.1", "1.0". If an unknown value is supplied,
        TLSv1.3 is chosen.
    user : Optional[str], default=None
        Username for proxy authentication (used together with `password`).
    password : Optional[str], default=None
        Password for proxy authentication (used together with `user`).
    timeout : int, default=30000
        Timeout in milliseconds (ms). Applied to both the overall timeout and the
        connect timeout (CONNECTTIMEOUT_MS and TIMEOUT_MS).
    verbose : bool, default=False
        If True, enables pycurl verbose output.

    Returns
    -------
    QueryResult
        - error: True if the request failed (network error, non-200 HTTP code, etc.).
        - message: Human-readable message or error string.
        - timeout: Measured connect time in milliseconds (rounded) if available.
        - response: Response body decoded using ISO-8859-1 if available.
        - total_time: Total transfer time in seconds if available.

    Notes
    -----
    - SSL verification is disabled (SSL_VERIFYHOST=0 and SSL_VERIFYPEER=0) by default.
      When using an HTTPS proxy the CA bundle from certifi is set for the connection.
    - Response body is decoded using ISO-8859-1 to preserve raw bytes without raising
      UnicodeDecodeError; callers may re-decode using a different encoding if needed.
    - Non-200 HTTP status codes are treated as failures and returned as QueryResult(error=True).
    - All exceptions raised by pycurl.perform() are caught and returned as QueryResult(error=True).

    Example
    -------
    >>> from proxy_checker.utils.curl import send_query
    >>> result = send_query("http://example.com", timeout=30000)
    >>> if result.error:
    ...     print("Request failed:", result.message)
    ... else:
    ...     print("OK", result.total_time, "s", "response length:", len(result.response or ""))
    """
    response = BytesIO()
    c = pycurl.Curl()

    if verbose:
        c.setopt(pycurl.VERBOSE, True)

    c.setopt(pycurl.URL, url)
    c.setopt(pycurl.WRITEDATA, response)
    c.setopt(pycurl.TIMEOUT_MS, timeout)
    # Also set connect timeout to the same ms and follow redirects
    c.setopt(pycurl.CONNECTTIMEOUT_MS, timeout)
    c.setopt(pycurl.FOLLOWLOCATION, True)
    c.setopt(pycurl.USERAGENT, "python-pycurl/1.0")
    c.setopt(pycurl.ACCEPT_ENCODING, "")

    c.setopt(pycurl.SSL_VERIFYHOST, 0)
    c.setopt(pycurl.SSL_VERIFYPEER, 0)

    if proxy:
        if user and password:
            c.setopt(pycurl.PROXYUSERPWD, f"{user}:{password}")

        # Allow proxy to be given as a full URL: scheme://host:port
        # Extract scheme and set PROXYTYPE for socks variants.
        proxy_scheme = None
        proxy_host = proxy
        try:
            # simple parse: split scheme
            if "://" in proxy:
                proxy_scheme, proxy_host = proxy.split("://", 1)
        except Exception:
            proxy_scheme = None

        c.setopt(pycurl.PROXY, proxy_host)

        if proxy_scheme:
            scheme = proxy_scheme.lower()
            if scheme in ("http", "https"):
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_HTTP)
            elif scheme == "socks4":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4)
            elif scheme == "socks4a":
                # socks4a resolves hostnames via the proxy
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS4A)
            elif scheme == "socks5":
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5)
            elif scheme == "socks5h":
                # socks5h resolves hostnames via the proxy
                c.setopt(pycurl.PROXYTYPE, pycurl.PROXYTYPE_SOCKS5_HOSTNAME)

        if proxy.startswith("https"):
            c.setopt(pycurl.CAINFO, certifi.where())
            versions = {
                "1.3": pycurl.SSLVERSION_MAX_TLSv1_3,
                "1.2": pycurl.SSLVERSION_MAX_TLSv1_2,
                "1.1": pycurl.SSLVERSION_MAX_TLSv1_1,
                "1.0": pycurl.SSLVERSION_MAX_TLSv1_0,
            }
            c.setopt(
                pycurl.SSLVERSION, versions.get(tls, pycurl.SSLVERSION_MAX_TLSv1_3)
            )

    try:
        c.perform()
    except Exception as e:
        return QueryResult(error=True, message=str(e))

    http_code = c.getinfo(pycurl.HTTP_CODE)
    if http_code != 200:
        return QueryResult(error=True, message=f"HTTP {http_code}")

    timeout_ms = round(c.getinfo(pycurl.CONNECT_TIME) * 1000)
    resp_text = response.getvalue().decode("iso-8859-1")
    total_time = c.getinfo(pycurl.TOTAL_TIME)

    return QueryResult(
        error=False,
        message="OK",
        timeout=timeout_ms,
        response=resp_text,
        total_time=total_time,
    )
