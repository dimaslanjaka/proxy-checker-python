import json
import os
import random
import re
import time
from io import BytesIO
from typing import Any, Optional, Union

import certifi
import pycurl
from .FileCache import FileCache
from .ProxyChekerResult import ProxyChekerResult


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
    def __init__(self, timeout: int = 5000, verbose: bool = False):
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
        checked = [j for j in self.proxy_judges if self.send_query(url=j)]
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
            resp = self.send_query(url=url)
            if resp:
                break
        if not resp:
            return ""

        match = REGEX_IP.search(resp["response"])
        if match:
            ip = match.group(0)
            cache.write_cache(ip, cache_timeout or 3600)
            return ip

        return resp["response"]

    def send_query(
        self,
        proxy: Optional[str] = None,
        url: Optional[str] = None,
        tls=1.3,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Union[None, dict]:
        response = BytesIO()
        c = pycurl.Curl()

        if self.verbose:
            c.setopt(pycurl.VERBOSE, True)

        c.setopt(pycurl.URL, url or random.choice(self.proxy_judges))
        c.setopt(pycurl.WRITEDATA, response)
        c.setopt(pycurl.TIMEOUT_MS, self.timeout)
        c.setopt(pycurl.SSL_VERIFYHOST, 0)
        c.setopt(pycurl.SSL_VERIFYPEER, 0)

        if user and password:
            c.setopt(pycurl.PROXYUSERPWD, f"{user}:{password}")

        if proxy:
            c.setopt(pycurl.PROXY, proxy)

            if proxy.startswith("https"):
                c.setopt(pycurl.CAINFO, certifi.where())
                versions = {
                    1.3: pycurl.SSLVERSION_MAX_TLSv1_3,
                    1.2: pycurl.SSLVERSION_MAX_TLSv1_2,
                    1.1: pycurl.SSLVERSION_MAX_TLSv1_1,
                    1.0: pycurl.SSLVERSION_MAX_TLSv1_0,
                }
                c.setopt(
                    pycurl.SSLVERSION, versions.get(tls, pycurl.SSLVERSION_MAX_TLSv1_3)
                )

        try:
            c.perform()
        except Exception:
            return None

        if c.getinfo(pycurl.HTTP_CODE) != 200:
            return None

        timeout = round(c.getinfo(pycurl.CONNECT_TIME) * 1000)
        resp_text = response.getvalue().decode("iso-8859-1")

        return {"timeout": timeout, "response": resp_text}

    def parse_anonymity(self, response: str) -> str:
        if not self.ip:
            return ""

        if self.ip in response:
            return "Transparent"

        if any(header in response for header in PRIVACY_HEADERS):
            return "Anonymous"

        return "Elite"

    def get_country(self, ip: str) -> list:
        r = self.send_query(url="https://ip2c.org/" + ip)
        if r and r["response"].startswith("1"):
            fields = r["response"].split(";")
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
        tls: float = 1.3,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ) -> ProxyChekerResult:

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
        total_timeout = 0

        for _ in range(retries):
            for proto in protocols_to_test:
                r = self.send_query(
                    proxy=f"{proto}://{proxy}",
                    user=user,
                    password=password,
                    tls=tls,
                )
                if not r:
                    continue

                protocols[proto] = r
                total_timeout += r["timeout"]

                if not check_all_protocols:
                    break

            if total_timeout:
                break

        if not protocols:
            return ProxyChekerResult(
                protocols=[],
                anonymity="",
                timeout=0,
                country=None,
                country_code=None,
                proxy=None,
                error=True,
            )

        sample_response = random.choice(list(protocols.values()))["response"]

        country = (
            self.get_country(proxy.split(":")[0]) if check_country else [None, None]
        )

        anonymity = self.parse_anonymity(sample_response)

        avg_timeout = total_timeout // len(protocols)

        remote_addr = None
        if check_address:
            match = REMOTE_ADDR_REGEX.search(sample_response)
            if match:
                remote_addr = match.group(1)

        return ProxyChekerResult(
            protocols=list(protocols.keys()),
            anonymity=anonymity,
            timeout=avg_timeout,
            country=country[0],
            country_code=country[1],
            proxy=remote_addr,
            error=False,
        )
