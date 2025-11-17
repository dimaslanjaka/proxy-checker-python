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

        # Checks
        if self.ip == "":
            print("ERROR: cannot get device ip")

        self.check_proxy_judges()

    def change_timeout(self, timeout: int) -> None:
        """
        Sets timeout for requests
        Args:
            :param timeout, int. Timeout in ms
        """
        self.timeout = timeout

    def change_verbose(self, value: bool) -> None:
        """
        Sets verbose for curl
        """
        self.verbose = value

    def check_proxy_judges(self) -> None:
        """
        This proxy checks several urls to get the proxy availability. These are the judges.
        There are several in this module. However, they can be nonoperational. This function
        removes the one not operative.
        """
        checked_judges = []

        for judge in self.proxy_judges:
            if self.send_query(url=judge):
                checked_judges.append(judge)

        # push working proxy judges url for `check_proxy`
        self.proxy_judges = checked_judges

        if len(checked_judges) == 0:
            print(
                "ERROR: JUDGES ARE OUTDATED. CREATE A GIT BRANCH AND UPDATE SELF.PROXY_JUDGES"
            )
            exit()
        elif len(checked_judges) == 1:
            print("WARNING! THERE'S ONLY 1 JUDGE!")

    def get_device_ip(self, cache_timeout: Optional[int] = 3600) -> str:
        """
        Gets the IP address by checking it via various services.

        Parameters:
        cache_timeout (Optional[int]): Cache timeout in seconds. Default is 3600 seconds (1 hour).

        Returns:
        str: IP address or an empty string if it couldn't find anything.
        """
        cache = FileCache("tmp/device-ip.json")
        # Read cache and check for expiration
        cached_value = cache.read_cache()
        if cached_value is not None:
            return cached_value
        if not cache_timeout:
            cache_timeout = 3600

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
        r = None
        for url in ip_services:
            r = self.send_query(url=url)
            if r:
                break

        if not r:
            return ""

        # parse IP using regex
        ip_address_match = re.search(
            r"(?!0)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",
            r["response"],
        )
        if ip_address_match:
            result = ip_address_match.group(0)
            if result:
                # Write cache with a value and expiration time in seconds
                cache.write_cache(result, cache_timeout)
            return result

        return r["response"]

    def send_query(
        self,
        proxy: Optional[str] = None,
        url: Optional[str] = None,
        tls=1.3,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Union[None, dict]:
        """
        Sends a query to a judge to get info from judge.
        Args:
            :param proxy: "IP:Port". Proxy to use in the connection
            :param url: Url judge to use
            :param tls
            :param user: Username for proxy
            :param password: Password for proxy
        Returns:
            False if response is not 200. Otherwise: 'timeout': timeout,'response': response}
        """
        response = BytesIO()
        c = pycurl.Curl()
        if self.verbose:
            c.setopt(pycurl.VERBOSE, True)

        c.setopt(pycurl.URL, url or random.choice(self.proxy_judges))
        c.setopt(pycurl.WRITEDATA, response)
        c.setopt(pycurl.TIMEOUT_MS, self.timeout)

        if user is not None and password is not None:
            c.setopt(pycurl.PROXYUSERPWD, f"{user}:{password}")

        c.setopt(pycurl.SSL_VERIFYHOST, 0)
        c.setopt(pycurl.SSL_VERIFYPEER, 0)

        if proxy:
            c.setopt(pycurl.PROXY, proxy)
            if proxy.startswith("https"):
                # c.setopt(pycurl.SSL_VERIFYHOST, 1)
                # c.setopt(pycurl.SSL_VERIFYHOST, 2)
                # c.setopt(pycurl.SSL_VERIFYPEER, 1)
                c.setopt(pycurl.CAINFO, certifi.where())
                if tls == 1.3:
                    c.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_MAX_TLSv1_3)
                elif tls == 1.2:
                    c.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_MAX_TLSv1_2)
                elif tls == 1.1:
                    c.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_MAX_TLSv1_1)
                elif tls == 1.0:
                    c.setopt(pycurl.SSLVERSION, pycurl.SSLVERSION_MAX_TLSv1_0)

        # Perform request
        try:
            c.perform()
        except Exception as e:
            # print(e)
            return None

        # Return None if the status is not 200
        if c.getinfo(pycurl.HTTP_CODE) != 200:
            return None

        # Calculate the request timeout in milliseconds
        timeout = round(c.getinfo(pycurl.CONNECT_TIME) * 1000)

        # Decode the response content
        response = response.getvalue().decode("iso-8859-1")

        return {"timeout": timeout, "response": response}

    def parse_anonymity(self, r: str) -> str:
        """
        Obtain the anonymity of the proxy
        Args:
            :param, str. IP
        Return: Transparent, Anonymous, Elite. Empty for failed get anonymity
        """
        if self.ip == "":
            return ""

        if self.ip in r:
            # device ip is found in proxy judges response headers
            return "Transparent"

        privacy_headers = [
            "VIA",
            "X-FORWARDED-FOR",
            "X-FORWARDED",
            "FORWARDED-FOR",
            "FORWARDED-FOR-IP",
            "FORWARDED",
            "CLIENT-IP",
            "PROXY-CONNECTION",
        ]

        if any([header in r for header in privacy_headers]):
            # contains spesific headers
            return "Anonymous"

        # perfect
        return "Elite"

    def get_country(self, ip: str) -> list:
        """
        Checks in https://ip2c.org the country from a given IP
        Args:
            :param ip, str. Including dots, but not port
        Return: [country, country shortname Alpha-2 code]
        """
        r = self.send_query(url="https://ip2c.org/" + ip)

        if r and r["response"][0] == "1":
            r = r["response"].split(";")
            return [r[3], r[1]]

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
    ) -> Union[None, dict]:
        """
        Checks if the proxy is working.
        Args:
            :param proxy: str "IP:Port", Ip including the dots.
            :param check_country: bool. Get country and country_code from https://ip2c.org/
            :param check_address: bool. Take remote adress from judge url
            :param check_all_protocols: bool. If True, after we found the proxy is of a specific \
                                        protocol, we continue looking for its validity for others. Protocols are: http, https, socks4, socks5
            :param protocol: str. 'http', 'https', 'socks4', 'socks5', or a list containing some of these. Check only these protocols
            :param retries: int. Number of times to retry the checking in case of proxy failure
            :param tls: float. 1.3, 1.2, 1.1, 1.0. If using https, this will be the maximum TLS tried in the connection. Notice that the TLS version
                    to be used will be random, but as maximum this parameter
            :param user: str. User to use for proxy connection
            :param password: str. Password to use for proxy connection
        Return:
            False if not working. Otherwise:
            {'protocols': list of protocols available, 'anonymity': 'Anonymous' or 'Transparent' or 'Elite','timeout': timeout\
             'country': 'country', 'country_code': 'country_code', 'remote_address':'remote_address'}
        """

        protocols = {}
        timeout = 0

        # Select protocols to check
        protocols_to_test = ["http", "https", "socks4", "socks5"]

        if isinstance(protocol, list):
            temp = []
            for p in protocol:
                if p in protocols_to_test:
                    temp.append(p)

            if len(temp) != 0:
                protocols_to_test = temp

        elif protocol in protocols_to_test:
            protocols_to_test = [protocol]

        # Test the proxy for each protocol
        for retry in range(retries):
            for protocol in protocols_to_test:
                r = self.send_query(
                    proxy=protocol + "://" + proxy,
                    user=user,
                    password=password,
                    tls=tls,
                )

                # Check if the request failed
                if not r:
                    continue

                protocols[protocol] = r
                timeout += r["timeout"]

                if not check_all_protocols:
                    break

            # Do not retry if any connection was successful
            if timeout != 0:
                break

        # Check if the proxy failed all tests
        if len(protocols) == 0:
            return None

        r = protocols[random.choice(list(protocols.keys()))]["response"]

        # Get country
        country = []
        if check_country:
            country = self.get_country(proxy.split(":")[0])

        # Check anonymity
        anonymity = self.parse_anonymity(r)

        # Check timeout
        timeout = timeout // len(protocols)

        # Check remote address
        remote_addr = "0.0.0.0"
        if check_address:
            remote_regex = r"REMOTE_ADDR = (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            remote_addr = re.search(remote_regex, r)
            if remote_addr:
                remote_addr = remote_addr.group(1)

        results = {
            "protocols": list(protocols.keys()),
            "anonymity": anonymity,
            "timeout": timeout,
        }

        if check_country:
            results["country"] = country[0]
            results["country_code"] = country[1]

        if check_address:
            results["remote_address"] = remote_addr

        return results
