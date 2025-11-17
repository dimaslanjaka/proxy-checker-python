from proxy_checker import ProxyChecker, get_device_ip

checker = ProxyChecker(verbose=False)
print(f"my IP {checker.device_ip}")
proxy = "16.78.41.33:9011"
proxy_ip = proxy.split(":")[0]
print(f"proxy IP {proxy_ip}")
result = checker.check_proxy(
    proxy=proxy, check_all_protocols=True, check_address=True, check_country=True
)
print(result)
print(f"latency: {result.latency} ms")
print(f"anonymity: {result.anonymity}")
print(f"is device ip same {checker.device_ip == proxy_ip}")
print(f"country: {result.country} ({result.country_code})")
