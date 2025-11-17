from proxy_checker import ProxyChecker

checker = ProxyChecker(verbose=False)
print(f"my IP {checker.ip}")
proxy = "157.175.43.137:797"
ip = proxy.split(":")[0]
print(f"proxy IP {ip}")
result = checker.check_proxy(
    proxy=proxy, check_all_protocols=True, check_address=True, check_country=True
)
print(result)
print(f"latency: {result.latency} ms")
print(f"anonymity: {result.anonymity}")
print(f"is proxy ip same {checker.ip == ip}")
