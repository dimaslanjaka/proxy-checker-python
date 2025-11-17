from proxy_checker import ProxyChecker

checker = ProxyChecker(verbose=False)
print(f"my IP {checker.device_ip}")
proxy = "16.78.41.33:9011"
proxy_ip = proxy.split(":")[0]
print(f"proxy IP {proxy_ip}")
result = checker.check_proxy(
    proxy=proxy, check_all_protocols=True, check_address=True, check_country=True
)
print(result)
if result.error:
    print("Error checking proxy:")
    for proto, tls_map in result.messages.items():
        print(f"Protocol: {proto}")
        for tls, msg in tls_map.items():
            print(f"  TLS {tls}: {msg}")
else:
    print(f"latency: {result.latency} ms")
    print(f"anonymity: {result.anonymity}")
    print(f"is device ip same {checker.device_ip == proxy_ip}")
    print(f"country: {result.country} ({result.country_code})")
