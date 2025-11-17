from proxy_checker import ProxyAnonymity

anonymity = ProxyAnonymity()
res = anonymity.get_anonymity(proxy="157.175.43.137:797", verbose=True)
if res:
    print(f"Anonymity: {res}")
