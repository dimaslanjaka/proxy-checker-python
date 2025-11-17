from proxy_checker.utils.get_public_ip import get_public_ip

res = get_public_ip(
    proxy_info={"proxy": "16.78.93.162:25731"}, cache=True, verbose=True
)
if res:
    print(f"My public IP is: {res}")
