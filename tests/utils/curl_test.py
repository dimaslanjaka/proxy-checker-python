import sys
import os

parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
sys.path.append(parent_dir)

from proxy_checker.utils.curl import send_query

res = send_query(url="https://google.com", timeout=50000, verbose=True)
print(res)
