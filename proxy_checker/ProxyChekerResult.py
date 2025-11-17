from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ProxyChekerResult:
    protocols: List[str]
    anonymity: str
    timeout: int
    country: Optional[str] = None
    country_code: Optional[str] = None
    proxy: Optional[str] = None
    error: bool = False
