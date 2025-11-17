from dataclasses import dataclass
from typing import List, Optional
from dataclasses import asdict
import json


@dataclass
class ProxyChekerResult:
    protocols: List[str]
    anonymity: str
    latency: int
    country: Optional[str] = None
    country_code: Optional[str] = None
    proxy: Optional[str] = None
    error: bool = False

    def to_dict(self) -> dict:
        """Return a plain dict representation of the result."""
        return asdict(self)

    def to_json(self) -> str:
        """Return a JSON string representation of the result."""
        return json.dumps(self.to_dict())

    def __str__(self) -> str:
        """Human-readable JSON string for printing."""
        return self.to_json()
