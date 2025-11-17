from dataclasses import dataclass
from typing import Optional, Literal, Union


@dataclass
class AnonymityResult:
    anonymity: Optional[Union[Literal["Transparent", "Anonymous", "Elite"], str]] = None
    remote_addr: Optional[str] = None
    device_ip: Optional[str] = None
    public_ip: Optional[str] = None

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)

    def __str__(self) -> str:
        import json

        return json.dumps(self.to_dict())
