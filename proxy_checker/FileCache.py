import json
import os
import time
from typing import Any, Optional


class FileCache:
    """
    A simple file-based cache system with expiration.

    Attributes:
        file_path (str): Path to the cache file.

    Methods:
        write_cache(value: Any, expires_in: int) -> None:
            Writes a value to the cache with an expiration time.

        read_cache() -> Optional[Any]:
            Reads the value from the cache if it has not expired.
    """

    def __init__(self, file_path: str) -> None:
        """
        Initializes the FileCache with a file path.

        Args:
            file_path (str): The path to the cache file.
        """
        self.file_path = file_path

    def write_cache(self, value: Any, expires_in: int) -> None:
        """
        Writes a value to the cache with an expiration time.

        Args:
            value (Any): The value to be cached.
            expires_in (int): The expiration time in seconds.
        """
        # Ensure the parent directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

        cache_data = {
            "value": value,
            "timestamp": time.time(),
            "expires_in": expires_in,
        }
        with open(self.file_path, "w") as cache_file:
            json.dump(cache_data, cache_file)

    def read_cache(self) -> Optional[Any]:
        """
        Reads the value from the cache if it has not expired.

        Returns:
            Optional[Any]: The cached value if valid, otherwise None.
        """
        if not os.path.exists(self.file_path):
            return None

        try:
            with open(self.file_path, "r") as cache_file:
                cache_data = json.load(cache_file)

            current_time = time.time()
            cache_time = cache_data["timestamp"]
            expires_in = cache_data["expires_in"]

            if current_time - cache_time > expires_in:
                return None

            return cache_data["value"]
        except Exception:
            return None
