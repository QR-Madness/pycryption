from lib.util.logger import log
import os
import random
import string
import time
from typing import Optional, Union

Seed = Union[int, str, bytes]


class DataGenerator:
    """
    Utility class for generating random data for encryption testing.

    Pass a ``seed`` for deterministic output — reproducible benchmarks
    require the same payload bytes across runs and machines.
    """

    @staticmethod
    def generate_ascii_text_data(
        length: int,
        charToSymbolRatio: float = 0.05,
        seed: Optional[Seed] = None,
    ) -> str:
        """Generate random text data of specified length."""
        start_time = time.perf_counter()
        rng = random.Random(seed) if seed is not None else random
        num_chars = int(length * (1 - charToSymbolRatio))
        num_symbols = length - num_chars

        chars = "".join(rng.choices(string.ascii_letters + string.digits, k=num_chars))
        symbols = "".join(rng.choices(string.punctuation + " ", k=num_symbols))

        result = list(chars + symbols)
        rng.shuffle(result)
        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000.0
        log(f"Generated {length} chars; took {elapsed_ms:.0f}ms | charToSymbolRatio: {charToSymbolRatio}")
        return "".join(result)

    @staticmethod
    def generate_binary_data(length: int, seed: Optional[Seed] = None) -> bytes:
        """
        Generate binary payload data.

        Unseeded data comes from os.urandom; seeded data from a dedicated
        Mersenne Twister instance (stable across Python versions/platforms).
        """
        if seed is None:
            return os.urandom(length)
        return random.Random(seed).randbytes(length)
