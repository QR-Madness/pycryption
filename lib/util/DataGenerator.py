from lib.util.logger import log
import time
import random
import string


class DataGenerator:
    """
    Utility class for generating random data for encryption testing.
    """

    @staticmethod
    def generate_ascii_text_data(length: int, charToSymbolRatio: float = 0.05) -> str:
        """Generate random text data of specified length."""
        start_time = time.perf_counter()
        num_chars = int(length * (1 - charToSymbolRatio))
        num_symbols = length - num_chars

        chars = "".join(random.choices(string.ascii_letters + string.digits, k=num_chars))
        symbols = "".join(random.choices(string.punctuation + " ", k=num_symbols))

        result = list(chars + symbols)
        random.shuffle(result)
        end_time = time.perf_counter()
        elapsed_ms = (end_time - start_time) * 1000.0
        log(f"Generated {length} chars; took {elapsed_ms:.0f}ms | charToSymbolRatio: {charToSymbolRatio}")
        return "".join(result)
