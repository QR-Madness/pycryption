# lib/util/kms_decorators.py
from functools import wraps
from typing import Callable, ParamSpec, TypeVar, Concatenate

P = ParamSpec("P")
R = TypeVar("R")
T = TypeVar("T")  # Add this for the self parameter

class TransientKmsError(Exception):
    """Replace with your real transient KMS exception types."""

def backoff(attempt: int) -> None:
    """Replace with your real backoff (sleep/jitter)."""
    import time
    time.sleep(min(0.1 * 2**attempt, 2.0))

def with_kms(
    client_factory: Callable[[], object],
    *,
    key_id: str,
    retries: int = 3,
) -> Callable[[Callable[Concatenate[T, P], R]], Callable[Concatenate[T, P], R]]:
    """Decorator factory to inject a KMS client/key and handle retries."""
    def decorator(fn: Callable[Concatenate[T, P], R]) -> Callable[Concatenate[T, P], R]:
        @wraps(fn)
        def wrapper(self: T, *args: P.args, **kwargs: P.kwargs) -> R:
            client = client_factory()  # could be cached; adapt as needed
            last_error: Exception | None = None
            for attempt in range(1, retries + 1):
                try:
                    kwargs.setdefault("kms_client", client)
                    kwargs.setdefault("kms_key_id", key_id)
                    return fn(self, *args, **kwargs)
                except TransientKmsError as e:
                    last_error = e
                    if attempt == retries:
                        raise
                    backoff(attempt)
            # This should never be reached, but satisfies type checker
            raise RuntimeError("Retry loop completed without return or exception")
        return wrapper
    return decorator