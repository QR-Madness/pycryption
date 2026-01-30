# lib/notebook/adapters.py
"""
Adapters to bridge lib/algorithms implementations with the notebook API.

The generic adapt() function uses an AlgorithmAdapter to automatically
convert between the notebook's raw-bytes interface and an algorithm's
structured Input/Output types.
"""
from __future__ import annotations

from typing import Any, Optional, Type, Union

from lib.EncryptionAlgorithm import AlgorithmAdapter, EncryptionAlgorithm
from lib.notebook.decorators import (
    algorithm,
    with_key,
    with_memory_profiling,
    with_metrics,
)
from lib.util.kms.providers import KeyProvider, LocalKeyProvider

# Key used to persist the adapter state dict inside CryptoRegistry.data
_STATE_KEY = "__adapter_state"


def adapt(
    algo_class: Type[EncryptionAlgorithm],
    key: Union[bytes, KeyProvider],
    name: Optional[str] = None,
    *,
    adapter: Optional[AlgorithmAdapter] = None,
    profile_memory: bool = False,
    collect_metrics: bool = False,
) -> Any:
    """
    Generic factory to wrap a lib/algorithms implementation for the notebook API.

    Creates a notebook-compatible algorithm instance that:
    1. Accepts raw bytes for encrypt/decrypt
    2. Uses the AlgorithmAdapter to marshal between bytes and structured I/O
    3. Persists auxiliary data (nonces, IVs, etc.) in the CryptoRegistry

    Args:
        algo_class: The EncryptionAlgorithm subclass (e.g., Aes256GcmAlgorithm)
        key: Raw key bytes or a KeyProvider instance
        name: Algorithm name for registration (defaults to class name)
        adapter: Optional adapter override. If not provided, calls algo_class.adapter().
        profile_memory: Enable memory profiling via tracemalloc.
        collect_metrics: Enable detailed metrics collection (timestamps).

    Returns:
        Notebook-compatible algorithm instance

    Raises:
        TypeError: If the algorithm class does not provide an adapter() classmethod
            and no adapter is passed explicitly.
    """
    # Resolve the adapter
    if adapter is None:
        if not hasattr(algo_class, "adapter"):
            raise TypeError(
                f"{algo_class.__name__} does not have an adapter() classmethod. "
                f"Either add one or pass an adapter explicitly."
            )
        adapter = algo_class.adapter()

    # Resolve key provider
    key_provider: KeyProvider
    if isinstance(key, KeyProvider):
        key_provider = key
    else:
        key_provider = LocalKeyProvider(key)

    # Resolve name
    algo_name = name or algo_class.__name__

    # Instantiate the inner algorithm with key provider
    inner = algo_class()
    inner._key_provider = key_provider  # type: ignore[attr-defined]

    # Capture in closure
    _adapter = adapter
    _inner = inner

    class AdaptedAlgorithm:
        """Auto-generated notebook adapter for a lib/algorithms implementation."""

        def encrypt(self, data: bytes, ctx: Any) -> bytes:
            payload = _adapter.prepare_encrypt_input(data)
            result = _inner.encrypt(payload)
            state: dict = {}
            ciphertext = _adapter.extract_encrypt_output(result, state)
            ctx.set(_STATE_KEY, state)
            return ciphertext

        def decrypt(self, data: bytes, ctx: Any) -> bytes:
            state: dict = ctx.get(_STATE_KEY, {})
            payload = _adapter.prepare_decrypt_input(data, state)
            result = _inner.decrypt(payload)
            return _adapter.extract_decrypt_output(result)

    # Apply decorators imperatively (bottom-up, same order as stacking)
    if collect_metrics:
        AdaptedAlgorithm = with_metrics()(AdaptedAlgorithm)
    if profile_memory:
        AdaptedAlgorithm = with_memory_profiling()(AdaptedAlgorithm)
    AdaptedAlgorithm = with_key(key_provider)(AdaptedAlgorithm)
    AdaptedAlgorithm = algorithm(algo_name)(AdaptedAlgorithm)

    AdaptedAlgorithm.__name__ = f"Adapted{algo_class.__name__}"
    AdaptedAlgorithm.__qualname__ = f"Adapted{algo_class.__name__}"

    return AdaptedAlgorithm()
