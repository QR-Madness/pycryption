# lib/notebook.py
"""
Notebook-friendly declarative API for encryption algorithm development.

Import this module in Jupyter notebooks for rapid algorithm prototyping:

    from lib.notebook import *

Then define algorithms declaratively:

    @algorithm("My-AES-Experiment")
    @with_key(generate_key(32))
    @with_aead()
    class MyAlgorithm:
        def encrypt(self, plaintext: bytes, ctx: AlgorithmContext) -> bytes:
            return ctx.aesgcm.encrypt(ctx.nonce, plaintext, None)

        def decrypt(self, ciphertext: bytes, ctx: AlgorithmContext) -> bytes:
            return ctx.aesgcm.decrypt(ctx.nonce, ciphertext, None)

    # Use it immediately
    quick_test(MyAlgorithm())
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, Optional, Type, TypeVar, Union

# Re-export key providers for convenience
from lib.util.key_providers import (
    KeyProvider,
    LocalKeyProvider,
    EnvKeyProvider,
    DerivedKeyProvider,
    KmsKeyProvider,
    KeyProviderError,
)

# Re-export composer types
from lib.EncryptionAlgorithm import (
    EncryptionAlgorithm,
    SIMPLE_COMPOSER_TYPE,
    MULTI_COMPOSER_TYPE,
)

T = TypeVar("T")


# -----------------------------------------------------------------------------
# Algorithm Configuration - Stored on decorated classes
# -----------------------------------------------------------------------------


@dataclass
class AlgorithmConfig:
    """
    Configuration for a decorated algorithm class.

    This is stored as a class attribute and copied to instances
    to avoid shared mutable state between instances.
    """

    name: str = "Unnamed"
    composer_type: str = SIMPLE_COMPOSER_TYPE
    key_provider: Optional[KeyProvider] = None
    nonce_size: int = 12
    collect_metrics: bool = False
    context_modifiers: list = field(default_factory=list)

    def copy(self) -> "AlgorithmConfig":
        """Create a copy for instance-level isolation."""
        return AlgorithmConfig(
            name=self.name,
            composer_type=self.composer_type,
            key_provider=self.key_provider,
            nonce_size=self.nonce_size,
            collect_metrics=self.collect_metrics,
            context_modifiers=list(self.context_modifiers),  # Copy the list
        )


# -----------------------------------------------------------------------------
# Algorithm Context - Injected into encrypt/decrypt methods
# -----------------------------------------------------------------------------


@dataclass
class AlgorithmContext:
    """
    Context object injected into algorithm methods.

    Contains all the "plumbing" so your algorithm can focus on the crypto logic.
    Access via the `ctx` parameter in your encrypt/decrypt methods.
    """

    # Key material
    key: bytes = field(default=b"")
    key_id: Optional[str] = None

    # Nonce/IV (auto-generated if not provided)
    nonce: bytes = field(default=b"")
    nonce_size: int = 12

    # Timing & metrics
    start_time: float = field(default=0.0)
    metrics: Dict[str, Any] = field(default_factory=dict)

    # Crypto primitives (populated by decorators)
    aesgcm: Any = None  # AESGCM instance if using @with_aead
    cipher: Any = None  # Generic cipher instance

    # Layer context (for multi-composer)
    layer_index: Optional[int] = None
    layer_id: Optional[str] = None
    previous_output: Optional[bytes] = None

    def generate_nonce(self) -> bytes:
        """Generate a fresh nonce."""
        self.nonce = os.urandom(self.nonce_size)
        return self.nonce

    def elapsed_ms(self) -> float:
        """Get elapsed time since context creation."""
        return (time.perf_counter() - self.start_time) * 1000


@dataclass
class AlgorithmResult:
    """
    Result wrapper from algorithm operations.

    Provides both the output data and collected metrics.
    """

    output: bytes
    nonce: Optional[bytes] = None
    metrics: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None

    def __bytes__(self) -> bytes:
        return self.output

    def __repr__(self) -> str:
        size = len(self.output)
        elapsed = self.metrics.get("elapsed_ms", "?")
        return f"<AlgorithmResult: {size} bytes, {elapsed}ms>"


# -----------------------------------------------------------------------------
# Core Decorators
# -----------------------------------------------------------------------------


def _get_config(obj: Any) -> AlgorithmConfig:
    """Get the algorithm config from an instance or class."""
    return getattr(obj, "_algo_config", AlgorithmConfig())


def _ensure_config(cls: Type[T]) -> AlgorithmConfig:
    """Ensure a class has an AlgorithmConfig, creating if needed."""
    if not hasattr(cls, "_algo_config"):
        cls._algo_config = AlgorithmConfig()  # type: ignore
    return cls._algo_config  # type: ignore


def algorithm(
    name: str,
    composer_type: str = SIMPLE_COMPOSER_TYPE,
) -> Callable[[Type[T]], Type[T]]:
    """
    Class decorator that transforms a simple class into a full algorithm.

    Usage:
        @algorithm("AES-256-GCM-Experiment")
        class MyAlgorithm:
            def encrypt(self, plaintext: bytes, ctx: AlgorithmContext) -> bytes:
                ...

    The decorated class gains:
    - _algo_config: AlgorithmConfig (class-level template)
    - _config: AlgorithmConfig (instance-level copy)
    - Automatic context injection into encrypt/decrypt
    """

    def decorator(cls: Type[T]) -> Type[T]:
        # Ensure config exists and set name
        config = _ensure_config(cls)
        config.name = name
        config.composer_type = composer_type

        # Wrap __init__ to copy config to instance
        original_init = cls.__init__ if hasattr(cls, "__init__") else None

        @wraps(original_init or object.__init__)
        def new_init(self: Any, *args: Any, **kwargs: Any) -> None:
            # Copy class config to instance for isolation
            self._config = _get_config(cls).copy()
            if original_init:
                original_init(self, *args, **kwargs)

        cls.__init__ = new_init  # type: ignore

        # Wrap encrypt method
        if hasattr(cls, "encrypt"):
            original_encrypt = cls.encrypt

            @wraps(original_encrypt)
            def wrapped_encrypt(self: Any, plaintext: bytes, **kwargs: Any) -> AlgorithmResult:
                ctx = _build_context(self, "encrypt")
                ctx.generate_nonce()

                try:
                    output = original_encrypt(self, plaintext, ctx, **kwargs)
                    ctx.metrics["elapsed_ms"] = round(ctx.elapsed_ms(), 3)
                    ctx.metrics["plaintext_bytes"] = len(plaintext)
                    ctx.metrics["output_bytes"] = len(output) if output else 0

                    return AlgorithmResult(
                        output=output,
                        nonce=ctx.nonce,
                        metrics=ctx.metrics,
                    )
                except Exception as e:
                    return AlgorithmResult(
                        output=b"",
                        nonce=ctx.nonce,
                        metrics=ctx.metrics,
                        success=False,
                        error=str(e),
                    )

            cls.encrypt = wrapped_encrypt  # type: ignore

        # Wrap decrypt method
        if hasattr(cls, "decrypt"):
            original_decrypt = cls.decrypt

            @wraps(original_decrypt)
            def wrapped_decrypt(
                self: Any,
                ciphertext: bytes,
                nonce: Optional[bytes] = None,
                **kwargs: Any,
            ) -> AlgorithmResult:
                ctx = _build_context(self, "decrypt")
                if nonce:
                    ctx.nonce = nonce

                try:
                    output = original_decrypt(self, ciphertext, ctx, **kwargs)
                    ctx.metrics["elapsed_ms"] = round(ctx.elapsed_ms(), 3)
                    ctx.metrics["ciphertext_bytes"] = len(ciphertext)
                    ctx.metrics["output_bytes"] = len(output) if output else 0

                    return AlgorithmResult(
                        output=output,
                        metrics=ctx.metrics,
                    )
                except Exception as e:
                    return AlgorithmResult(
                        output=b"",
                        metrics=ctx.metrics,
                        success=False,
                        error=str(e),
                    )

            cls.decrypt = wrapped_decrypt  # type: ignore

        return cls

    return decorator


def _build_context(instance: Any, operation: str) -> AlgorithmContext:
    """Build context for an algorithm operation."""
    config = getattr(instance, "_config", AlgorithmConfig())

    ctx = AlgorithmContext(
        start_time=time.perf_counter(),
        nonce_size=config.nonce_size,
    )
    ctx.metrics["algorithm"] = config.name
    ctx.metrics["operation"] = operation

    # Get key from provider if available
    if config.key_provider:
        ctx.key = config.key_provider.get_key()
        ctx.metrics["key_provider"] = config.key_provider.__class__.__name__

    # Apply any context modifiers (from decorators)
    for modifier in config.context_modifiers:
        modifier(ctx)

    return ctx


# -----------------------------------------------------------------------------
# Key Injection Decorators
# -----------------------------------------------------------------------------


def with_key(key: Union[bytes, KeyProvider]) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to configure key for the algorithm.

    Usage:
        @algorithm("MyAlgo")
        @with_key(my_32_byte_key)
        class MyAlgorithm:
            ...

        # Or with a provider:
        @algorithm("MyAlgo")
        @with_key(DerivedKeyProvider(password, salt))
        class MyAlgorithm:
            ...
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        if isinstance(key, KeyProvider):
            config.key_provider = key
        else:
            config.key_provider = LocalKeyProvider(bytes(key))
        return cls

    return decorator


def with_password(
    password: str,
    salt: bytes,  # Required - caller must provide for reproducibility
    kdf: str = "pbkdf2",
    iterations: int = 480000,
) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to derive key from password.

    Usage:
        my_salt = generate_salt()  # Store this for decryption!

        @algorithm("MyAlgo")
        @with_password("secret", salt=my_salt)
        class MyAlgorithm:
            ...
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.key_provider = DerivedKeyProvider(
            password=password,
            salt=salt,
            kdf=kdf,
            iterations=iterations,
        )
        return cls

    return decorator


def with_env_key(env_var: str) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to load key from environment variable.

    Usage:
        @algorithm("MyAlgo")
        @with_env_key("MY_ENCRYPTION_KEY")
        class MyAlgorithm:
            ...
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.key_provider = EnvKeyProvider(env_var)
        return cls

    return decorator


# -----------------------------------------------------------------------------
# Crypto Primitive Decorators
# -----------------------------------------------------------------------------


def with_aead(nonce_size: int = 12) -> Callable[[Type[T]], Type[T]]:
    """
    Decorator that pre-configures AESGCM and injects it into context.

    Usage:
        @algorithm("MyAlgo")
        @with_key(key)
        @with_aead()
        class MyAlgorithm:
            def encrypt(self, plaintext: bytes, ctx: AlgorithmContext) -> bytes:
                return ctx.aesgcm.encrypt(ctx.nonce, plaintext, None)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.nonce_size = nonce_size

        def inject_aesgcm(ctx: AlgorithmContext) -> None:
            if ctx.key:
                ctx.aesgcm = AESGCM(ctx.key)

        config.context_modifiers.append(inject_aesgcm)
        return cls

    return decorator


def with_metrics() -> Callable[[Type[T]], Type[T]]:
    """
    Decorator to enable detailed metrics collection.

    Usage:
        @algorithm("MyAlgo")
        @with_metrics()
        class MyAlgorithm:
            ...
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.collect_metrics = True

        def add_detailed_metrics(ctx: AlgorithmContext) -> None:
            ctx.metrics["detailed"] = True
            ctx.metrics["timestamp"] = time.time()

        config.context_modifiers.append(add_detailed_metrics)
        return cls

    return decorator


# -----------------------------------------------------------------------------
# Quick Factories for Common Patterns
# -----------------------------------------------------------------------------


def aes256gcm_algorithm(
    name: str = "AES-256-GCM",
    key: Optional[bytes] = None,
    password: Optional[str] = None,
    salt: Optional[bytes] = None,
) -> Callable[[Type[T]], Type[T]]:
    """
    All-in-one decorator for AES-256-GCM algorithms.

    Usage:
        @aes256gcm_algorithm(key=my_key)
        class MyAlgorithm:
            def encrypt(self, plaintext: bytes, ctx: AlgorithmContext) -> bytes:
                return ctx.aesgcm.encrypt(ctx.nonce, plaintext, None)

            def decrypt(self, ciphertext: bytes, ctx: AlgorithmContext) -> bytes:
                return ctx.aesgcm.decrypt(ctx.nonce, ciphertext, None)
    """

    def decorator(cls: Type[T]) -> Type[T]:
        # Apply in reverse order (innermost first)
        cls = with_aead(nonce_size=12)(cls)

        if password:
            if salt is None:
                raise ValueError("salt is required when using password")
            cls = with_password(password, salt=salt)(cls)
        elif key:
            cls = with_key(key)(cls)

        cls = algorithm(name)(cls)
        return cls

    return decorator


# -----------------------------------------------------------------------------
# Notebook Utilities
# -----------------------------------------------------------------------------


def generate_key(size: int = 32) -> bytes:
    """Generate a random key for testing."""
    return os.urandom(size)


def generate_salt(size: int = 16) -> bytes:
    """Generate a random salt for KDF."""
    return os.urandom(size)


def quick_test(algo_instance: Any, test_data: bytes = b"Hello, PyCryption!") -> None:
    """
    Quick test helper for notebook development.

    Usage:
        quick_test(MyAlgorithm())
    """
    config = getattr(algo_instance, "_config", None)
    name = config.name if config else "Unknown"
    print(f"Testing: {name}")
    print(f"Input: {test_data!r}")
    print("-" * 40)

    # Encrypt
    enc_result = algo_instance.encrypt(test_data)
    print(f"Encrypt: {enc_result}")
    if not enc_result.success:
        print(f"  ERROR: {enc_result.error}")
        return

    # Decrypt
    dec_result = algo_instance.decrypt(enc_result.output, nonce=enc_result.nonce)
    print(f"Decrypt: {dec_result}")
    if not dec_result.success:
        print(f"  ERROR: {dec_result.error}")
        return

    # Verify
    if dec_result.output == test_data:
        print("✓ Round-trip successful!")
    else:
        print("✗ Round-trip FAILED!")
        print(f"  Expected: {test_data!r}")
        print(f"  Got: {dec_result.output!r}")


def benchmark(
    algo_instance: Any,
    data_sizes: Optional[list[int]] = None,
    iterations: int = 10,
) -> Dict[str, Any]:
    """
    Benchmark an algorithm with various data sizes.

    Usage:
        results = benchmark(MyAlgorithm())
    """
    if data_sizes is None:
        data_sizes = [100, 1000, 10000, 100000]

    config = getattr(algo_instance, "_config", None)
    name = config.name if config else "Unknown"

    results: Dict[str, Any] = {
        "algorithm": name,
        "iterations": iterations,
        "benchmarks": [],
    }

    for size in data_sizes:
        data = os.urandom(size)
        encrypt_times = []
        decrypt_times = []

        for _ in range(iterations):
            # Encrypt
            enc_result = algo_instance.encrypt(data)
            if enc_result.success:
                encrypt_times.append(enc_result.metrics.get("elapsed_ms", 0))

            # Decrypt
            dec_result = algo_instance.decrypt(enc_result.output, nonce=enc_result.nonce)
            if dec_result.success:
                decrypt_times.append(dec_result.metrics.get("elapsed_ms", 0))

        avg_encrypt = sum(encrypt_times) / len(encrypt_times) if encrypt_times else 0
        avg_decrypt = sum(decrypt_times) / len(decrypt_times) if decrypt_times else 0

        results["benchmarks"].append({
            "size_bytes": size,
            "avg_encrypt_ms": round(avg_encrypt, 3),
            "avg_decrypt_ms": round(avg_decrypt, 3),
            "throughput_mbps": round((size / 1_000_000) / (avg_encrypt / 1000), 2) if avg_encrypt > 0 else 0,
        })

    return results


# -----------------------------------------------------------------------------
# Export everything for `from lib.notebook import *`
# -----------------------------------------------------------------------------

__all__ = [
    # Core decorators
    "algorithm",
    "with_key",
    "with_password",
    "with_env_key",
    "with_aead",
    "with_metrics",
    "aes256gcm_algorithm",
    # Config & Context types
    "AlgorithmConfig",
    "AlgorithmContext",
    "AlgorithmResult",
    # Key providers
    "KeyProvider",
    "LocalKeyProvider",
    "EnvKeyProvider",
    "DerivedKeyProvider",
    "KmsKeyProvider",
    "KeyProviderError",
    # Utilities
    "generate_key",
    "generate_salt",
    "quick_test",
    "benchmark",
    # Constants
    "SIMPLE_COMPOSER_TYPE",
    "MULTI_COMPOSER_TYPE",
]
