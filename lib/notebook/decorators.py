# lib/notebook/decorators.py
"""
Decorators for notebook-style algorithm development.

These decorators handle logistics: key injection, context building,
nonce generation, metrics collection, and crypto primitive setup.
"""
from __future__ import annotations

import time
from functools import wraps
from typing import Any, Callable, Optional, Type, TypeVar, Union

from lib.EncryptionAlgorithm import SIMPLE_COMPOSER_TYPE
from lib.util.kms.providers import (
    KeyProvider,
    LocalKeyProvider,
    DerivedKeyProvider,
    EnvKeyProvider,
)

from lib.notebook.context import (
    AlgorithmConfig,
    AlgorithmContext,
    AlgorithmResult,
)

T = TypeVar("T")


# -----------------------------------------------------------------------------
# Internal Helpers
# -----------------------------------------------------------------------------


def _get_config(obj: Any) -> AlgorithmConfig:
    """Get the algorithm config from an instance or class."""
    return getattr(obj, "_algo_config", AlgorithmConfig())


def _ensure_config(cls: Type[T]) -> AlgorithmConfig:
    """Ensure a class has an AlgorithmConfig, creating if needed."""
    if not hasattr(cls, "_algo_config"):
        cls._algo_config = AlgorithmConfig()  # type: ignore
    return cls._algo_config  # type: ignore


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
# Core Decorator
# -----------------------------------------------------------------------------


def algorithm(
    name: str,
    composer_type: str = SIMPLE_COMPOSER_TYPE,
) -> Callable[[Type[T]], Type[T]]:
    """
    Class decorator that transforms a class into a managed algorithm.

    Wraps encrypt/decrypt methods to inject AlgorithmContext and
    return AlgorithmResult with metrics.

    Args:
        name: Algorithm identifier for registration and metrics
        composer_type: SIMPLE_COMPOSER_TYPE or MULTI_COMPOSER_TYPE
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.name = name
        config.composer_type = composer_type

        # Wrap __init__ to copy config to instance
        original_init = cls.__init__ if hasattr(cls, "__init__") else None

        @wraps(original_init or object.__init__)
        def new_init(self: Any, *args: Any, **kwargs: Any) -> None:
            self._config = _get_config(cls).copy()
            if original_init:
                original_init(self, *args, **kwargs)

        cls.__init__ = new_init  # type: ignore

        # Wrap encrypt method
        if hasattr(cls, "encrypt"):
            original_encrypt = getattr(cls, "encrypt")

            @wraps(original_encrypt)
            def wrapped_encrypt(self: Any, data: bytes, **kwargs: Any) -> AlgorithmResult:
                ctx = _build_context(self, "encrypt")
                ctx.generate_nonce()

                try:
                    output = original_encrypt(self, data, ctx, **kwargs)
                    ctx.metrics["elapsed_ms"] = round(ctx.elapsed_ms(), 3)
                    ctx.metrics["input_bytes"] = len(data)
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
            original_decrypt = getattr(cls, "decrypt")

            @wraps(original_decrypt)
            def wrapped_decrypt(
                self: Any,
                data: bytes,
                nonce: Optional[bytes] = None,
                **kwargs: Any,
            ) -> AlgorithmResult:
                ctx = _build_context(self, "decrypt")
                if nonce:
                    ctx.nonce = nonce

                try:
                    output = original_decrypt(self, data, ctx, **kwargs)
                    ctx.metrics["elapsed_ms"] = round(ctx.elapsed_ms(), 3)
                    ctx.metrics["input_bytes"] = len(data)
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


# -----------------------------------------------------------------------------
# Key Injection Decorators
# -----------------------------------------------------------------------------


def with_key(key: Union[bytes, KeyProvider]) -> Callable[[Type[T]], Type[T]]:
    """
    Inject a key or KeyProvider into the algorithm context.

    The key will be available as `ctx.key` in encrypt/decrypt methods.

    Args:
        key: Raw key bytes or a KeyProvider instance
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
    salt: bytes,
    kdf: str = "pbkdf2",
    iterations: int = 480000,
) -> Callable[[Type[T]], Type[T]]:
    """
    Derive and inject a key from password using KDF.

    Args:
        password: Password string
        salt: Salt bytes (must be provided for reproducibility)
        kdf: KDF algorithm ("pbkdf2" or "scrypt")
        iterations: KDF iterations
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
    Load and inject key from environment variable.

    Args:
        env_var: Environment variable name containing the key
    """

    def decorator(cls: Type[T]) -> Type[T]:
        config = _ensure_config(cls)
        config.key_provider = EnvKeyProvider(env_var)
        return cls

    return decorator


# -----------------------------------------------------------------------------
# Crypto Primitive Decorators
# -----------------------------------------------------------------------------


def with_metrics() -> Callable[[Type[T]], Type[T]]:
    """
    Enable detailed metrics collection.

    Adds timestamp and detailed flag to collected metrics.
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