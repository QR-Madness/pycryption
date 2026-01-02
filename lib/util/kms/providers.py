# lib/util/key_providers.py
"""
Key Provider architecture for decoupling key management from encryption algorithms.

Usage:
    @use_key_provider(LocalKeyProvider(my_32_byte_key))
    class MyAlgorithm(EncryptionAlgorithm):
        def encrypt(self, payload): ...
        def decrypt(self, payload): ...

The decorator injects `_key_provider` into the class and wraps encrypt/decrypt
to automatically handle key retrieval.
"""
from abc import ABC, abstractmethod
from functools import wraps
from typing import Any, Callable, Optional, Type, TypeVar

T = TypeVar("T")


class KeyProviderError(Exception):
    """Base exception for key provider errors."""


class KeyNotFoundError(KeyProviderError):
    """Raised when a key cannot be retrieved."""


class KeyValidationError(KeyProviderError):
    """Raised when a key fails validation."""


class KeyProvider(ABC):
    """
    Abstract base for key providers.

    Implement this protocol to create custom key retrieval strategies.
    """

    @abstractmethod
    def get_key(self, key_id: Optional[str] = None) -> bytes:
        """
        Retrieve encryption key.

        Args:
            key_id: Optional identifier for the key (used by KMS, vault, etc.)

        Returns:
            Raw key bytes

        Raises:
            KeyNotFoundError: If key cannot be retrieved
            KeyProviderError: For other provider-specific errors
        """
        ...

    def validate_key(self, key: bytes, expected_length: int) -> None:
        """Validate key meets requirements."""
        if len(key) != expected_length:
            raise KeyValidationError(
                f"Expected {expected_length}-byte key, got {len(key)} bytes"
            )


class LocalKeyProvider(KeyProvider):
    """
    Simple in-memory key provider.

    Best for: Testing, development, single-key scenarios.
    """

    def __init__(self, key: bytes):
        self._key = key

    def get_key(self, key_id: Optional[str] = None) -> bytes:
        return self._key


class EnvKeyProvider(KeyProvider):
    """
    Retrieve key from environment variable.

    Best for: Container deployments, CI/CD pipelines.
    """

    def __init__(self, env_var: str, encoding: str = "utf-8"):
        self._env_var = env_var
        self._encoding = encoding

    def get_key(self, key_id: Optional[str] = None) -> bytes:
        import os
        import base64

        value = os.environ.get(self._env_var)
        if value is None:
            raise KeyNotFoundError(f"Environment variable {self._env_var} not set")

        # Try base64 first (preferred for binary keys)
        try:
            return base64.b64decode(value, validate=True)
        except Exception:
            # Fall back to raw encoding (for simple ASCII keys)
            # Note: This is intentional for flexibility in dev/testing
            return value.encode(self._encoding)


class DerivedKeyProvider(KeyProvider):
    """
    Derive key from password using KDF.

    Best for: Password-based encryption, user-supplied secrets.
    """

    def __init__(
        self,
        password: str,
        salt: bytes,
        key_length: int = 32,
        kdf: str = "pbkdf2",  # or "scrypt", "argon2"
        iterations: int = 480000,  # OWASP 2023 recommendation for PBKDF2-SHA256
    ):
        self._password = password
        self._salt = salt
        self._key_length = key_length
        self._kdf = kdf
        self._iterations = iterations
        self._cached_key: Optional[bytes] = None

    def get_key(self, key_id: Optional[str] = None) -> bytes:
        if self._cached_key is not None:
            return self._cached_key

        if self._kdf == "pbkdf2":
            self._cached_key = self._derive_pbkdf2()
        elif self._kdf == "scrypt":
            self._cached_key = self._derive_scrypt()
        else:
            # TODO: Add argon2 support
            raise KeyProviderError(f"Unsupported KDF: {self._kdf}")

        return self._cached_key

    def _derive_pbkdf2(self) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self._key_length,
            salt=self._salt,
            iterations=self._iterations,
        )
        return kdf.derive(self._password.encode("utf-8"))

    def _derive_scrypt(self) -> bytes:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        kdf = Scrypt(
            salt=self._salt,
            length=self._key_length,
            n=2**14,  # CPU/memory cost
            r=8,       # Block size
            p=1,       # Parallelization
        )
        return kdf.derive(self._password.encode("utf-8"))


class KmsKeyProvider(KeyProvider):
    """
    Retrieve key from external KMS (AWS, GCP, Azure, HashiCorp Vault).

    Best for: Production deployments, key rotation, audit trails.
    """

    def __init__(
        self,
        client_factory: Callable[[], Any],
        key_id: str,
        retries: int = 3,
        cache_ttl_seconds: int = 300,
    ):
        self._client_factory = client_factory
        self._key_id = key_id
        self._retries = retries
        self._cache_ttl = cache_ttl_seconds
        self._client: Optional[Any] = None
        self._cached_key: Optional[bytes] = None
        self._cache_time: float = 0

    def get_key(self, key_id: Optional[str] = None) -> bytes:
        import time

        effective_key_id = key_id or self._key_id

        # Check cache
        if self._cached_key and (time.time() - self._cache_time) < self._cache_ttl:
            return self._cached_key

        # Get client (lazy init)
        if self._client is None:
            self._client = self._client_factory()

        # Subclasses must implement _fetch_from_kms
        self._cached_key = self._fetch_from_kms(effective_key_id)
        self._cache_time = time.time()
        return self._cached_key

    def _fetch_from_kms(self, key_id: str) -> bytes:
        """
        Override this method for specific KMS implementations.

        Example for AWS KMS (data key):
            response = self._client.generate_data_key(KeyId=key_id, KeySpec='AES_256')
            return response['Plaintext']
        """
        raise NotImplementedError


# -----------------------------------------------------------------------------
# Class Decorator for Key Injection
# -----------------------------------------------------------------------------


def use_key_provider(provider: KeyProvider) -> Callable[[Type[T]], Type[T]]:
    """
    Class decorator that injects a KeyProvider into an EncryptionAlgorithm.

    The provider is stored as `_key_provider` on the class instance.
    Subclasses can access keys via `self._key_provider.get_key()`.

    Usage:
        @use_key_provider(LocalKeyProvider(my_key))
        class Aes256GcmAlgorithm(EncryptionAlgorithm):
            ...
    """

    def decorator(cls: Type[T]) -> Type[T]:
        original_init = cls.__init__

        @wraps(original_init)
        def new_init(self: Any, *args: Any, **kwargs: Any) -> None:
            self._key_provider = provider
            original_init(self, *args, **kwargs)

        cls.__init__ = new_init  # type: ignore[method-assign]
        return cls

    return decorator


def inject_key(
    key_length: int = 32,
    key_id: Optional[str] = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """
    Method decorator that injects the key from the provider into the method.

    The key is passed as a `_injected_key` kwarg to the decorated method.

    Usage:
        @inject_key(key_length=32)
        def encrypt(self, payload, *, _injected_key: bytes):
            # Use _injected_key for encryption
            ...
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        @wraps(fn)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> T:
            if not hasattr(self, "_key_provider"):
                raise KeyProviderError(
                    "No key provider configured. Use @use_key_provider decorator on class."
                )

            key = self._key_provider.get_key(key_id)
            self._key_provider.validate_key(key, key_length)
            kwargs["_injected_key"] = key
            return fn(self, *args, **kwargs)

        return wrapper

    return decorator
