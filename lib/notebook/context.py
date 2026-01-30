# lib/notebook/context.py
"""
Centralized cryptographic context for algorithm development.

The CryptoRegistry is the single source of truth for all cryptographic
materials: keys, salts, nonces, derived keys, KDFs, and layer compositions.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Union

from lib.util.kms.providers import KeyProvider

# Type aliases
KDFFunction = Callable[[bytes, bytes], bytes]  # (key, salt) -> derived_key
EncapsulateFunction = Callable[[bytes], tuple[bytes, bytes]]  # public_key -> (ciphertext, shared_secret)
DecapsulateFunction = Callable[[bytes, bytes], bytes]  # (secret_key, ciphertext) -> shared_secret


@dataclass
class CryptoRegistry:
    """
    Centralized registry for all cryptographic materials.
    
    This is the single source of truth persisted across encrypt/decrypt calls.
    All materials are keyed by string names for easy composition.
    """
    
    # Raw materials
    keys: Dict[str, bytes] = field(default_factory=dict)
    salts: Dict[str, bytes] = field(default_factory=dict)
    nonces: Dict[str, bytes] = field(default_factory=dict)
    
    # Derived/computed materials
    derived_keys: Dict[str, bytes] = field(default_factory=dict)
    shared_secrets: Dict[str, bytes] = field(default_factory=dict)
    
    # Functions
    kdfs: Dict[str, KDFFunction] = field(default_factory=dict)
    encapsulators: Dict[str, EncapsulateFunction] = field(default_factory=dict)
    decapsulators: Dict[str, DecapsulateFunction] = field(default_factory=dict)
    
    # Arbitrary storage for algorithm-specific data
    data: Dict[str, Any] = field(default_factory=dict)
    
    # --- Key Management ---
    
    def set_key(self, name: str, key: bytes) -> bytes:
        """Store a key by name."""
        self.keys[name] = key
        return key
    
    def get_key(self, name: str) -> Optional[bytes]:
        """Retrieve a key by name."""
        return self.keys.get(name)
    
    def require_key(self, name: str) -> bytes:
        """Get key or raise if not found."""
        if name not in self.keys:
            raise KeyError(f"Key '{name}' not registered")
        return self.keys[name]
    
    # --- Salt Management ---
    
    def set_salt(self, name: str, salt: Optional[bytes] = None, size: int = 32) -> bytes:
        """Store or generate a salt. Returns existing if already set."""
        if name not in self.salts:
            self.salts[name] = salt if salt is not None else os.urandom(size)
        return self.salts[name]
    
    def get_salt(self, name: str) -> Optional[bytes]:
        """Retrieve a salt by name."""
        return self.salts.get(name)
    
    def require_salt(self, name: str) -> bytes:
        """Get salt or raise if not found."""
        if name not in self.salts:
            raise KeyError(f"Salt '{name}' not registered")
        return self.salts[name]
    
    # --- Nonce Management ---
    
    def set_nonce(self, name: str, nonce: Optional[bytes] = None, size: int = 12) -> bytes:
        """Store or generate a nonce. Always overwrites (nonces should be unique)."""
        self.nonces[name] = nonce if nonce is not None else os.urandom(size)
        return self.nonces[name]
    
    def get_nonce(self, name: str) -> Optional[bytes]:
        """Retrieve a nonce by name."""
        return self.nonces.get(name)
    
    def require_nonce(self, name: str) -> bytes:
        """Get nonce or raise if not found."""
        if name not in self.nonces:
            raise KeyError(f"Nonce '{name}' not registered")
        return self.nonces[name]
    
    # --- KDF Management ---
    
    def set_kdf(self, name: str, func: KDFFunction) -> None:
        """Register a KDF function."""
        self.kdfs[name] = func
    
    def derive(self, kdf_name: str, key: bytes, salt_name: str, cache_as: Optional[str] = None) -> bytes:
        """
        Derive a key using a registered KDF and salt.
        
        Args:
            kdf_name: Name of registered KDF function
            key: Input key material
            salt_name: Name of registered salt
            cache_as: If provided, cache the derived key under this name
        """
        if kdf_name not in self.kdfs:
            raise KeyError(f"KDF '{kdf_name}' not registered")
        salt = self.require_salt(salt_name)
        derived = self.kdfs[kdf_name](key, salt)
        if cache_as:
            self.derived_keys[cache_as] = derived
        return derived
    
    def get_derived_key(self, name: str) -> Optional[bytes]:
        """Retrieve a cached derived key."""
        return self.derived_keys.get(name)
    
    # --- Encapsulation (for PQ/KEM algorithms) ---
    
    def set_encapsulator(self, name: str, func: EncapsulateFunction) -> None:
        """Register an encapsulation function (e.g., Kyber encaps)."""
        self.encapsulators[name] = func
    
    def set_decapsulator(self, name: str, func: DecapsulateFunction) -> None:
        """Register a decapsulation function (e.g., Kyber decaps)."""
        self.decapsulators[name] = func
    
    def encapsulate(self, name: str, public_key: bytes, cache_as: Optional[str] = None) -> tuple[bytes, bytes]:
        """
        Run encapsulation, returning (ciphertext, shared_secret).
        
        Args:
            name: Name of registered encapsulator
            public_key: Public key bytes
            cache_as: If provided, cache the shared secret under this name
        """
        if name not in self.encapsulators:
            raise KeyError(f"Encapsulator '{name}' not registered")
        ciphertext, shared_secret = self.encapsulators[name](public_key)
        if cache_as:
            self.shared_secrets[cache_as] = shared_secret
        return ciphertext, shared_secret
    
    def decapsulate(self, name: str, secret_key: bytes, ciphertext: bytes, cache_as: Optional[str] = None) -> bytes:
        """
        Run decapsulation, returning shared_secret.
        
        Args:
            name: Name of registered decapsulator
            secret_key: Secret key bytes
            ciphertext: Encapsulated ciphertext
            cache_as: If provided, cache the shared secret under this name
        """
        if name not in self.decapsulators:
            raise KeyError(f"Decapsulator '{name}' not registered")
        shared_secret = self.decapsulators[name](secret_key, ciphertext)
        if cache_as:
            self.shared_secrets[cache_as] = shared_secret
        return shared_secret
    
    def get_shared_secret(self, name: str) -> Optional[bytes]:
        """Retrieve a cached shared secret."""
        return self.shared_secrets.get(name)
    
    # --- Generic Data Storage ---
    
    def set(self, name: str, value: Any) -> None:
        """Store arbitrary data."""
        self.data[name] = value
    
    def get(self, name: str, default: Any = None) -> Any:
        """Retrieve arbitrary data."""
        return self.data.get(name, default)


@dataclass
class AlgorithmConfig:
    """
    Configuration for a decorated algorithm class.
    
    Stored as a class attribute and copied to instances.
    """
    name: str = "Unnamed"
    key_provider: Optional[KeyProvider] = None
    collect_metrics: bool = False
    profile_memory: bool = False
    context_modifiers: list = field(default_factory=list)

    def copy(self) -> "AlgorithmConfig":
        """Create a copy for instance-level isolation."""
        return AlgorithmConfig(
            name=self.name,
            key_provider=self.key_provider,
            collect_metrics=self.collect_metrics,
            profile_memory=self.profile_memory,
            context_modifiers=list(self.context_modifiers),
        )


@dataclass
class AlgorithmContext:
    """
    Context injected into algorithm encrypt/decrypt methods.
    
    Provides access to the centralized CryptoRegistry and timing utilities.
    The registry persists across calls; context is recreated each call.
    """
    
    key: bytes = field(default=b"")
    start_time: float = field(default=0.0)
    metrics: Dict[str, Any] = field(default_factory=dict)
    registry: CryptoRegistry = field(default_factory=CryptoRegistry)
    
    def elapsed_ms(self) -> float:
        """Get elapsed time since context creation."""
        return (time.perf_counter() - self.start_time) * 1000
    
    # --- Convenience accessors (delegate to registry) ---
    
    def set_salt(self, name: str, salt: Optional[bytes] = None, size: int = 32) -> bytes:
        """Store or generate a salt."""
        return self.registry.set_salt(name, salt, size)
    
    def get_salt(self, name: str) -> Optional[bytes]:
        """Get a salt by name."""
        return self.registry.get_salt(name)
    
    def set_nonce(self, name: str, nonce: Optional[bytes] = None, size: int = 12) -> bytes:
        """Store or generate a nonce."""
        return self.registry.set_nonce(name, nonce, size)
    
    def get_nonce(self, name: str) -> Optional[bytes]:
        """Get a nonce by name."""
        return self.registry.get_nonce(name)
    
    def set_kdf(self, name: str, func: KDFFunction) -> None:
        """Register a KDF function."""
        self.registry.set_kdf(name, func)
    
    def derive(self, kdf_name: str, salt_name: str, cache_as: Optional[str] = None) -> bytes:
        """Derive a key using the context's primary key."""
        return self.registry.derive(kdf_name, self.key, salt_name, cache_as)
    
    def get_derived_key(self, name: str) -> Optional[bytes]:
        """Get a cached derived key."""
        return self.registry.get_derived_key(name)
    
    def set(self, name: str, value: Any) -> None:
        """Store arbitrary data in registry."""
        self.registry.set(name, value)
    
    def get(self, name: str, default: Any = None) -> Any:
        """Retrieve arbitrary data from registry."""
        return self.registry.get(name, default)


@dataclass
class AlgorithmResult:
    """Result wrapper from algorithm operations."""
    
    output: bytes
    metrics: Dict[str, Any] = field(default_factory=dict)
    success: bool = True
    error: Optional[str] = None

    def __bytes__(self) -> bytes:
        return self.output

    def __repr__(self) -> str:
        size = len(self.output)
        elapsed = self.metrics.get("elapsed_ms", "?")
        return f"<AlgorithmResult: {size} bytes, {elapsed}ms>"
