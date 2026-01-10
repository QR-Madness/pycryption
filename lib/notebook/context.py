# lib/notebook/context.py
"""
Context and result types for notebook-style algorithms.

These dataclasses hold configuration, runtime context, and operation results.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Callable

from lib.EncryptionAlgorithm import SIMPLE_COMPOSER_TYPE
from lib.util.kms.providers import KeyProvider

KDFFunction = Callable[[bytes, bytes], bytes]  # (key, salt) -> derived_key


@dataclass
class LayerMaterial:
    """"
    Single layer's cryptographic materials.
    """
    key: Optional[bytes] = None
    salt: Optional[bytes] = None
    nonce: Optional[bytes] = None
    derived_key: Optional[bytes] = None


@dataclass
class AlgorithmConfig:
    """
    Configuration for a decorated algorithm class.

    Stored as a class attribute and copied to instances
    to avoid shared mutable state between instances.
    """

    name: str = "Unnamed"
    composer_type: str = SIMPLE_COMPOSER_TYPE
    key_provider: Optional[KeyProvider] = None
    collect_metrics: bool = False
    context_modifiers: list = field(default_factory=list)

    def copy(self) -> "AlgorithmConfig":
        """Create a copy for instance-level isolation."""
        return AlgorithmConfig(
            name=self.name,
            composer_type=self.composer_type,
            key_provider=self.key_provider,
            collect_metrics=self.collect_metrics,
            context_modifiers=list(self.context_modifiers),
        )


@dataclass
class ContextRegistry:
    """Central registry for KDFs and layer materials, keyed by string names."""

    kdfs: Dict[str, KDFFunction] = field(default_factory=dict)
    layers: Dict[str, LayerMaterial] = field(default_factory=dict)
    salts: Dict[str, bytes] = field(default_factory=dict)

    def register_kdf(self, name: str, func: KDFFunction) -> None:
        self.kdfs[name] = func

    def register_salt(self, name: str, salt: Optional[bytes] = None, size: int = 16) -> bytes:
        if salt is None:
            salt = os.urandom(size)
        self.salts[name] = salt
        return salt

    def get_layer(self, name: str) -> LayerMaterial:
        if name not in self.layers:
            self.layers[name] = LayerMaterial()
        return self.layers[name]

    def derive_key(self, kdf_name: str, key: bytes, salt_name: str) -> bytes:
        if kdf_name not in self.kdfs:
            raise KeyError(f"KDF '{kdf_name}' not registered")
        if salt_name not in self.salts:
            raise KeyError(f"Salt '{salt_name}' not registered")
        return self.kdfs[kdf_name](key, self.salts[salt_name])


@dataclass
class AlgorithmContext:
    """
    Context object injected into algorithm encrypt/decrypt methods.

    Provides key material, nonce, timing utilities, and optional
    crypto primitives configured by decorators.
    """

    # Primary Key material
    key: bytes = field(default=b"")
    key_id: Optional[str] = None

    # Nonce/IV (auto-generated if not provided)
    nonce: bytes = field(default=b"")
    nonce_size: int = 12

    # Timing & metrics
    start_time: float = field(default=0.0)
    metrics: Dict[str, Any] = field(default_factory=dict)

    registry: ContextRegistry = field(default_factory=ContextRegistry)

    # IN-REVIEW Crypto primitives (populated by decorators)
    # aesgcm: Any = None
    # chacha: Any = None
    # cipher: Any = None

    def generate_nonce(self) -> bytes:
        """Generate a fresh nonce."""
        self.nonce = os.urandom(self.nonce_size)
        return self.nonce

    def elapsed_ms(self) -> float:
        """Get elapsed time since context creation."""
        return (time.perf_counter() - self.start_time) * 1000

    def layers(self) -> Dict[str, LayerMaterial]:
        return self.registry.layers

    def layer(self, name: str) -> LayerMaterial:
        """Access layer materials by name."""
        return self.registry.get_layer(name)

    def derive(self, kdf_name: str, salt_name: str) -> bytes:
        """Derive key using registered KDF and salt."""
        if self.key is None:
            raise ValueError("No base key available")
        return self.registry.derive_key(kdf_name, self.key, salt_name)


@dataclass
class AlgorithmResult:
    """
    Result wrapper from algorithm operations.

    Contains output data, nonce used, collected metrics, and error state.
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
