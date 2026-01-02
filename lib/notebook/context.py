# lib/notebook/context.py
"""
Context and result types for notebook-style algorithms.

These dataclasses hold configuration, runtime context, and operation results.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from lib.EncryptionAlgorithm import SIMPLE_COMPOSER_TYPE
from lib.util.kms.providers import KeyProvider


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
            context_modifiers=list(self.context_modifiers),
        )


@dataclass
class AlgorithmContext:
    """
    Context object injected into algorithm encrypt/decrypt methods.

    Provides key material, nonce, timing utilities, and optional
    crypto primitives configured by decorators.
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
    aesgcm: Any = None
    chacha: Any = None
    cipher: Any = None

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