# lib/notebook/pipeline.py
"""
Multi Encryption — layered pipelines of notebook-API algorithms.

A MultiEncryption chains registered layers: encrypt() runs data through
every enabled layer in order, decrypt() unwinds them in reverse. Each layer
is any notebook-API algorithm instance (declared via decorators or bridged
via adapt()), and manages its own keys and auxiliary state exactly as it
would standalone — the pipeline only moves bytes between them.

This is the lab's hybrid-scheme research vehicle: e.g., AES-256-GCM wrapped
by the ML-KEM-768 hybrid gives classical + post-quantum defense in depth,
and the per-layer metrics show what each wrap costs.

A pipeline deliberately quacks like a notebook-API algorithm (encrypt /
decrypt returning AlgorithmResult, with a ``_config``), so it can be
registered in a ComposerSession and benchmarked or quality-analyzed like
any single specimen.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from lib.notebook.context import AlgorithmConfig, AlgorithmResult


@dataclass
class Layer:
    """One pipeline stage wrapping a notebook-API algorithm instance."""

    name: str
    algo: Any
    enabled: bool = True


class MultiEncryption:
    """
    Sequentially layered encryption over notebook-API algorithms.

    Layers encrypt in registration order and decrypt in reverse. Disabled
    layers are skipped in both directions (A/B testing a layer's cost is a
    one-liner: ``pipeline.disable("layer")``).
    """

    def __init__(self, name: str = "MultiEncryption") -> None:
        self._layers: List[Layer] = []
        # Quack like a decorated algorithm for ComposerSession/benchmark()
        self._config = AlgorithmConfig(name=name)

    # ------------------------------------------------------------------
    # Layer management
    # ------------------------------------------------------------------

    def add_layer(self, algo: Any, name: Optional[str] = None) -> "MultiEncryption":
        """Append a layer (outermost-last). Returns self for chaining."""
        config = getattr(algo, "_config", None)
        layer_name = name or (config.name if config else algo.__class__.__name__)
        if any(l.name == layer_name for l in self._layers):
            raise ValueError(f"Layer '{layer_name}' already exists")
        self._layers.append(Layer(name=layer_name, algo=algo))
        return self

    def remove_layer(self, name: str) -> "MultiEncryption":
        """Remove a layer by name."""
        self._get(name)  # raises if missing
        self._layers = [l for l in self._layers if l.name != name]
        return self

    def move_layer(self, name: str, position: int) -> "MultiEncryption":
        """Reorder a layer to *position* (0 = innermost / first to encrypt)."""
        layer = self._get(name)
        self._layers.remove(layer)
        self._layers.insert(position, layer)
        return self

    def enable(self, name: str) -> "MultiEncryption":
        """Enable a layer."""
        self._get(name).enabled = True
        return self

    def disable(self, name: str) -> "MultiEncryption":
        """Disable a layer (skipped on encrypt AND decrypt)."""
        self._get(name).enabled = False
        return self

    def layers(self) -> List[Dict[str, Any]]:
        """Layer order and status."""
        return [
            {"position": i, "name": l.name, "enabled": l.enabled}
            for i, l in enumerate(self._layers)
        ]

    def _get(self, name: str) -> Layer:
        for layer in self._layers:
            if layer.name == name:
                return layer
        raise KeyError(f"Layer '{name}' not registered")

    def _active(self) -> List[Layer]:
        return [l for l in self._layers if l.enabled]

    # ------------------------------------------------------------------
    # Pipeline operations
    # ------------------------------------------------------------------

    def encrypt(self, data: bytes) -> AlgorithmResult:
        """Chain *data* through every enabled layer in order."""
        return self._run(data, operation="encrypt")

    def decrypt(self, data: bytes) -> AlgorithmResult:
        """Unwind every enabled layer in reverse order."""
        return self._run(data, operation="decrypt")

    def _run(self, data: bytes, operation: str) -> AlgorithmResult:
        layers = self._active()
        if operation == "decrypt":
            layers = list(reversed(layers))

        start = time.perf_counter()
        metrics: Dict[str, Any] = {
            "algorithm": self._config.name,
            "operation": operation,
            "layer_count": len(layers),
            "layers": [],
        }

        if not layers:
            return AlgorithmResult(
                output=b"", metrics=metrics, success=False,
                error="Pipeline has no enabled layers",
            )

        current = data
        for layer in layers:
            result: AlgorithmResult = getattr(layer.algo, operation)(current)
            layer_metrics = {
                "layer": layer.name,
                "elapsed_ms": result.metrics.get("elapsed_ms", 0),
                "input_bytes": len(current),
                "output_bytes": len(result.output),
            }
            if operation == "encrypt" and len(current) > 0:
                layer_metrics["expansion_ratio"] = round(len(result.output) / len(current), 4)
            metrics["layers"].append(layer_metrics)

            if not result.success:
                metrics["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 3)
                return AlgorithmResult(
                    output=b"", metrics=metrics, success=False,
                    error=f"layer '{layer.name}' {operation} failed: {result.error}",
                )
            current = result.output

        metrics["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 3)
        metrics["input_bytes"] = len(data)
        metrics["output_bytes"] = len(current)
        if operation == "encrypt" and len(data) > 0:
            metrics["expansion_ratio"] = round(len(current) / len(data), 4)

        return AlgorithmResult(output=current, metrics=metrics)
