"""Import helpers for user-provided authorizers and custom invariants."""

from __future__ import annotations

import importlib
from collections.abc import Callable
from typing import Any, cast

from permissiondiff.errors import AdapterError


def load_callable(spec: str) -> Callable[..., Any]:
    """Load a callable from a strict ``module:attribute`` reference."""
    module_name, separator, attribute_name = spec.partition(":")
    if not separator or not module_name or not attribute_name:
        raise AdapterError(f"invalid callable {spec!r}; expected 'module:function'")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise AdapterError(f"could not import module {module_name!r}: {exc}") from exc
    try:
        value = getattr(module, attribute_name)
    except AttributeError as exc:
        raise AdapterError(f"module {module_name!r} has no attribute {attribute_name!r}") from exc
    if not callable(value):
        raise AdapterError(f"{spec!r} does not reference a callable")
    return cast("Callable[..., Any]", value)
