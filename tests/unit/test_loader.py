"""Tests for strict authorizer/invariant callable loading."""

from __future__ import annotations

import pytest

from permissiondiff.errors import AdapterError
from permissiondiff.loader import load_callable


def test_loads_a_valid_callable() -> None:
    assert load_callable("os:getcwd")() != ""


def test_rejects_spec_without_module_and_attribute() -> None:
    with pytest.raises(AdapterError, match="expected 'module:function'"):
        load_callable("nocolon")


def test_rejects_unimportable_module() -> None:
    with pytest.raises(AdapterError, match="could not import module"):
        load_callable("permissiondiff_missing_module:authorize")


def test_rejects_missing_attribute() -> None:
    with pytest.raises(AdapterError, match="has no attribute"):
        load_callable("os:definitely_missing_attribute")


def test_rejects_non_callable_attribute() -> None:
    with pytest.raises(AdapterError, match="does not reference a callable"):
        load_callable("os:sep")
