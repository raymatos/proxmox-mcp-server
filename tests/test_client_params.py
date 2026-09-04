"""Regression tests for Proxmox parameter serialization.

Every boolean parameter in this server (~168 across the tool modules) used to
fail with an HTTP 400: httpx renders Python ``True`` as the string ``"true"``,
but the Proxmox API's ``-boolean`` type only accepts ``1``/``0``. Proven by
elimination against a live cluster — ``clone_vm(full=)`` and
``migrate_vm(with-local-disks=)`` both succeeded with the boolean removed and
failed with it present.
"""

import httpx
import pytest

from proxmox_mcp.client import _proxmox_params, _proxmox_value


def test_true_becomes_one_and_false_becomes_zero():
    assert _proxmox_params({"full": True}) == {"full": 1}
    assert _proxmox_params({"with-local-disks": False}) == {"with-local-disks": 0}


def test_non_boolean_values_pass_through_untouched():
    data = {"newid": 123, "name": "clone", "bwlimit": 0, "ratio": 1.5, "x": None}
    assert _proxmox_params(data) == data


def test_ints_are_not_mistaken_for_booleans():
    # isinstance(True, int) is True, so ordering inside the coercion matters.
    assert _proxmox_value(1) == 1
    assert _proxmox_value(0) == 0
    assert isinstance(_proxmox_value(True), int)
    assert _proxmox_value(True) == 1


def test_booleans_inside_lists_are_converted():
    assert _proxmox_params({"flags": [True, False, "keep"]}) == {
        "flags": [1, 0, "keep"]
    }


@pytest.mark.parametrize("empty", [None, {}])
def test_empty_payloads_are_returned_unchanged(empty):
    assert _proxmox_params(empty) == empty


def test_encoded_wire_format_matches_what_proxmox_accepts():
    """The actual regression: what lands on the wire."""
    raw = {"full": True, "with-local-disks": False}
    assert "full=true" in str(httpx.QueryParams(raw))  # the old, rejected form
    encoded = str(httpx.QueryParams(_proxmox_params(raw)))
    assert "full=1" in encoded
    assert "with-local-disks=0" in encoded
    assert "true" not in encoded and "false" not in encoded
