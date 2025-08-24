import sys
from pathlib import Path

import pytest

# Ensure the pysiaalarm package is importable without requiring Home Assistant.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "custom_components" / "sia"))

from pysiaalarm.event import SIAEvent
from pysiaalarm.utils import MessageTypes


def test_valid_length_with_hex_overflow():
    """Event length should be validated using hexadecimal conversion."""
    payload = "A" * 18  # 0x12 characters
    event = SIAEvent(
        full_message=payload,
        msg_crc="ABCD",
        length="0012",
        encrypted=False,
        message_type=MessageTypes.SIADCS,
    )
    assert event.valid_length


def test_valid_length_detects_mismatch():
    payload = "A" * 18
    event = SIAEvent(
        full_message=payload,
        msg_crc="ABCD",
        length="0013",
        encrypted=False,
        message_type=MessageTypes.SIADCS,
    )
    assert not event.valid_length
