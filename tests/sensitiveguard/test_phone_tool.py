"""Tests for the minimal phone-number detection tool."""

from __future__ import annotations

import pytest

from sensitiveguard.phone_tool import detect


@pytest.mark.parametrize(
    "text",
    [
        "请联系13800138000",
        "请联系 +86 13800138000",
        "请联系 0086-138-0013-8000",
    ],
)
def test_detect_finds_mainland_mobile_numbers(text: str) -> None:
    result = detect(text)

    assert result == {"has_phone": True, "count": 1}
    assert "13800138000" not in repr(result)


def test_detect_returns_false_when_no_mobile_number_exists() -> None:
    assert detect("客户希望下周再次联系") == {"has_phone": False, "count": 0}


def test_detect_counts_multiple_numbers_without_returning_them() -> None:
    text = "主号码13800138000，备用号码13900139000"

    result = detect(text)

    assert result == {"has_phone": True, "count": 2}
    assert "13800138000" not in repr(result)
    assert "13900139000" not in repr(result)


def test_detect_rejects_non_string_input() -> None:
    with pytest.raises(TypeError, match="text must be a string"):
        detect(13800138000)  # type: ignore[arg-type]
