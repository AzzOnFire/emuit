from emuit import Result

import pytest


@pytest.fixture
def ascii() -> Result:
    return Result({0x10000: b'ascii string'})


@pytest.fixture
def unicode() -> Result:
    return Result({0x10000: b'u\x00n\x00i\x00c\x00o\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00'})


@pytest.fixture
def unicode_short() -> Result:
    return Result({0x10000: b'u\x00n\x00i\x00c\x00'})


def test_ascii_pretty(ascii: Result):
    res = ascii.pretty()
    assert res[0x10000] == 'ascii string'


def test_unicode_pretty(unicode: Result):
    res = unicode.pretty()
    assert res[0x10000] == 'unicode string'


def test_unicode_short_pretty(unicode_short: Result):
    res = unicode_short.pretty()
    assert res[0x10000] == 'unic'
