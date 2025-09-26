from emuit import Buffer

import pytest


@pytest.fixture
def ascii() -> Buffer:
    return Buffer(0x10000, b'ascii string')


@pytest.fixture
def unicode() -> Buffer:
    return Buffer(0x10000, b'u\x00n\x00i\x00c\x00o\x00d\x00e\x00 \x00s\x00t\x00r\x00i\x00n\x00g\x00')


@pytest.fixture
def unicode_short() -> Buffer:
    return Buffer(0x10000, b'u\x00n\x00i\x00c\x00')


def test_ascii_pretty(ascii: Buffer):
    assert ascii.try_decode() == 'ascii string'


def test_unicode_pretty(unicode: Buffer):
    assert unicode.try_decode() == 'unicode string'


def test_unicode_short_pretty(unicode_short: Buffer):
    assert unicode_short.try_decode() == 'unic'
