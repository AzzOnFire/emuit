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


def test_unicode_terminated_pretty():
    # short UTF-16 strings followed by zero bytes, also shifted by one byte
    assert Buffer(0x10000, b'D\x00S\x00\x00\x00\x00').try_decode() == 'DS'
    assert Buffer(0x10000, b'\x00D\x00S\x00\x00\x00').try_decode() == 'DS'


def test_undecodable_pretty():
    # no prefix decodes as UTF-8
    assert Buffer(0x10000, b'\x80hello world').try_decode() == ''


def test_partly_decodable_pretty():
    # the longest prefix that decodes
    assert Buffer(0x10000, b'hello\xe9world').try_decode() == 'hello'
    assert Buffer(0x10000, b'A' * 200000 + b'\xe9' + b'B' * 200000).try_decode() == 'A' * 200000


def test_metric_decodable_silent(capsys, ascii: Buffer):
    assert ascii.metric_decodable() > 0.6
    assert capsys.readouterr().out == ''


def test_write_instruction_ea():
    assert Buffer(0x10000, b'ab', [0x401000, 0x401000, 0x401004]).write_instruction_ea == 0x401000
    assert Buffer(0x10000, b'ab').write_instruction_ea is None


def test_repr():
    assert repr(Buffer(0x10000, b'ab', [0x401000])) == "Buffer(pc=0x401000, ea=0x10000, data=b'ab')"
    assert repr(Buffer(0x10000, b'ab')) == "Buffer(pc=None, ea=0x10000, data=b'ab')"
    assert str(Buffer(0x10000, b'ab')) == "b'ab'"
