"""Value/operator translation. Each case pins a specific LEQL output."""

import pytest
from sigma.exceptions import SigmaError


def test_exact(convert):
    assert convert("sel: {Image: 'C:\\Windows\\cmd.exe'}\ncondition: sel") == (
        'process.exe_path = NOCASE("C:\\Windows\\cmd.exe")'
    )


def test_contains_startswith_endswith(convert):
    assert convert("sel: {CommandLine|contains: 'http'}\ncondition: sel") == 'process.cmd_line ICONTAINS "http"'
    assert convert("sel: {CommandLine|startswith: 'cmd'}\ncondition: sel") == 'process.cmd_line ISTARTS-WITH "cmd"'
    assert convert("sel: {Image|endswith: '\\cmd.exe'}\ncondition: sel") == "process.exe_path=/\\\\cmd\\.exe$/i"


def test_inner_wildcard_becomes_regex(convert):
    # upstream emitted NOCASE("C:\Users\*\evil.exe"), matching a literal asterisk
    assert convert("sel: {Image: 'C:\\Users\\\\*\\evil.exe'}\ncondition: sel") == (
        "process.exe_path=/^C:\\\\Users\\\\.*\\\\evil\\.exe$/i"
    )


def test_single_char_wildcard(convert):
    assert convert("sel: {Image: 'C:\\a?b.exe'}\ncondition: sel") == "process.exe_path=/^C:\\\\a.b\\.exe$/i"


def test_escaped_wildcard_is_literal(convert):
    assert convert("sel: {CommandLine|contains: 'a\\*b'}\ncondition: sel") == 'process.cmd_line ICONTAINS "a*b"'


def test_mixed_or_is_not_merged(convert):
    # upstream produced: process.cmd_line IIN ["foo", "bar"]
    out = convert("a: {CommandLine: foo}\nb: {CommandLine|contains: bar}\ncondition: a or b")
    assert out == 'process.cmd_line = NOCASE("foo") OR process.cmd_line ICONTAINS "bar"'


def test_list_operators(convert):
    assert convert("sel: {CommandLine: [a, b]}\ncondition: sel") == 'process.cmd_line IIN ["a", "b"]'
    assert convert("sel: {CommandLine|contains: [a, b]}\ncondition: sel") == (
        'process.cmd_line ICONTAINS-ANY ["a", "b"]'
    )
    assert convert("sel: {CommandLine|startswith: [a, b]}\ncondition: sel") == (
        'process.cmd_line ISTARTS-WITH-ANY ["a", "b"]'
    )
    assert convert("sel: {CommandLine|contains|all: [a, b]}\ncondition: sel") == (
        'process.cmd_line ICONTAINS-ALL ["a", "b"]'
    )
    assert convert("sel: {Image|endswith: ['\\a.exe', '\\b.exe']}\ncondition: sel") == (
        "process.exe_path=/(\\\\a\\.exe|\\\\b\\.exe)$/i"
    )


def test_number_list(convert):
    assert convert("sel: {ProcessId: [1, 2]}\ncondition: sel") == "process.pid IN [1, 2]"


def test_quotes(convert):
    assert convert("sel: {CommandLine|contains: 'say \"hi\"'}\ncondition: sel") == (
        "process.cmd_line ICONTAINS 'say \"hi\"'"
    )
    assert convert("sel: {CommandLine|contains: \"it's\"}\ncondition: sel") == 'process.cmd_line ICONTAINS "it\'s"'
    assert convert("sel: {CommandLine|contains: 'a\"b''c'}\ncondition: sel") == (
        "process.cmd_line ICONTAINS '''a\"b'c'''"
    )


def test_trailing_backslash_uses_regex(convert):
    assert convert("sel: {CommandLine|contains: '\\Temp\\'}\ncondition: sel") == "process.cmd_line=/\\\\Temp\\\\/i"


def test_regex_slash_escaped_and_case_sensitive(convert):
    assert convert("sel: {CommandLine|re: 'a/b'}\ncondition: sel") == "process.cmd_line=/a\\/b/"
    assert convert("sel: {CommandLine|re|i: 'a\\/b'}\ncondition: sel") == "process.cmd_line=/a\\/b/i"


def test_cased_modifier(convert):
    assert convert("sel: {CommandLine|contains|cased: 'AbC'}\ncondition: sel") == 'process.cmd_line CONTAINS "AbC"'


def test_boolean(convert):
    out = convert("sel: {Signed: false}\ncondition: sel", "{product: windows, category: image_load}")
    assert out == 'event_id=7 AND event.EventData.Data.Signed = NOCASE("false")'


def test_explicit_grouping(convert):
    out = convert("a: {CommandLine: x}\nb: {Image: y}\nc: {User: z}\ncondition: a and not (b or c)")
    assert out == (
        'process.cmd_line = NOCASE("x") AND (NOT (process.exe_path = NOCASE("y") '
        'OR process.username = NOCASE("z")))'
    )


@pytest.mark.parametrize(
    "detection",
    [
        "sel: {CommandLine: null}\ncondition: sel",
        "sel: {CommandLine|exists: true}\ncondition: sel",
        "sel: {CommandLine|fieldref: Image}\ncondition: sel",
        "sel: {CommandLine|re|m: 'a'}\ncondition: sel",
    ],
)
def test_unsupported_constructs_fail(convert, detection):
    with pytest.raises((SigmaError, NotImplementedError)):
        convert(detection)


def test_formats(convert):
    det = "sel: {CommandLine|contains: 'x AND y'}\ncondition: sel"
    assert convert(det, fmt="leql_advanced_search") == 'where(process.cmd_line ICONTAINS "x AND y")'
    # upstream split the string literal on "AND"
    assert convert(det, fmt="leql_detection_definition") == (
        'from(\n  entry_type = "process_start_event"\n)\nwhere(\n  process.cmd_line ICONTAINS "x AND y"\n)'
    )
