"""Log source routing, field mapping and user-defined sources."""

import pytest
from sigma.exceptions import SigmaError

from sigma2leql import LEQLBackend, load_sources
from conftest import rule


def test_builtin_sources_load():
    ids = {s.id for s in load_sources()}
    assert {"process_creation", "dns", "proxy", "firewall", "azure_signin", "sysmon_registry_set"} <= ids


@pytest.mark.parametrize("product", ["windows", "linux", "macos"])
def test_process_creation_all_platforms(convert, product):
    out = convert("sel: {Image|endswith: '/curl'}\ncondition: sel", f"{{product: {product}, category: process_creation}}")
    assert out.startswith("process.exe_path=")


def test_original_file_name_mapping(convert):
    # upstream mapped OriginalFileName to process.name (the process's own name)
    assert convert("sel: {OriginalFileName: x.exe}\ncondition: sel") == (
        'process.exe_file.orig_filename = NOCASE("x.exe")'
    )


def test_unmapped_field_fails(convert):
    with pytest.raises(SigmaError, match="no InsightIDR mapping"):
        convert("sel: {IntegrityLevel: High}\ncondition: sel")


def test_keyword_detection_fails(convert):
    with pytest.raises(SigmaError, match="Keyword"):
        convert("kw: [mimikatz]\ncondition: kw")


def test_unsupported_logsource_fails(convert):
    with pytest.raises(SigmaError, match="Log source not supported"):
        convert("sel: {EventID: 4624}\ncondition: sel", "{product: windows, service: security}")


@pytest.mark.parametrize(
    "category,event_cond",
    [
        ("registry_set", "event_id=13"),
        ("registry_event", "(event_id IN [12, 13, 14])"),
        ("file_event", "event_id=11"),
        ("network_connection", "event_id=3"),
        ("pipe_created", "(event_id IN [17, 18])"),
    ],
)
def test_sysmon_routing(convert, category, event_cond):
    out = convert("sel: {Image|endswith: '\\x.exe'}\ncondition: sel", f"{{product: windows, category: {category}}}")
    assert out == f"{event_cond} AND event.EventData.Data.Image=/\\\\x\\.exe$/i"


def test_hashes_split(convert):
    out = convert("sel:\n  Hashes|contains:\n    - 'IMPHASH=AA11'\n    - 'SHA256=BB22'\ncondition: sel")
    assert out == (
        'process.exe_file.hashes.imphash = NOCASE("AA11") OR process.exe_file.hashes.sha256 = NOCASE("BB22")'
    )


def test_hashes_unknown_algo_fails(convert):
    with pytest.raises(SigmaError):
        convert("sel: {Hashes|contains: 'SHA512=abc'}\ncondition: sel")


def test_firewall_value_translation(convert):
    out = convert("sel: {action: drop, dst_port: 445}\ncondition: sel", "{category: firewall}")
    assert out == 'connection_status = NOCASE("DENY") AND destination_port=445'


def test_entry_type_attributes(backend):
    col = rule("sel: {TargetObject|contains: Run}\ncondition: sel", "{product: windows, category: registry_set}")
    backend.convert(col)
    attrs = col.rules[0].custom_attributes
    assert attrs["insightidr_entry_type"] == "sysmon"
    assert attrs["insightidr_log_set"] == "Sysmon"


def test_user_source_file(tmp_path):
    extra = tmp_path / "extra.yml"
    extra.write_text(
        """
sources:
  - id: linux_auditd
    logsource: [{product: linux, service: auditd}]
    entry_type: raw
    log_set: Linux Auditd
    fields: {exe: source_json.exe}
    conditions: {source_json.type: EXECVE}
  - id: proxy
    disabled: true
"""
    )
    backend = LEQLBackend(sources=[extra])
    out = backend.convert(rule("sel: {exe|endswith: /nc}\ncondition: sel", "{product: linux, service: auditd}"))[0]
    assert out == 'source_json.type = NOCASE("EXECVE") AND source_json.exe=/\\/nc$/i'
    with pytest.raises(SigmaError, match="Log source not supported"):
        backend.convert(rule("sel: {c-uri|contains: x}\ncondition: sel", "{category: proxy}"))


def test_invalid_source_definition(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("sources:\n  - id: x\n    logsource: [{category: y}]\n")
    with pytest.raises(ValueError, match="missing"):
        load_sources([bad])


def test_hashes_nested_in_and_is_grouped(convert):
    out = convert("sel:\n  Image|endswith: '\\x.exe'\n  Hashes|contains: ['IMPHASH=AA', 'MD5=BB']\ncondition: sel")
    assert out == (
        "process.exe_path=/\\\\x\\.exe$/i AND (process.exe_file.hashes.imphash = NOCASE(\"AA\") "
        "OR process.exe_file.hashes.md5 = NOCASE(\"BB\"))"
    )
