import json
import re
from pathlib import Path

import pytest

from sigma2leql.cli import main

RULES = Path(__file__).parent / "rules"


def test_convert_directory_json(capsys):
    assert main(["convert", str(RULES), "--json", "-", "-q"]) == 0
    results = {Path(r["file"]).name: r for r in json.loads(capsys.readouterr().out)}
    ok = results["proc_creation_certutil_download.yml"]
    assert ok["status"] == "ok"
    assert ok["log_set"] == "Process Start Event"
    assert ok["query"].startswith("where(")
    assert results["unsupported_security_logon.yml"]["status"] == "error"


def test_strict_exit_code():
    assert main(["convert", str(RULES), "-q"]) == 0  # failures alone don't fail the run
    assert main(["convert", str(RULES / "proc_creation_certutil_download.yml"), "--strict", "-q"]) == 0
    assert main(["convert", str(RULES / "unsupported_security_logon.yml"), "--strict", "-q"]) == 1


def test_output_dir_and_report(tmp_path):
    out, report = tmp_path / "out", tmp_path / "report.csv"
    assert main(["convert", str(RULES), "-o", str(out), "--report", str(report), "-q", "-f", "detection"]) == 0
    leql = (out / "registry_set_run_key.leql").read_text()
    assert 'entry_type = "sysmon"' in leql
    assert "# log set: Sysmon" in leql
    assert "unsupported_security_logon" in report.read_text()


def test_sources_command(capsys):
    assert main(["sources", "--fields"]) == 0
    out = capsys.readouterr().out
    assert "sysmon_registry_set" in out
    assert re.search(r"CommandLine +->  process.cmd_line", out)
    assert "Hashes (IMPHASH=...)" in out


def test_missing_path():
    with pytest.raises(SystemExit, match="no such file"):
        main(["convert", "does/not/exist.yml"])
