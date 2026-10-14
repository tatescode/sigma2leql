# sigma2leql

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules into Rapid7 InsightIDR **LEQL** queries.

`sigma2leql` builds on [pySigma](https://github.com/SigmaHQ/pySigma) and the official
[pySigma-backend-insightidr](https://github.com/SigmaHQ/pySigma-backend-insightidr). It adds:

- **More log sources.** Process creation on Windows, Linux and macOS, plus 15 Windows Sysmon
  categories (registry, file, image load, network, pipes, process access, WMI and others) on top of
  the upstream DNS, proxy, firewall and Azure sign-in support.
- **Correctness fixes** for queries the upstream backend gets silently wrong (see [below](#fixes-over-the-upstream-backend)).
- **Fail-loud field checking.** If a rule uses a field InsightIDR doesn't have, the rule fails with
  a clear reason. The tool never outputs a query that can't match, or that always matches under `NOT`.
- **A batch CLI** with per-rule reports (text, `.leql` files, JSON, CSV).
- **YAML-defined log sources.** You can add or override sources without touching Python.

On the full SigmaHQ ruleset (3,154 rules), **1,966 rules convert**. The upstream backend converts 905.
Every rule that fails gets a stated reason.

## Install

Requires Python 3.9+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install "git+https://github.com/tatescode/sigma2leql.git"
# or, from a clone:
pip install -e ".[dev]"
```

> **Version pins are deliberate.** `pysigma-backend-insightidr` 0.2.4 (the latest release) requires
> `pysigma<0.12`, and pySigma 0.11 crashes on `pyparsing>=3.2` with `'str' object is not callable`.
> That crash affects about 300 SigmaHQ rules. Don't upgrade these in the same environment.
> The current `sigma-cli` requires pySigma ≥ 1.3, so it can't drive this backend. Use the
> `sigma2leql` CLI instead.

## Usage

```bash
# Convert a file or a whole directory (recursive). Queries go to stdout, a summary to stderr.
sigma2leql convert rules/

# One .leql file per rule, plus a CSV report that includes failures and their reasons
sigma2leql convert rules/ -o out/ --report report.csv

# Machine-readable output
sigma2leql convert rules/ --json results.json

# CI gate: exit 1 if any rule fails to convert
sigma2leql convert rules/ --strict

# What's supported, and how each Sigma field maps
sigma2leql sources --fields
```

### Output formats (`-f`)

| Format | Output | Use it in |
|---|---|---|
| `advanced` (default) | `where(<expr>)` | Log Search, Advanced mode, with the log set selected |
| `plain` | `<expr>` | Log Search, Simple mode, or for embedding |
| `detection` | `from(entry_type = "...")` + `where(...)` | Custom detection rule logic |

Every result is tagged with the **log set** to search, such as *Process Start Event* or *Sysmon*.
Select that log set in Log Search before running the query.

Example:

```
$ sigma2leql convert rules/windows/registry/registry_set/registry_set_run_key.yml
# Run Key Persistence From Temp Directory
# id: ... | level: high | log set: Sysmon (sysmon) | file: ...
where(event_id=13 AND ((event.EventData.Data.TargetObject ICONTAINS "\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" AND (...)) AND (NOT event.EventData.Data.Image=/\\msiexec\.exe$/i)))
```

### Python API

```python
from sigma.collection import SigmaCollection
from sigma2leql import LEQLBackend

backend = LEQLBackend(sources=["my_sources.yml"])   # extra source files are optional
rules = SigmaCollection.from_yaml(open("rule.yml").read())
print(backend.convert(rules, "leql_advanced_search"))
```

## Supported log sources

| Sigma logsource | InsightIDR log set (`entry_type`) | Notes |
|---|---|---|
| `windows`/`linux`/`macos` · `process_creation` | Process Start Event (`process_start_event`) | `Hashes` values split into md5/sha1/sha256/imphash |
| `windows` · `dns_query`, any · `dns` | DNS Query (`dns`) | |
| any · `proxy` | Web Proxy Activity (`web_proxy`) | |
| any · `firewall` | Firewall Activity (`firewall`) | `action` values translated to `ACCEPT`/`DENY` |
| `azure` · `signinlogs` | Ingress Authentication (`ingress_auth`) | `source_json.*` keys are unverified (see below) |
| `windows` · `network_connection`, `process_termination`, `driver_load`, `image_load`, `create_remote_thread`, `raw_access_thread`, `process_access`, `file_event`, `file_change`, `file_delete`, `registry_add`/`delete`/`set`/`rename`/`event`, `create_stream_hash`, `pipe_created`, `wmi_event`, `process_tampering` | Sysmon (`sysmon`) | Filtered by `event_id`; fields under `event.EventData.Data.*` |

Field targets come from Rapid7's published event-type schemas
(`https://log-entry-schema.idr.insight.rapid7.com/schemas/<type>/latest/<type>.schema.json`).
Run `sigma2leql sources --fields` for the full mapping.

## Adding a log source

Log sources are defined in YAML. The built-ins are in
[`src/sigma2leql/sources.yml`](src/sigma2leql/sources.yml). To add your own, write a file and pass it
with `--sources` (repeatable):

```yaml
sources:
  - id: powershell_script_block
    logsource: [{product: windows, category: ps_script}]
    entry_type: raw                     # used by the `detection` format
    log_set: Windows PowerShell         # the log set name in your tenant
    conditions: {source_json.eventCode: 4104}   # ANDed onto every query
    fields:                             # Sigma field -> LEQL key
      ScriptBlockText: source_json.eventData.ScriptBlockText
```

Other keys:
- `prefix` + `passthrough`: keep Sigma field names and add a prefix
- `values`: translate exact values
- `hashes`: split Sysmon-style `Hashes`
- `disabled: true`: remove a built-in source

An entry with the same `id` as a built-in **replaces** it. See
[`examples/custom_sources.yml`](examples/custom_sources.yml).

To find the right keys, open a real event in Log Search's Entry Inspector. Then convert your rules
with `--report report.csv` and test a few of the queries in Log Search.

## Fixes over the upstream backend

| Sigma | Upstream 0.2.4 output | Problem | sigma2leql |
|---|---|---|---|
| `X: foo` OR `X\|contains: bar` | `X IIN ["foo","bar"]` | contains is dropped | `X = NOCASE("foo") OR X ICONTAINS "bar"` |
| `Image: 'C:\Users\*\evil.exe'` | `= NOCASE("C:\Users\*\evil.exe")` | `*` is matched literally | `=/^C:\\Users\\.*\\evil\.exe$/i` |
| `a?b.exe` | `NOCASE("a*b.exe")` | same | `=/^a.b\.exe$/i` |
| `\|re: 'a/b'` | `=/a/b/i` | broken regex; forced case-insensitive | `=/a\/b/` |
| `OriginalFileName` | `process.name` | wrong field | `process.exe_file.orig_filename` |
| `c-uri-query` | `url_path` | wrong field | `url_query` |
| value with `'` and `"` | `"""..."""` | not LEQL syntax | `'''...'''` |
| `detection` format | splits on `AND`/`OR` inside strings | changes the search string | not split |
| unknown fields | passed through as-is | silent no-match | rule fails with a reason |
| `x AND y OR z` | relies on operator precedence | LEQL precedence is undocumented | every group parenthesized |
| `Signed: false`, numbers in lists, empty values | crash | | supported |

Upstream rejected `Hashes`, `Imphash` and the proxy `c-useragent`/`c-uri-stem` fields. These now map
to real schema fields.

## Known limitations / verify in your tenant

LEQL behavior that Rapid7 doesn't document, and that couldn't be tested without a tenant:

1. **Sysmon key layout.** Rapid7's schema puts Sysmon fields at `event.EventData.Data.<Name>` with
   `event_id`. Check this against a real Sysmon event in your tenant.
2. **Backslashes in quoted strings.** Rapid7's docs show `where(path="C:\Windows")` with single,
   literal backslashes, and the tool relies on that. Values ending in `\` are emitted as regexes to
   avoid any escaping ambiguity.
3. **Numeric/boolean comparisons.** `event_id=13`, `event_id IN [12, 13]` and
   `X = NOCASE("false")` are used against keys that are strings in the schema.
4. **Azure sign-in `source_json.*` keys** come from upstream and aren't covered by a published schema.

Not supported. These rules fail with a reason:
- `null` checks (57 SigmaHQ rules), `exists`, `fieldref`, and keyword-only (full-text) detections.
  LEQL has no documented missing-key test.
- Fields InsightIDR doesn't collect for the event type, such as `IntegrityLevel`, `CurrentDirectory`
  and `LogonId` for process start, or `Image` for DNS. Sysmon process creation would provide them,
  but `process_creation` is routed to Process Start Event.
- Windows Security/System/PowerShell event logs, cloud audit logs, auditd and similar sources. These
  depend on how your tenant ingests them. Add them with `--sources`.
- Correlation rules and aggregations.
- Very large IOC rules (for example `driver_load_win_vuln_drivers.yml`, about 237K characters) are
  flagged in the summary, because they likely exceed InsightIDR query limits.

## Development

```bash
pip install -e ".[dev]"
pytest

# Regression check against the SigmaHQ corpus
git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
sigma2leql convert /tmp/sigma/rules -o /tmp/out --report /tmp/report.csv > /dev/null
```

## License

MIT. See [LICENSE](LICENSE).

This project depends on, but does not include or modify, [pySigma](https://github.com/SigmaHQ/pySigma)
and [pySigma-backend-insightidr](https://github.com/SigmaHQ/pySigma-backend-insightidr). Both are
licensed under LGPL-2.1, and their licenses apply to those packages when installed.
