"""sigma2leql command line interface."""

import argparse
import csv
import json
import re
import sys
import warnings
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator, List, Optional

from sigma.collection import SigmaCollection

from . import __version__
from .backend import LEQLBackend
from .pipeline import HASH_FIELD_PREFIX, ENTRY_TYPE_ATTR, LOG_SET_ATTR, SOURCE_ID_ATTR, load_sources

LONG_QUERY = 10_000

FORMATS = {
    "plain": "default",
    "advanced": "leql_advanced_search",
    "detection": "leql_detection_definition",
}


@dataclass
class Result:
    file: str
    title: str = ""
    id: str = ""
    level: str = ""
    logsource: str = ""
    status: str = "ok"
    log_set: str = ""
    entry_type: str = ""
    source: str = ""
    query: str = ""
    error: str = ""


def iter_rule_files(paths: List[str]) -> Iterator[Path]:
    for p in map(Path, paths):
        if p.is_dir():
            yield from sorted(f for f in p.rglob("*") if f.suffix in (".yml", ".yaml") and f.is_file())
        elif p.is_file():
            yield p
        else:
            raise SystemExit(f"error: no such file or directory: {p}")


def clean_error(e: Exception) -> str:
    msg = str(e).strip() or type(e).__name__
    return re.sub(r"\s*\(while converting rule.*\)$", "", msg)


def convert_file(path: Path, backend: LEQLBackend, fmt: str) -> List[Result]:
    try:
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    except Exception as e:  # malformed YAML or invalid Sigma
        return [Result(file=str(path), status="error", error=f"parse error: {clean_error(e)}")]
    results = []
    for rule in collection.rules:
        ls = rule.logsource if hasattr(rule, "logsource") else None
        res = Result(
            file=str(path),
            title=rule.title or "",
            id=str(rule.id or ""),
            level=str(rule.level.name.lower()) if getattr(rule, "level", None) else "",
            logsource="/".join(v for v in (ls.product, ls.category, ls.service) if v) if ls else "",
        )
        try:
            queries = backend.convert_rule(rule, fmt)
            res.query = "\n".join(str(q) for q in queries)
            res.entry_type = rule.custom_attributes.get(ENTRY_TYPE_ATTR, "")
            res.log_set = rule.custom_attributes.get(LOG_SET_ATTR, "")
            res.source = rule.custom_attributes.get(SOURCE_ID_ATTR, "")
        except Exception as e:
            res.status, res.error = "error", clean_error(e)
        results.append(res)
    return results


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("_") or "rule"


def write_text(results: List[Result], out, show_errors: bool):
    for r in results:
        if r.status == "ok":
            out.write(f"# {r.title}\n# id: {r.id or '-'} | level: {r.level or '-'} | "
                      f"log set: {r.log_set} ({r.entry_type}) | file: {r.file}\n{r.query}\n\n")
        elif show_errors:
            out.write(f"# SKIPPED {r.title or r.file}\n# {r.file}: {r.error}\n\n")


def write_outdir(results: List[Result], outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    used = Counter()
    for r in results:
        if r.status != "ok":
            continue
        stem = safe_name(Path(r.file).stem)
        used[stem] += 1
        name = stem if used[stem] == 1 else f"{stem}_{used[stem]}"
        header = (f"# {r.title}\n# id: {r.id or '-'}\n# level: {r.level or '-'}\n"
                  f"# log set: {r.log_set} (entry_type {r.entry_type})\n# source: {r.file}\n")
        (outdir / f"{name}.leql").write_text(header + r.query + "\n", encoding="utf-8")


def write_csv(results: List[Result], path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(Result.__dataclass_fields__))
        w.writeheader()
        for r in results:
            w.writerow(asdict(r))


def summarize(results: List[Result], err) -> None:
    ok = sum(r.status == "ok" for r in results)
    failed = [r for r in results if r.status != "ok"]
    err.write(f"\nConverted {ok}/{len(results)} rules")
    if failed:
        err.write(f" ({len(failed)} failed)\n\nTop failure reasons:\n")
        reasons = Counter(r.error.split(". Supported")[0][:140] for r in failed)
        for reason, n in reasons.most_common(10):
            err.write(f"  {n:5}  {reason}\n")
    else:
        err.write("\n")
    long = [r for r in results if len(r.query) > LONG_QUERY]
    if long:
        err.write(f"\n{len(long)} queries are longer than {LONG_QUERY:,} characters and may exceed "
                  "InsightIDR query limits (usually large IOC lists):\n")
        for r in long[:10]:
            err.write(f"  {len(r.query):9,}  {r.file}\n")
    by_set = Counter(r.log_set for r in results if r.status == "ok")
    if by_set:
        err.write("\nBy log set:\n")
        for name, n in by_set.most_common():
            err.write(f"  {n:5}  {name}\n")


def cmd_convert(args) -> int:
    backend = LEQLBackend(sources=args.sources)
    results: List[Result] = []
    for path in iter_rule_files(args.paths):
        results += convert_file(path, backend, FORMATS[args.format])

    if args.output:
        write_outdir(results, Path(args.output))
    if args.json:
        payload = json.dumps([asdict(r) for r in results], indent=2)
        if args.json == "-":
            sys.stdout.write(payload + "\n")
        else:
            Path(args.json).write_text(payload + "\n", encoding="utf-8")
    if args.report:
        write_csv(results, args.report)
    if not args.output and args.json != "-":
        write_text(results, sys.stdout, show_errors=args.show_errors)
    if not args.quiet:
        summarize(results, sys.stderr)

    failed = any(r.status != "ok" for r in results)
    return 1 if (failed and args.strict) else 0


def cmd_sources(args) -> int:
    for src in load_sources(args.sources):
        ls = ", ".join(
            "/".join(v for v in (l.get("product"), l.get("category"), l.get("service")) if v) for l in src.logsource
        )
        print(f"{src.id}  [{src.status}]")
        print(f"  sigma logsource : {ls}")
        print(f"  InsightIDR      : log set '{src.log_set}', entry_type {src.entry_type}")
        if src.conditions:
            print(f"  adds condition  : {src.conditions}")
        if args.fields:
            shown = {
                (f"Hashes ({k[len(HASH_FIELD_PREFIX):]}=...)" if k.startswith(HASH_FIELD_PREFIX) else k): v
                for k, v in src.fields.items()
            }
            width = max(len(k) for k in shown)
            for k, v in sorted(shown.items()):
                print(f"    {k:<{width}}  ->  {v}")
        print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sigma2leql", description="Convert Sigma rules to Rapid7 InsightIDR LEQL.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("convert", help="convert Sigma rule files or directories")
    c.add_argument("paths", nargs="+", help="Sigma rule files and/or directories (searched recursively)")
    c.add_argument("-f", "--format", choices=FORMATS, default="advanced",
                   help="plain: bare expression; advanced: where(...) for Log Search (default); "
                        "detection: from(entry_type)/where() rule logic")
    c.add_argument("-s", "--sources", action="append", default=[], metavar="YAML",
                   help="extra/override log source definitions (repeatable)")
    c.add_argument("-o", "--output", metavar="DIR", help="write one .leql file per converted rule into DIR")
    c.add_argument("--json", metavar="FILE", help="write all results as JSON ('-' for stdout)")
    c.add_argument("--report", metavar="CSV", help="write a per-rule CSV report including failures")
    c.add_argument("--show-errors", action="store_true", help="include failed rules in text output")
    c.add_argument("--strict", action="store_true", help="exit with status 1 if any rule fails")
    c.add_argument("-q", "--quiet", action="store_true", help="no summary on stderr")
    c.set_defaults(func=cmd_convert)

    s = sub.add_parser("sources", help="list supported log sources")
    s.add_argument("-s", "--sources", action="append", default=[], metavar="YAML")
    s.add_argument("--fields", action="store_true", help="show field mappings")
    s.set_defaults(func=cmd_sources)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    warnings.filterwarnings("ignore", module="sigma")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
