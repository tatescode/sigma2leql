"""InsightIDR LEQL backend: upstream pySigma-backend-insightidr with correctness fixes.

Fixes over upstream 0.2.4:
* wildcards inside a value (``C:\\Users\\*\\x.exe``) and ``?`` wildcards are converted to regular
  expressions instead of being matched literally
* OR/AND lists are only merged into IIN / ICONTAINS-ANY / ... when every value uses the same match
  type; upstream merged ``x = foo OR x contains bar`` into ``x IIN ["foo", "bar"]``
* ``/`` inside Sigma regular expressions is escaped, and regexes keep Sigma's case-sensitivity
* triple quotes use LEQL's ``'''`` (upstream emitted ``\"\"\"``)
* values that cannot be quoted safely (trailing backslash, backslash before the quote) fall back to
  an equivalent regex
* the detection-rule format no longer splits on AND/OR inside string values
* unsupported constructs (null, exists, field references, cased modifiers on lists) fail loudly
"""

from typing import ClassVar, Dict, List, Optional, Tuple, Union

from sigma.backends.insight_idr import InsightIDRBackend
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionOR
from sigma.conversion.state import ConversionState
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaCasedString,
    SigmaNumber,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

from .pipeline import ENTRY_TYPE_ATTR, insightidr_pipeline

# Characters escaped when a literal is embedded in a LEQL /regex/. Kept minimal on purpose so the
# result is valid in any common regex dialect (Python's re.escape also escapes spaces, '#', etc.).
_REGEX_SPECIAL = set("\\.^$|?*+()[]{}/")

EXACT, CONTAINS, STARTSWITH, ENDSWITH, REGEX, ANY = (
    "exact",
    "contains",
    "startswith",
    "endswith",
    "regex",
    "any",
)


def regex_escape(text: str) -> str:
    return "".join("\\" + c if c in _REGEX_SPECIAL else c for c in text)


def escape_regex_slashes(regexp: str) -> str:
    """Escape unescaped forward slashes so a regex can be wrapped in /.../."""
    out, escaped = [], False
    for c in regexp:
        if c == "/" and not escaped:
            out.append("\\/")
        else:
            out.append(c)
        escaped = c == "\\" and not escaped
    return "".join(out)


def quote(text: str) -> Optional[str]:
    """Quote a literal for LEQL, or return None if it cannot be quoted safely."""
    if '"' not in text:
        q = '"'
    elif "'" not in text:
        q = "'"
    elif "'''" not in text and not text.endswith("'"):
        q = "'''"
    else:
        return None
    # A backslash right before the closing quote (or before an embedded quote char) could be read
    # as an escape sequence; avoid the ambiguity entirely.
    if text.endswith("\\") or ("\\" + q[0]) in text:
        return None
    return q + text + q


class LEQLBackend(InsightIDRBackend):
    """Rapid7 InsightIDR LEQL backend with extended log sources and correctness fixes."""

    name: ClassVar[str] = "Rapid7 InsightIDR LEQL (sigma2leql)"
    formats: ClassVar[Dict[str, str]] = {
        "default": "Plain LEQL expression for Log Search",
        "leql_advanced_search": "where(...) query for Log Search 'Advanced' mode",
        "leql_detection_definition": "from(entry_type)/where() block for detection rule logic",
    }
    backend_processing_pipeline: ClassVar[ProcessingPipeline] = insightidr_pipeline()

    # LEQL's AND/OR precedence is not documented, so never rely on it: group every sub-expression.
    parenthesize: bool = True

    str_triple_quote: ClassVar[str] = "'''"
    case_sensitive_eq_token: ClassVar[str] = "="
    field_null_expression = None
    field_equals_field_expression = None

    def __init__(self, processing_pipeline=None, collect_errors=False, sources=(), **backend_options):
        super().__init__(processing_pipeline, collect_errors, **backend_options)
        if sources:
            self.backend_processing_pipeline = insightidr_pipeline(sources)

    # ------------------------------------------------------------------ string classification

    @staticmethod
    def classify(value: SigmaString) -> Tuple[str, Optional[str]]:
        """Return (match type, literal) for a Sigma string.

        The literal is None for REGEX (wildcards inside the value, '?' wildcards, or a literal that
        cannot be quoted safely) and ANY (value is just '*').
        """
        parts = list(value.s)
        wildcards = (SpecialChars.WILDCARD_MULTI, SpecialChars.WILDCARD_SINGLE)
        if any(not isinstance(p, str) and p not in wildcards for p in parts):
            raise SigmaFeatureNotSupportedByBackendError(
                "Unresolved placeholder in value; resolve placeholders before conversion."
            )
        if parts and all(p is SpecialChars.WILDCARD_MULTI for p in parts):
            return ANY, None
        lead = bool(parts) and parts[0] is SpecialChars.WILDCARD_MULTI
        trail = bool(parts) and parts[-1] is SpecialChars.WILDCARD_MULTI
        core = parts[int(lead) : len(parts) - int(trail)]
        if not all(isinstance(p, str) for p in core):
            return REGEX, None
        literal = "".join(core)
        if quote(literal) is None:
            return REGEX, None
        kind = {(False, False): EXACT, (True, True): CONTAINS, (False, True): STARTSWITH, (True, False): ENDSWITH}[
            (lead, trail)
        ]
        return kind, literal

    @staticmethod
    def string_to_regex(value: SigmaString) -> str:
        """Convert a Sigma string (with wildcards) to an anchored regex body."""
        parts = list(value.s)
        lead = bool(parts) and parts[0] is SpecialChars.WILDCARD_MULTI
        trail = len(parts) > 1 and parts[-1] is SpecialChars.WILDCARD_MULTI
        core = parts[int(lead) : len(parts) - int(trail)]
        body = "".join(
            ".*" if p is SpecialChars.WILDCARD_MULTI else "." if p is SpecialChars.WILDCARD_SINGLE else regex_escape(p)
            for p in core
        )
        return ("" if lead else "^") + body + ("" if trail else "$")

    def _regex(self, field: str, body: str, case_insensitive: bool = True) -> str:
        return f"{field}=/{body}/{'i' if case_insensitive else ''}"

    # ------------------------------------------------------------------ field = value

    def convert_condition_field_eq_val_str(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState):
        kind, literal = self.classify(cond.value)
        field = cond.field
        if kind == ANY:
            return self._regex(field, ".*", False)
        if kind == REGEX:
            return self._regex(field, self.string_to_regex(cond.value))
        if kind == CONTAINS:
            return f"{field} ICONTAINS {quote(literal)}"
        if kind == STARTSWITH:
            return f"{field} ISTARTS-WITH {quote(literal)}"
        if kind == ENDSWITH:
            return self._regex(field, regex_escape(literal) + "$")
        return f"{field} = NOCASE({quote(literal)})"

    def convert_condition_field_eq_val_str_case_sensitive(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ):
        kind, literal = self.classify(cond.value)
        field = cond.field
        if kind == ANY:
            return self._regex(field, ".*", False)
        if kind == CONTAINS:
            return f"{field} CONTAINS {quote(literal)}"
        if kind == STARTSWITH:
            return f"{field} STARTS-WITH {quote(literal)}"
        if kind == EXACT:
            return f"{field} = {quote(literal)}"
        return self._regex(field, self.string_to_regex(cond.value), case_insensitive=False)

    def convert_condition_field_eq_val_re(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState):
        flags = cond.value.flags
        unsupported = flags - {SigmaRegularExpressionFlag.IGNORECASE}
        if unsupported:
            raise SigmaFeatureNotSupportedByBackendError(
                f"Regex flags {', '.join(f.name for f in unsupported)} are not supported in LEQL."
            )
        return self._regex(
            cond.field,
            escape_regex_slashes(cond.value.regexp),
            case_insensitive=SigmaRegularExpressionFlag.IGNORECASE in flags,
        )

    def convert_condition_field_eq_val_bool(self, cond: ConditionFieldEqualsValueExpression, state: ConversionState):
        # InsightIDR stores booleans from Windows/Sysmon events as "true"/"false" strings.
        return f"{cond.field} = NOCASE(\"{'true' if cond.value.boolean else 'false'}\")"

    def convert_condition_field_eq_val_null(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Null/empty-field checks are not supported in LEQL.")

    def convert_condition_field_eq_val_exists(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("The 'exists' modifier is not supported in LEQL.")

    def convert_condition_field_eq_field(self, cond, state):
        raise SigmaFeatureNotSupportedByBackendError("Field references (fieldref) are not supported in LEQL.")

    # ------------------------------------------------------------------ list (in) expressions

    def _list_kind(self, cond: Union[ConditionOR, ConditionAND]) -> Optional[str]:
        """The shared match type if `cond` can be expressed as a single list operator, else None."""
        args = cond.args
        if len(args) < 2 or not all(isinstance(a, ConditionFieldEqualsValueExpression) for a in args):
            return None
        if len({a.field for a in args}) != 1:
            return None
        if all(isinstance(a.value, SigmaNumber) for a in args):
            return "number" if isinstance(cond, ConditionOR) else None
        if not all(type(a.value) is SigmaString for a in args):  # excludes cased strings, regex, etc.
            return None
        kinds = {self.classify(a.value)[0] for a in args}
        if len(kinds) != 1:
            return None
        kind = kinds.pop()
        if isinstance(cond, ConditionAND):
            return kind if kind == CONTAINS else None
        return kind if kind in (EXACT, CONTAINS, STARTSWITH, ENDSWITH) else None

    def decide_convert_condition_as_in_expression(self, cond, state) -> bool:
        return self._list_kind(cond) is not None

    def convert_condition_as_in_expression(self, cond, state):
        kind = self._list_kind(cond)
        field = cond.args[0].field
        if kind == "number":
            return f"{field} IN [{', '.join(str(a.value) for a in cond.args)}]"
        literals = [self.classify(a.value)[1] for a in cond.args]
        if kind == ENDSWITH:
            return self._regex(field, "(" + "|".join(regex_escape(v) for v in literals) + ")$")
        items = ", ".join(quote(v) for v in literals)
        if isinstance(cond, ConditionAND):
            return f"{field} ICONTAINS-ALL [{items}]"
        op = {EXACT: "IIN", CONTAINS: "ICONTAINS-ANY", STARTSWITH: "ISTARTS-WITH-ANY"}[kind]
        return f"{field} {op} [{items}]"

    # ------------------------------------------------------------------ output formats

    def finalize_query_leql_detection_definition(self, rule: SigmaRule, query: str, index: int, state) -> str:
        entry_type = rule.custom_attributes.get(ENTRY_TYPE_ATTR) or rule.logsource.category
        return f'from(\n  entry_type = "{entry_type}"\n)\nwhere(\n  {query}\n)'
