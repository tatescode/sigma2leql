"""Build the InsightIDR processing pipeline from declarative log source definitions (sources.yml)."""

from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union

import yaml
from sigma.conditions import ConditionOR
from sigma.exceptions import SigmaTransformationError
from sigma.modifiers import SigmaAllModifier
from sigma.processing.conditions import (
    DetectionItemProcessingCondition,
    FieldNameProcessingCondition,
    IncludeFieldCondition,
    LogsourceCondition,
    RuleProcessingItemAppliedCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    DetectionItemFailureTransformation,
    DetectionItemTransformation,
    FieldMappingTransformation,
    MapStringTransformation,
    RuleFailureTransformation,
    SetCustomAttributeTransformation,
)
from sigma.rule import SigmaDetection, SigmaDetectionItem
from sigma.types import SigmaString

ENTRY_TYPE_ATTR = "insightidr_entry_type"
LOG_SET_ATTR = "insightidr_log_set"
SOURCE_ID_ATTR = "insightidr_source_id"


@dataclass
class LogSource:
    id: str
    logsource: List[Dict[str, Optional[str]]]
    entry_type: str
    log_set: str
    fields: Dict[str, str] = field(default_factory=dict)
    conditions: Dict[str, Union[str, int, List[Union[str, int]]]] = field(default_factory=dict)
    values: Dict[str, Dict[str, str]] = field(default_factory=dict)
    hashes: Dict[str, str] = field(default_factory=dict)
    description: str = ""
    status: str = "unverified"

    @classmethod
    def from_dict(cls, d: dict) -> "LogSource":
        d = dict(d)
        prefix = d.pop("prefix", "")
        passthrough = d.pop("passthrough", [])
        mapping = {name: prefix + name for name in passthrough}
        mapping.update(d.get("fields") or {})
        d["hashes"] = {k.upper(): v for k, v in (d.get("hashes") or {}).items()}
        mapping.update({HASH_FIELD_PREFIX + algo: target for algo, target in d["hashes"].items()})
        d["fields"] = mapping
        missing = [k for k in ("id", "logsource", "entry_type", "log_set") if not d.get(k)]
        if missing:
            raise ValueError(f"log source definition {d.get('id', '?')!r} is missing {', '.join(missing)}")
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise ValueError(f"log source {d['id']!r} has unknown keys: {', '.join(sorted(unknown))}")
        if not mapping:
            raise ValueError(f"log source {d['id']!r} maps no fields")
        return cls(**d)

    def logsource_conditions(self) -> List[LogsourceCondition]:
        return [
            LogsourceCondition(
                category=ls.get("category"), product=ls.get("product"), service=ls.get("service")
            )
            for ls in self.logsource
        ]


def load_sources(extra_files: Iterable[Union[str, Path]] = ()) -> List[LogSource]:
    """Load built-in log sources, then apply user files in order.

    A user entry with the same id replaces the built-in one; an entry with `disabled: true` removes it.
    """
    docs = [resources.files(__package__).joinpath("sources.yml").read_text(encoding="utf-8")]
    docs += [Path(f).read_text(encoding="utf-8") for f in extra_files]
    by_id: Dict[str, LogSource] = {}
    for doc in docs:
        for entry in (yaml.safe_load(doc) or {}).get("sources", []):
            if entry.get("disabled"):
                by_id.pop(entry["id"], None)
                continue
            src = LogSource.from_dict(entry)
            by_id[src.id] = src
    return list(by_id.values())


HASH_FIELD_PREFIX = "Hashes_"


@dataclass
class SplitHashesTransformation(DetectionItemTransformation):
    """Split Sysmon-style ``Hashes`` values ('SHA256=abc', '*IMPHASH=abc*') into one field per algorithm.

    Produces fields named ``Hashes_<ALGO>`` with exact hash values, OR-linked.
    """

    algorithms: List[str]

    def apply_detection_item(self, detection_item: SigmaDetectionItem):
        if any(m is SigmaAllModifier for m in detection_item.modifiers):
            raise SigmaTransformationError("Hashes|...|all is not supported")
        by_algo: Dict[str, List[str]] = {}
        for value in detection_item.value:
            if not isinstance(value, SigmaString):
                raise SigmaTransformationError(f"Unsupported Hashes value {value!r}")
            plain = value.to_plain().strip("*")
            algo, sep, digest = plain.partition("=")
            algo = algo.upper()
            if not sep or not digest or algo not in self.algorithms or not digest.isalnum():
                raise SigmaTransformationError(
                    f"Cannot map Hashes value '{plain}'; supported algorithms: {', '.join(self.algorithms)}"
                )
            by_algo.setdefault(algo, []).append(digest)
        items = [
            SigmaDetectionItem(HASH_FIELD_PREFIX + algo, [], [SigmaString(d) for d in digests])
            for algo, digests in by_algo.items()
        ]
        return SigmaDetection(items, item_linking=ConditionOR) if len(items) > 1 else items[0]


@dataclass
class UnmappedFieldCondition(FieldNameProcessingCondition):
    """Matches field names (including field references) that the log source does not map."""

    fields: List[str]

    def match_field_name(self, pipeline, field: Optional[str]) -> bool:
        return field is not None and field not in self.fields


@dataclass
class KeywordDetectionCondition(DetectionItemProcessingCondition):
    """Matches keyword (field-less, full-text) detection items."""

    def match(self, pipeline, detection_item) -> bool:
        return detection_item.field is None


def _source_items(src: LogSource) -> List[ProcessingItem]:
    logsource = src.logsource_conditions()

    def item(suffix: str, transformation, **kwargs) -> ProcessingItem:
        return ProcessingItem(
            identifier=f"insightidr_{src.id}_{suffix}",
            transformation=transformation,
            rule_conditions=logsource,
            rule_condition_linking=any,
            **kwargs,
        )

    items = []
    if src.hashes:
        items.append(
            item(
                "split_hashes",
                SplitHashesTransformation(list(src.hashes)),
                field_name_conditions=[IncludeFieldCondition(fields=["Hashes"])],
            )
        )
    items += [
        item(
            "fail_keywords",
            DetectionItemFailureTransformation(
                f"Keyword (full-text) detections are not supported for {src.log_set}; "
                "use field-based detections."
            ),
            detection_item_conditions=[KeywordDetectionCondition()],
        ),
        item(
            "fail_unmapped_fields",
            DetectionItemFailureTransformation(
                f"Rule uses a field with no InsightIDR mapping for {src.log_set} ({src.entry_type}). "
                f"Supported fields: {', '.join(sorted(src.fields))}"
            ),
            field_name_conditions=[UnmappedFieldCondition(fields=list(src.fields))],
        ),
    ]
    for sigma_field, mapping in src.values.items():
        items.append(
            item(
                f"values_{sigma_field}",
                MapStringTransformation(
                    {
                        variant: str(v)
                        for k, v in mapping.items()
                        for variant in (str(k), str(k).lower(), str(k).upper(), str(k).capitalize())
                    }
                ),
                field_name_conditions=[IncludeFieldCondition(fields=[sigma_field])],
            )
        )
    items.append(item("fieldmapping", FieldMappingTransformation(src.fields)))
    if src.conditions:
        items.append(item("conditions", AddConditionTransformation(dict(src.conditions))))
    items += [
        item("entry_type", SetCustomAttributeTransformation(ENTRY_TYPE_ATTR, src.entry_type)),
        item("log_set", SetCustomAttributeTransformation(LOG_SET_ATTR, src.log_set)),
        item("source_id", SetCustomAttributeTransformation(SOURCE_ID_ATTR, src.id)),
    ]
    return items


def insightidr_pipeline(extra_source_files: Iterable[Union[str, Path]] = ()) -> ProcessingPipeline:
    sources = load_sources(extra_source_files)
    items: List[ProcessingItem] = []
    for src in sources:
        items += _source_items(src)
    items.append(
        ProcessingItem(
            identifier="insightidr_fail_unsupported_logsource",
            transformation=RuleFailureTransformation(
                "Log source not supported. Supported: "
                + "; ".join(
                    ", ".join(
                        "/".join(v for v in (ls.get("product"), ls.get("category"), ls.get("service")) if v)
                        for ls in src.logsource
                    )
                    for src in sources
                )
                + ". Add a definition with --sources to support more."
            ),
            rule_conditions=[
                RuleProcessingItemAppliedCondition(f"insightidr_{src.id}_entry_type") for src in sources
            ],
            rule_condition_linking=any,
            rule_condition_negation=True,
        )
    )
    return ProcessingPipeline(
        name="Sigma to Rapid7 InsightIDR (LEQL)",
        priority=10,
        items=items,
    )
