import textwrap

import pytest
from sigma.collection import SigmaCollection

from sigma2leql import LEQLBackend


@pytest.fixture
def backend():
    return LEQLBackend()


def rule(detection: str, logsource: str = "{product: windows, category: process_creation}") -> SigmaCollection:
    """Build a one-rule collection from an indented detection block."""
    body = textwrap.indent(textwrap.dedent(detection).strip(), "    ")
    return SigmaCollection.from_yaml(f"title: Test\nlogsource: {logsource}\ndetection:\n{body}\n")


@pytest.fixture
def convert(backend):
    def _convert(detection: str, logsource: str = "{product: windows, category: process_creation}", fmt="default"):
        return backend.convert(rule(detection, logsource), fmt)[0]

    return _convert
