"""Convert Sigma rules to Rapid7 InsightIDR LEQL queries."""

from .backend import LEQLBackend
from .pipeline import insightidr_pipeline, load_sources

__all__ = ["LEQLBackend", "insightidr_pipeline", "load_sources"]
__version__ = "0.1.0"
