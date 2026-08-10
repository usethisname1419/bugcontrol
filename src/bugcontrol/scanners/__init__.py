"""Local scanner job runner."""

from bugcontrol.scanners.js_crawl import crawl_and_scan_secrets
from bugcontrol.scanners.runner import JobRunner, filter_scannable_targets

__all__ = ["JobRunner", "filter_scannable_targets", "crawl_and_scan_secrets"]
