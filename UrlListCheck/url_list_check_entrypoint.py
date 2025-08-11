#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
UrlListCheck entrypoint for Cortex.

- Reads analyzer input & config via cortexutils
- Downloads the list to a per-job path
- Runs your fast matcher
- Maps (hardmatch, softmatch) -> safe/suspicious/malicious
- Emits proper taxonomy + full JSON report

Config keys (set in Cortex UI / flavor configurationItems):
  config.url          (str)     REQUIRED - where to download the list
  config.verify_tls   (bool)    optional  - default True
  config.ca_cert      (str)     optional  - path to CA bundle inside container
  config.timeout      (number)  optional  - seconds, default 60
"""

import os
import sys
import json
import tempfile
from typing import Optional, Dict

from cortexutils.analyzer import Analyzer

# --- Load your two scripts even if their filenames contain hyphens ---
#    We load them by absolute path relative to this file.
import importlib.util


def _load_symbol(module_filename: str, symbol_name: str):
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, module_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Required module not found: {path}")
    mod_name = os.path.splitext(os.path.basename(module_filename))[0].replace("-", "_")
    spec = importlib.util.spec_from_file_location(mod_name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    try:
        return getattr(mod, symbol_name)
    except AttributeError as e:
        raise AttributeError(f"{module_filename} does not export {symbol_name}()") from e


# Import the functions as provided by you:
download_file = _load_symbol("downloader-v2.py", "download_file")
check_membership = _load_symbol("fast_matcher-v4.py", "check_membership")

VALID_LEVELS = {"safe", "suspicious", "malicious", "info"}


class UrlListCheckAnalyzer(Analyzer):
    def __init__(self):
        super().__init__()

        # Read user-configurable params from Cortex (Analyzer input -> config.*).
        # These names must exist in your flavor's configurationItems.
        self.list_url: str = self.get_param(
            "config.url", None, "Missing required configuration: url"
        )
        self.verify_tls: bool = self.get_param("config.verify_tls", True)
        self.ca_cert: Optional[str] = self.get_param("config.ca_cert", None)
        self.timeout: int = int(self.get_param("config.timeout", 60))

        # Decide where to store the list for THIS job.
        # Prefer the job dir passed by Cortex (argv[1]); fall back to /tmp if absent.
        self.job_dir = None
        if len(sys.argv) > 1 and os.path.isdir(sys.argv[1]):
            self.job_dir = os.path.abspath(sys.argv[1])
        else:
            self.job_dir = tempfile.mkdtemp(prefix="cortex-job-")

        self.work_dir = os.path.join(self.job_dir, "work")
        os.makedirs(self.work_dir, exist_ok=True)

        self.list_path = os.path.join(self.work_dir, "indicator-list.txt")

    # Controls the colored chip in TheHive.
    def summary(self, raw: Optional[Dict]) -> Dict:
        lvl = (raw or {}).get("classification", "info")
        if lvl not in VALID_LEVELS:
            lvl = "info"
        # namespace/predicate/value are free text; keep them clean & short
        return {
            "taxonomies": [
                self.build_taxonomy(lvl, "UrlListCheck", "Status", lvl)
            ]
        }

    def _classify_from_matches(self, hard: bool, soft: bool) -> str:
        if hard:
            return "malicious"
        if soft:
            return "suspicious"
        return "safe"

    def run(self):
        # Ingest input.json (observable, datatype, tlp, etc.)
        super().run()

        value = self.get_param("data", None, "No observable provided")
        dtype = self.get_param("dataType", "unknown")  # e.g., 'url' | 'domain' | 'fqdn'
        value_type = "url" if dtype == "url" else "domain"  # map 'fqdn' -> 'domain'

        # 1) Download (or refresh) the list to the per-job path
        try:
            ok = download_file(
                url=self.list_url,
                dest_path=self.list_path,
                verify_tls=self.verify_tls,
                ca_cert=self.ca_cert,
                timeout=self.timeout,
                # reasonable defaults for the remaining optional params:
                max_bytes=None,
                user_agent=None,   # let your downloader decide its default UA
                file_mode=0o644,
            )
            if not ok or not os.path.exists(self.list_path):
                self.error("Download failed or produced no file")
        except Exception as e:
            self.error(f"Download error: {e}")

        # 2) Match the observable against the downloaded list
        try:
            result: Dict[str, bool] = check_membership(
                list_path=self.list_path, value=value, value_type=value_type
            )
            hard = bool(result.get("hardmatch", False))
            soft = bool(result.get("softmatch", False))
            classification = self._classify_from_matches(hard, soft)

            # 3) Report back to Cortex/TheHive
            self.report(
                {
                    "observable": value,
                    "type": dtype,
                    "value_type_used": value_type,
                    "download": {
                        "url": self.list_url,
                        "path": self.list_path,
                        "verify_tls": self.verify_tls,
                        "timeout": self.timeout,
                        "ca_cert": self.ca_cert,
                    },
                    "matches": {
                        "hardmatch": hard,
                        "softmatch": soft,
                    },
                    "classification": classification,
                }
            )
        except Exception as e:
            self.error(f"Matching error: {e}")


if __name__ == "__main__":
    UrlListCheckAnalyzer().run()
