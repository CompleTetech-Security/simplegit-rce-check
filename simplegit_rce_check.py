#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline package-version evidence triage for CVE-2026-102826: simple-git configuration include command injection.
No network, package-manager invocation, application imports, or exploit payloads.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

TOOL_NAME = "simplegit-rce-check"
TOOL_VERSION = "1.1.0"
REPORT_SCHEMA_VERSION = "1.1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 10000
MAX_FIELD = 512
MAX_FILES = 100  # combined --inventory and --csv-list files per run

# =============================================================================
# BEGIN ADVISORY DATA  (the ONLY block that differs between simple-git siblings)
# =============================================================================
CVE_ID = 'CVE-2026-102826'
ADVISORY_TITLE = 'simple-git configuration include command injection'
RULES_DATE = '2026-10-24'
FIXES = {'4': (4, 0, 0)}
SOURCES = ('https://github.com/steveukx/git-js/security/advisories/GHSA-g4wm-2vf7-vfgr', 'https://github.com/advisories/GHSA-g4wm-2vf7-vfgr')
PRECONDITIONS = (('attacker_influence_over_clone_mirror_customargs', 'attacker influence over clone/mirror customArgs'), ('attacker_controlled_readable_git_configuration_file', 'attacker-controlled readable Git configuration file'), ('remote_operation_loads_unsafe_configuration', 'remote operation loads unsafe configuration'))
ADVISORY_NOTES = ('Do not invent affected status for hypothetical versions between 3.36.0 and 4.0.0. File-pattern findings show review targets, not proven input taint. include.path and includeIf variants share this advisory.',)
RECOMMENDATION = 'Verify the deployed simple-git instance and upgrade to 4.0.0 or a reviewed fixed release; review advisory conditions without executing untrusted code.'
AFFECTED_MIN = (0, 0, 0)
AFFECTED_MAX = (3, 36, 0)
FIXED = (4, 0, 0)
FIXED_LINE = (4,)
DISPUTED = ()
# =============================================================================
# END ADVISORY DATA
# =============================================================================

# =============================================================================
# BEGIN REUSABLE PACKAGE VERSION ENGINE  (identical across simple-git siblings)
# Uses only the constants above: FIXES, RECOMMENDATION.
# =============================================================================
OFFICIAL_BUILD_SOURCES = frozenset({"", "unknown", "upstream", "official", "official_upstream"})
ASCII_SPACE = " \t\r\n"
VERSION_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


UNKNOWN_RECOMMENDATION = (
    "Collect or verify the exact upstream simple-git version and build provenance of the running process, then run this checker again."
)


def _fmt(version):
    return ".".join(str(part) for part in version)


def assess_version(package_version="", *, version_candidates=None, build_source="unknown"):
    """Compare reported upstream simple-git version evidence with the fixed releases.

    Returns status (potentially_affected | fixed_version_reported
    | unknown) plus a more specific version_status. Anything missing, malformed,
    qualified, conflicting, vendor-built or uncovered stays unknown.
    """
    result = {"status": "unknown", "version_status": "version_not_disclosed", "fixed_version": "",
              "notes": [], "recommendation": UNKNOWN_RECOMMENDATION}
    notes = result["notes"]
    if version_candidates is None:
        candidates = []
    elif isinstance(version_candidates, (list, tuple, set, frozenset)):
        candidates = list(version_candidates)
    elif isinstance(version_candidates, str):
        candidates = [version_candidates]
    else:
        result["version_status"] = "unrecognized_or_partial_version"
        notes.append("Version candidates must be strings in a collection; they cannot be compared.")
        return result
    if len(candidates) > 128:
        result["version_status"] = "conflicting_versions"
        notes.append("Too many version candidates were supplied for one runtime.")
        return result
    values = [package_version, *candidates]
    if any(value is not None and not isinstance(value, str) for value in values):
        result["version_status"] = "unrecognized_or_partial_version"
        notes.append("Non-text version metadata cannot be compared safely.")
        return result
    # One normalization: strip ASCII whitespace only, then at most one leading "v".
    versions = sorted({value.strip(ASCII_SPACE).removeprefix("v") for value in values if value and value.strip(ASCII_SPACE)})
    if not versions:
        notes.append("No simple-git version was reported. Missing metadata does not establish that the runtime is unaffected.")
        return result
    if len(versions) != 1:
        result["version_status"] = "conflicting_versions"
        notes.append("Conflicting reported versions: " + ", ".join(value[:128] for value in versions))
        return result

    version = versions[0]
    match = None if len(version) > 128 else VERSION_PATTERN.fullmatch(version)
    if not match:
        qualified = re.match(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(.+)", version[:128])
        result["version_status"] = "qualified_version_unverified" if qualified else "unrecognized_or_partial_version"
        notes.append(
            f"Version {version[:128]!r} is not a plain stable release. Prereleases, nightly/rc builds, package suffixes "
            "and custom builds need vendor verification."
        )
        return result

    parsed = tuple(int(part) for part in match.groups())
    source = ("".join(c.lower() if c.isascii() else c for c in build_source.strip(ASCII_SPACE))
              if isinstance(build_source, str) else "invalid")
    if source not in OFFICIAL_BUILD_SOURCES:
        result["version_status"] = "vendor_build_unverified"
        notes.append("Custom, vendor, or otherwise unrecognized package provenance needs independent patch evidence.")
        return result
    if parsed in DISPUTED:
        result["version_status"] = "source_discrepancy"
        notes.append("Primary advisory and reviewed database disagree at this boundary; obtain maintainer evidence.")
        return result
    if AFFECTED_MIN <= parsed <= AFFECTED_MAX:
        result.update(status="potentially_affected", version_status="in_documented_affected_range",
                      fixed_version=_fmt(FIXED), recommendation=RECOMMENDATION)
        notes.append("Reported version matches the documented affected range; application preconditions and exploitability were not established.")
    elif parsed >= FIXED and parsed[:len(FIXED_LINE)] == FIXED_LINE:
        result.update(status="fixed_version_reported", version_status="at_or_above_fixed_version",
                      fixed_version=_fmt(FIXED), recommendation="Verify this package instance is actually deployed and contains the upstream fix.")
        notes.append("Reported version meets the fix within this reviewed release line; this is not installed-patch attestation.")
    else:
        result["version_status"] = "outside_reviewed_range"
        notes.append("Version is outside the documented affected range and reviewed fixed line. No safety or other-vulnerability conclusion is made.")
    return result
# =============================================================================
# END REUSABLE PACKAGE VERSION ENGINE
# =============================================================================

PRECONDITION_KEYS = tuple(key for key, _ in PRECONDITIONS)
OBSERVATIONS = {True: "reported_true", False: "reported_false", None: "not_reported"}
INVENTORY_FIELDS = {"schema_version", "package", "label", "package_version", "build_source", *PRECONDITION_KEYS}
SOURCE_COLUMNS = ["source_path", "source_line", "source_operation", "source_argument_shapes", "source_factory_options", "source_config_argument", "source_coverage"]
CSV_COLUMNS = ["record_type", "input_label", "input_source", "package_version", "build_source", "status", "version_status", "fixed_version",
               "exploitability", "evidence_type", "evidence_confidence", "cve", "rules_as_of", *[f"precondition_{key}" for key in PRECONDITION_KEYS],
               "recommendation", "notes", "sources", "report_schema_version", "report_complete"]
CSV_COLUMNS += SOURCE_COLUMNS + ["version_candidates"]
STATUS_ORDER = {"potentially_affected": 0, "unknown": 2, "fixed_version_reported": 3}
STATUS_LABELS = {"potentially_affected": "Potentially affected", "unknown": "Unknown", "fixed_version_reported": "Fixed version reported"}


def assess_entry(label, input_source, package_version, build_source="unknown", observations=None):
    """Build one report row. version_status, preconditions and exploitability stay separate."""
    verdict = assess_version(package_version, build_source=build_source)
    observations = observations or {}
    notes = list(verdict["notes"]) + list(ADVISORY_NOTES)
    row = {
        "input_label": label, "input_source": input_source,
        "package_version": package_version if isinstance(package_version, str) else "",
        "build_source": build_source if isinstance(build_source, str) else "",
        "status": verdict["status"], "version_status": verdict["version_status"],
        "fixed_version": verdict["fixed_version"], "exploitability": "not_tested",
        "evidence_type": "operator_reported_version",
        "evidence_confidence": "insufficient" if verdict["status"] == "unknown" else "low",
        "cve": CVE_ID, "rules_as_of": RULES_DATE,
    }
    for key in PRECONDITION_KEYS:
        row[f"precondition_{key}"] = OBSERVATIONS[observations.get(key)]
    if any(observations.get(key) is not None for key in PRECONDITION_KEYS):
        notes.append("Precondition observations are operator-supplied and unverified; they do not change the version status.")
    row.update({"recommendation": verdict["recommendation"], "notes": notes, "sources": list(SOURCES),
                "report_schema_version": REPORT_SCHEMA_VERSION})
    return row


def _tri_state(value, name, *, text=False):
    """JSON inventories take booleans or null only; CSV cells and CLI flags take the
    exact lowercase text true or false, and CSV cells may also be empty."""
    if value is None or (text and value == ""):
        return None
    if type(value) is bool and not text:
        return value
    if text and value in ("true", "false"):
        return value == "true"
    raise ValueError(f"{name} must be " + ("true, false or empty" if text else "true, false or null"))


def entry_from_record(record, fallback_label, input_source, *, require_schema=True, text=False):
    if not isinstance(record, dict) or set(record) - INVENTORY_FIELDS:
        raise ValueError("Each entry must be an object containing only documented fields")
    if require_schema and (type(record.get("schema_version")) is not int or record["schema_version"] != 1):
        raise ValueError("Inventory schema_version must be 1")
    if record.get("package", 'simple-git') != 'simple-git':
        raise ValueError("This checker assesses simple-git; other packages need their own assessment")
    for key in ("label", "package_version", "build_source"):
        if key in record and (not isinstance(record[key], str) or len(record[key]) > MAX_FIELD):
            raise ValueError(f"{key} must be a string of at most {MAX_FIELD} characters")
    if "package_version" not in record:
        raise ValueError("Entry is missing package_version")
    observations = {key: _tri_state(record.get(key), key, text=text) for key in PRECONDITION_KEYS}
    return assess_entry(record.get("label") or fallback_label, input_source, record["package_version"],
                        record.get("build_source") or "unknown", observations)


def _require_regular_file(path, what="Input"):
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise ValueError(f"{what} must be a regular file")


def _bounded_text(value, name):
    if not isinstance(value, str) or len(value) > MAX_FIELD:
        raise ValueError(f"{name} must be a string of at most {MAX_FIELD} characters")
    return value


def _read_bounded(path):
    _require_regular_file(path)
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Input file exceeds the 4 MiB limit")
    return raw.decode("utf-8-sig")


# Bounded lexer bundled from vm2-nesting-check 1618874; same CompleteTech licensing.
def _js_tokens(text):
    """Bounded lexical hints, not a JavaScript parser. Never retain source strings."""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\u2028", "\n").replace("\u2029", "\n")
    tokens = []
    index, line = 0, 1
    while index < len(text):
        start = index
        char = text[index]
        if char.isspace():
            line += char == "\n"
            index += 1
            continue
        if text.startswith("//", index):
            end = text.find("\n", index)
            index = len(text) if end < 0 else end
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("Unterminated JavaScript comment")
            line += text.count("\n", index, end + 2)
            index = end + 2
            continue
        token_line = line
        if char in "\"'`":
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                elif text[index] == char:
                    index += 1
                    break
                else:
                    index += 1
            else:
                raise ValueError("Unterminated JavaScript string or template")
            raw = text[start + 1:index - 1]
            value = "@template" if char == "`" else "@" + raw if raw in {"simple-git", "config", "customArgs"} else "@string"
            line += text.count("\n", start, index)
        elif char == "/" and (not tokens or tokens[-1][0] in {"=", "(", "[", "{", ":", ",", ";", "return", "=>"}):
            # Regex bodies are opaque. Templates (including interpolations) are
            # also opaque; the report always states incomplete lexical coverage.
            index += 1
            in_class = False
            while index < len(text):
                c = text[index]
                if c == "\\":
                    index += 2
                    continue
                if c == "[":
                    in_class = True
                elif c == "]":
                    in_class = False
                elif c == "/" and not in_class:
                    index += 1
                    break
                elif c == "\n":
                    raise ValueError("Unterminated JavaScript regex candidate")
                index += 1
            else:
                raise ValueError("Unterminated JavaScript regex candidate")
            value = "@regex"
        elif char.isascii() and (char.isalpha() or char in "_$"):
            index += 1
            while index < len(text) and text[index].isascii() and (text[index].isalnum() or text[index] in "_$"):
                index += 1
            value = text[start:index]
        elif text.startswith("...", index):
            value, index = "...", index + 3
        else:
            value, index = char, index + 1
        tokens.append((value, token_line))
        if len(tokens) > 200000:
            raise ValueError("Source exceeds the 200,000 token limit")
    return tokens




def _token_pairs(values):
    stack, pairs = [], {}
    for index, value in enumerate(values):
        if value in {"{", "[", "("}:
            stack.append(index)
        elif value in {"}", "]", ")"}:
            if not stack or values[stack[-1]] != {"}": "{", "]": "[", ")": "("}[value]:
                raise ValueError("Unbalanced JavaScript delimiters")
            opening = stack.pop()
            pairs[opening] = index
    if stack:
        raise ValueError("Unbalanced JavaScript delimiters")
    return pairs


def _segments(values, start, end, pairs):
    """Top-level argument/property slices with a bounded inspection window."""
    if end - start > 4096:
        return None
    parts, index, first = [], start, start
    while index < end:
        if values[index] in {"(", "[", "{"} and index in pairs:
            index = pairs[index] + 1
            continue
        if values[index] == ",":
            parts.append((first, index))
            first = index + 1
        index += 1
    if first < end:
        parts.append((first, end))
    return parts


def _argument_shape(values, start, end, pairs):
    if start >= end:
        return "missing"
    if end == start + 1 and values[start] in {"@string", "@simple-git", "@config", "@customArgs"}:
        return "literal_string"
    if values[start] in {"[", "{"} and pairs.get(start) == end - 1:
        if "..." in values[start:end]:
            return "dynamic_or_unsupported"
        return "array_literal" if values[start] == "[" else "object_literal"
    return "dynamic_or_unsupported"


def _simplegit_factories(values):
    factories, namespaces = set(), set()
    ident = r"[A-Za-z_$][A-Za-z0-9_$]*"
    for index, value in enumerate(values):
        if value not in {"const", "let", "var", "import"}:
            continue
        end = index + 1
        while end < min(len(values), index + 100) and values[end] != ";":
            end += 1
        statement = " ".join(values[index:end])
        if value == "import":
            m = re.match(r"import (" + ident + r") from @simple-git(?: |$)", statement)
            if m:
                factories.add(m[1])
            m = re.match(r"import \* as (" + ident + r") from @simple-git(?: |$)", statement)
            if m:
                namespaces.add(m[1])
            m = re.match(r"import \{ (.*?) \} from @simple-git(?: |$)", statement)
            if m:
                for member in re.split(r"\s*,\s*", m[1]):
                    member = re.fullmatch(r"simpleGit(?: as (" + ident + r"))?", member)
                    if member:
                        factories.add(member[1] or "simpleGit")
        else:
            m = re.match(r"(?:const|let|var) (" + ident + r") = require \( @simple-git \)(.*)", statement)
            if m and (not m[2].startswith(" .") or re.match(r" \. simpleGit(?: |$)", m[2])):
                factories.add(m[1])
            m = re.match(r"(?:const|let|var) \{ (.*?) \} = require \( @simple-git \)", statement)
            if m:
                for member in re.split(r"\s*,\s*", m[1]):
                    member = re.fullmatch(r"simpleGit(?: : (" + ident + r"))?", member)
                    if member:
                        factories.add(member[1] or "simpleGit")
    return factories, namespaces


def _factory_shapes(values, opening, pairs):
    closing = pairs[opening]
    args = _segments(values, opening + 1, closing, pairs)
    if args is None:
        return "dynamic_or_unsupported", "unknown"
    if not args:
        return "no_arguments", "not_observed"
    start, end = args[0]
    shape = _argument_shape(values, start, end, pairs)
    if shape != "object_literal":
        return shape, "unknown"
    props = _segments(values, start + 1, end - 1, pairs)
    keys, config = set(), "not_observed"
    for first, last in props or []:
        if last - first < 3 or values[first + 1] != ":":
            return shape, "unknown"
        key = values[first].removeprefix("@")
        if key in keys:
            return shape, "unknown"
        keys.add(key)
        if key == "config":
            config = _argument_shape(values, first + 2, last, pairs)
    return shape, config


def scan_source_text(text, relative_path):
    tokens = _js_tokens(text)
    values = [token[0] for token in tokens]
    pairs = _token_pairs(values)
    factories, namespaces = _simplegit_factories(values)
    clients, direct = {}, {}
    for index, value in enumerate(values[:-1]):
        opening = None
        if value in factories and values[index + 1] == "(":
            opening = index + 1
        elif (index + 3 < len(values) and value in namespaces
              and values[index + 1:index + 4] == [".", "simpleGit", "("]):
            opening = index + 3
        elif index + 4 < len(values) and values[index:index + 5] == ["require", "(", "@simple-git", ")", "("]:
            opening = index + 4
        if opening is None or opening not in pairs:
            continue
        shape = _factory_shapes(values, opening, pairs)
        direct[pairs[opening]] = shape
        if index >= 2 and values[index - 1] == "=":
            clients[values[index - 2]] = shape
    rows = []
    for index in range(len(values) - 3):
        if values[index + 1] != "." or values[index + 2] not in {"clone", "mirror"} or values[index + 3] != "(":
            continue
        shape = direct.get(index) if values[index] == ")" else clients.get(values[index])
        if shape is None:
            continue
        args = _segments(values, index + 4, pairs[index + 3], pairs)
        shapes = "unknown" if args is None else ",".join(_argument_shape(values, a, b, pairs) for a, b in args) or "no_arguments"
        row = assess_entry(relative_path, "source", "")
        row.update(evidence_type="lexical_source_candidate", source_path=relative_path,
                   source_line=tokens[index + 2][1], source_operation=values[index + 2],
                   source_argument_shapes=shapes, source_factory_options=shape[0],
                   source_config_argument=shape[1], source_coverage="limited_lexical")
        row["notes"].append(
            f"Source candidate {relative_path}:{tokens[index + 2][1]}: {values[index + 2]}; arguments={shapes}; "
            f"factory_options={shape[0]}; config={shape[1]}. Constants, variables and object/array shapes do not prove trust or taint. "
            "Shadowing, reassignment, execution order, templates, callbacks and unsupported syntax need manual review; no match is not absence.")
        rows.append(row)
        if len(rows) > MAX_ENTRIES:
            raise ValueError("Too many source candidates")
    if not rows:
        row = assess_entry(relative_path, "source", "")
        row.update(evidence_type="source_coverage", source_path=relative_path, source_line="",
                   source_operation="not_observed", source_argument_shapes="unknown",
                   source_factory_options="unknown", source_config_argument="unknown", source_coverage="limited_lexical")
        row["notes"].append("No supported import-associated clone/mirror candidate found; package presence and input trust remain unknown.")
        rows.append(row)
    return rows


def load_source(path, root, budget, out):
    budget.add_file()
    relative = Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    _bounded_text(relative, "Source relative path")
    rows = scan_source_text(_read_bounded(path), relative)
    budget.add_entries(len(rows))
    out.extend(rows)


def _metadata_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate metadata key")
            result[key] = value
        return result
    def reject(_):
        raise ValueError("Non-finite metadata number")
    result = json.loads(_read_bounded(path), object_pairs_hook=unique, parse_constant=reject)
    if not isinstance(result, dict):
        raise ValueError("Package metadata must be a JSON object")
    return result


def load_installed_package(path, budget, out):
    budget.add_file()
    data = _metadata_json(path)
    if data.get("name") != "simple-git":
        raise ValueError("Installed manifest must identify simple-git")
    version = _bounded_text(data.get("version", ""), "Package version")
    budget.add_entries(1)
    row = assess_entry("simple-git installed manifest", "installed_manifest", version)
    row["evidence_type"] = "installed_manifest_version"
    row["notes"].append("Explicitly selected installed package manifest; not evidence that a deployed process loads it. Scripts and URLs are not collected or executed.")
    out.append(row)


def _legacy_instances(dependencies):
    pending = [(dependencies, "", 0)]
    result, count = {}, 0
    while pending:
        entries, prefix, depth = pending.pop()
        if not isinstance(entries, dict) or depth > 64:
            raise ValueError("Unsupported dependency tree or depth")
        for name, item in entries.items():
            count += 1
            if count > MAX_ENTRIES or not isinstance(item, dict):
                raise ValueError("Invalid or excessive dependency metadata")
            location = prefix + "node_modules/" + name
            _bounded_text(location, "Dependency location")
            if location.startswith("/") or "\\" in location or ":" in location or any(p in {".", ".."} for p in location.split("/")):
                raise ValueError("Dependency location must be a relative npm path")
            if name == "simple-git" or item.get("name") == "simple-git" or str(item.get("version", "")).startswith("npm:simple-git@"):
                result[location] = item
            if "dependencies" in item:
                pending.append((item["dependencies"], location + "/", depth + 1))
    return result


def load_npm_lock(path, budget, out):
    budget.add_file()
    data = _metadata_json(path)
    lock_version = data.get("lockfileVersion")
    if type(lock_version) is not int or lock_version not in {1, 2, 3}:
        raise ValueError("Only npm lockfile versions 1, 2 and 3 are supported")
    legacy = _legacy_instances(data.get("dependencies", {}))
    if lock_version == 1 and "packages" in data:
        raise ValueError("Conflicting lockfile version and package metadata")
    instances = legacy
    conflict = False
    if lock_version in {2, 3}:
        packages = data.get("packages")
        if not isinstance(packages, dict) or len(packages) > MAX_ENTRIES:
            raise ValueError("Lockfile packages must be a bounded object")
        instances = {}
        for location, item in packages.items():
            if not isinstance(item, dict) or len(location) > MAX_FIELD:
                raise ValueError("Invalid package metadata")
            if location.startswith("/") or "\\" in location or ":" in location or any(p in {".", ".."} for p in location.split("/")):
                raise ValueError("Package location must be a relative npm path")
            if "link" in item and type(item["link"]) is not bool:
                raise ValueError("Package link flag must be boolean")
            if location == "node_modules/simple-git" or location.endswith("/node_modules/simple-git") or item.get("name") == "simple-git":
                instances[location] = item
        if legacy:
            conflict = {k: v.get("version") for k, v in instances.items()} != {k: v.get("version") for k, v in legacy.items()}
            if conflict:
                instances = {**legacy, **instances}
    rows = []
    for location, item in sorted(instances.items()):
        if "name" in item and item["name"] != "simple-git":
            raise ValueError("Conflicting simple-git package identity")
        if "link" in item and type(item["link"]) is not bool:
            raise ValueError("Package link flag must be boolean")
        version = _bounded_text(item.get("version", ""), "Dependency version")
        row = assess_entry(location, "npm_lockfile", "" if item.get("link") or conflict else version)
        row["evidence_type"] = "npm_lockfile_resolved_version"
        if item.get("link") or conflict:
            row["notes"].append("Linked or conflicting lockfile metadata cannot establish a package version; inspect the installed manifest.")
        row["version_candidates"] = sorted({version, _bounded_text(legacy.get(location, {}).get("version", ""), "Legacy dependency version")} - {""})
        if row["version_candidates"]:
            row["notes"].append("Reported version candidates: " + ", ".join(row["version_candidates"]))
        row["notes"].append("Lockfile-resolved instance, not deployed runtime attestation. Registry URLs, scripts and package data are not collected.")
        rows.append(row)
    if not rows:
        row = assess_entry("npm lockfile coverage", "npm_lockfile", "")
        row["notes"].append("No determinable simple-git instance found in supported lock metadata; package absence is not established.")
        rows.append(row)
    budget.add_entries(len(rows))
    out.extend(rows)


class Budget:
    """Counts entries and files while loading, so limits hold before rows pile up."""

    def __init__(self):
        self.entries = 0
        self.files = 0

    def add_file(self):
        self.files += 1
        if self.files > MAX_FILES:
            raise ValueError(f"A run is limited to {MAX_FILES} input files")

    def add_entries(self, count):
        self.entries += count
        if self.entries > MAX_ENTRIES:
            raise ValueError(f"A run is limited to {MAX_ENTRIES:,} inputs")


def load_inventory(path, budget=None, out=None):
    """Return entry rows; rows are also appended to ``out`` as soon as each is assessed."""
    budget = budget or Budget()
    out = [] if out is None else out
    budget.add_file()
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate inventory key")
            value[key] = item
        return value

    def reject_constant(_):
        raise ValueError("Non-finite JSON number")

    data = json.loads(_read_bounded(path), object_pairs_hook=unique_object, parse_constant=reject_constant)
    records = data if isinstance(data, list) else [data]
    if not records or len(records) > MAX_ENTRIES:
        raise ValueError(f"Inventory must contain between 1 and {MAX_ENTRIES:,} entries")
    budget.add_entries(len(records))
    for index, record in enumerate(records):
        out.append(entry_from_record(record, f"{Path(path).stem}:{index + 1}", "inventory"))
    return out


def _reject_bare_quotes(text):
    """csv.reader accepts a quote inside an unquoted cell; this checker does not."""
    state = "start"  # start of cell | unquoted | quoted | after a closing quote
    index, size = 0, len(text)
    while index < size:
        char = text[index]
        if state == "start":
            state = "quoted" if char == '"' else ("start" if char in ",\r\n" else "unquoted")
        elif state == "unquoted":
            if char == '"':
                raise ValueError("CSV list has a quote inside an unquoted cell")
            if char in ",\r\n":
                state = "start"
        elif state == "quoted":
            if char == '"':
                state = "after"
        else:  # after a closing quote: an escaped quote, or the end of the cell
            if char == '"':
                state = "quoted"
            elif char in ",\r\n":
                state = "start"
            else:
                raise ValueError("CSV list has text after a closing quote")
        index += 1
    if state in ("quoted",):
        raise ValueError("CSV list has an unterminated quote")


def load_csv_list(path, budget=None, out=None):
    budget = budget or Budget()
    out = [] if out is None else out
    budget.add_file()
    csv.field_size_limit(MAX_FIELD * 4)
    text = _read_bounded(path)
    if "\x00" in text:
        raise ValueError("CSV list contains a NUL character")
    _reject_bare_quotes(text)
    reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
    if not reader.fieldnames or "package_version" not in reader.fieldnames:
        raise ValueError("CSV list needs a header row with a package_version column")
    if len(set(reader.fieldnames)) != len(reader.fieldnames):
        raise ValueError("CSV list header has duplicate columns")
    if set(reader.fieldnames) - (INVENTORY_FIELDS - {"schema_version", "package"}):
        raise ValueError("CSV list contains undocumented columns")
    count = 0
    for index, record in enumerate(reader):
        if None in record or None in record.values():
            raise ValueError(f"CSV row {index + 2} has a different number of fields than the header")
        budget.add_entries(1)
        out.append(entry_from_record(record, f"{Path(path).stem}:{index + 1}", "csv", require_schema=False, text=True))
        count += 1
    if not count:
        raise ValueError("CSV list contains no rows")
    return out


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(value)
    if isinstance(value, str) and "\x00" in value:
        raise ValueError("CSV values cannot contain NUL characters")
    if isinstance(value, str) and (value[:1] in ("\t", "\r", "\n") or value.lstrip().startswith(("=", "+", "-", "@"))):
        return "'" + value
    return value


REPORT_CSS = """
:root{--bg:#F8FAFC;--surface:#FFFFFF;--surface-2:#EEF2FF;--ink:#0F172A;--ink-2:#1E293B;--ink-3:#64748B;--line:#E2E8F0;
--accent:#1E3A8A;--accent-text:#1E3A8A;--on-accent:#FFFFFF;--bad:#B42318;--bad-bg:#FEE4E2;--ok:#067647;--ok-bg:#DCFAE6;--unk:#475467;--unk-bg:#EAECF0}
@media (prefers-color-scheme:dark){:root{--bg:#0F172A;--surface:#1E293B;--surface-2:#273449;--ink:#F1F5F9;--ink-2:#CBD5E1;--ink-3:#94A3B8;
--line:#334155;--accent-text:#93C5FD;--bad:#FDA29B;--bad-bg:#55160C;--ok:#75E0A7;--ok-bg:#053321;--unk:#D0D5DD;--unk-bg:#344054}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,system-ui,sans-serif}
main{max-width:1240px;margin:0 auto;padding:24px 16px 48px}
header{padding:20px 0;border-bottom:3px solid var(--accent);margin-bottom:20px}
.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent-text);text-transform:uppercase}
h1{margin:2px 0;font-size:26px}.sub{color:var(--ink-3);margin:0}h2{margin:32px 0 10px;font-size:18px;color:var(--ink-2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;color:var(--accent-text)}.tile span{color:var(--ink-3);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line)}
table.narrow{max-width:360px}
th{background:var(--accent);color:var(--on-accent);text-align:left;padding:8px 10px;font-size:13px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}tr:nth-child(even) td{background:var(--surface-2)}
td.site{overflow-wrap:anywhere;min-width:160px}td.notes{color:var(--ink-3);font-size:13px;min-width:240px}
code{font:13px Consolas,monospace}ul.obs{list-style:none;margin:0;padding:0;font-size:12px;overflow-wrap:anywhere}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.potentially_affected{color:var(--bad);background:var(--bad-bg)}.pill.fixed_version_reported{color:var(--ok);background:var(--ok-bg)}
.pill.unknown{color:var(--unk);background:var(--unk-bg)}
.callout{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;color:var(--ink-2)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px}
a{color:var(--accent-text)}details{max-width:430px}summary{cursor:pointer;color:var(--accent-text)}details ul{padding-left:18px}
@media print{body{background:#fff}tr,.tile{break-inside:avoid}details>summary{display:none}}
"""


def render_html(rows, *, brand="CompleteTech LLC", generated_at=None, complete=True):
    def esc(value):
        return html.escape("" if value is None else str(value), quote=True)

    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = sorted(rows, key=lambda row: STATUS_ORDER.get(row.get("status"), 2))
    counts = {key: sum(row.get("status") == key for row in rows) for key in STATUS_ORDER}
    tiles = [("", len(rows), "Inputs assessed"), ("bad", counts["potentially_affected"], "Potentially affected"),
             ("", counts["unknown"], "Unknown"),
             ("ok", counts["fixed_version_reported"], "Fixed version reported")]
    body = []
    for row in rows:
        status = row.get("status") if row.get("status") in STATUS_ORDER else "unknown"
        observed = "".join(
            f"<li title='{esc(description)}'><code>{esc(key)}</code>: {esc(row.get('precondition_' + key))}</li>" for key, description in PRECONDITIONS)
        notes = "".join(f"<li>{esc(note)}</li>" for note in dict.fromkeys(row.get("notes", [])))
        body.append(
            "<tr>"
            f"<td class='site'>{esc(row.get('input_label'))}<br><small>{esc(row.get('input_source'))}</small></td>"
            f"<td><span class='pill {status}'>{STATUS_LABELS[status]}</span><br><small><code>{esc(row.get('version_status'))}</code></small></td>"
            f"<td><code>{esc(row.get('package_version') or chr(8212))}</code><br><small>build: {esc(row.get('build_source') or chr(8212))}</small></td>"
            f"<td><code>{esc(row.get('fixed_version') or chr(8212))}</code></td>"
            f"<td><ul class='obs'>{observed}</ul></td>"
            f"<td class='notes'><p>{esc(row.get('recommendation'))}</p>"
            f"<details><summary>Evidence and limitations</summary><ul>{notes}</ul></details></td></tr>")
    fixes = "".join(f"<tr><td>{major}.x</td><td><code>{_fmt(version)}</code></td></tr>" for major, version in FIXES.items())
    tile_html = "".join(f"<div class='tile {cls}'><b>{value}</b><span>{esc(label)}</span></div>" for cls, value, label in tiles)
    sources = " · ".join(f"<a href='{esc(url)}'>{esc(url.rsplit('/', 1)[-1])}</a>" for url in SOURCES)
    incomplete = "" if complete else "<p class='callout'><b>Interrupted run.</b> Only completed inputs are shown; assess the rest again.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>{esc(CVE_ID)} Version Report</title><style>{REPORT_CSS}</style></head><body><main>
<header><div class="eyebrow">{esc(brand)}</div><h1>{esc(CVE_ID)} Version Report</h1>
<p class="sub">{esc(ADVISORY_TITLE)} · generated {esc(generated_at)} · rules as of {esc(RULES_DATE)}</p></header>
<p class="callout"><b>Version evidence, not a proof of exploitability.</b> Every result has exploitability <code>not_tested</code>.
Unknown results need investigation. Precondition observations are operator-reported and do not change the version status.</p>
{incomplete}<div class="tiles">{tile_html}</div>
<h2>Results</h2><div class="wrap"><table><thead><tr><th>Input</th><th>Assessment</th><th>Reported version</th>
<th>Upstream fix</th><th>Precondition observations</th><th>Next step and evidence</th></tr></thead>
<tbody>{''.join(body) or '<tr><td colspan="6">No results.</td></tr>'}</tbody></table></div>
<h2>Upstream fixed releases</h2><div class="wrap"><table class="narrow"><thead><tr><th>Branch</th><th>Fixed in</th></tr></thead><tbody>{fixes}</tbody></table></div>
<h2>Verify the deployed application</h2>
<p>Check the actual simple-git binary in each serving process or container. Upgrade the runtime, redeploy, then collect the version again.
Vendor and custom builds require vendor evidence because fixes may be backported.</p>
<footer>{esc(brand)} · {TOOL_NAME} {TOOL_VERSION} · {sources}</footer>
</main></body></html>
"""


def write_report(output, rows, *, format="csv", brand="CompleteTech LLC", complete=True):
    if format == "csv":
        # QUOTE_ALL keeps a bare CR/LF/TAB inside a quoted cell, so it can never start a new row.
        writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS, lineterminator="\n", quoting=csv.QUOTE_ALL)
        writer.writeheader()
        for row in rows:
            writer.writerow({**{key: csv_safe(row.get(key)) for key in CSV_COLUMNS}, "record_type": "result", "report_complete": "true" if complete else "false"})
        if not rows:
            writer.writerow({"record_type": "summary", "report_complete": "true" if complete else "false",
                             "report_schema_version": REPORT_SCHEMA_VERSION, "rules_as_of": RULES_DATE,
                             "cve": CVE_ID, "exploitability": "not_tested"})
    elif format == "json":
        json.dump({"tool": TOOL_NAME, "tool_version": TOOL_VERSION, "report_schema_version": REPORT_SCHEMA_VERSION,
                   "cve": CVE_ID, "rules_as_of": RULES_DATE, "sources": list(SOURCES), "complete": complete,
                   "generated_at": datetime.now(timezone.utc).isoformat(), "results": rows},
                  output, ensure_ascii=False, indent=2)
        output.write("\n")
    else:
        output.write(render_html(rows, brand=brand, complete=complete))


def render_report(rows, **options):
    """Render fully in memory and encode, so an encoding error happens before any output."""
    buffer = io.StringIO(newline="")
    write_report(buffer, rows, **options)
    text = buffer.getvalue()
    return text.encode("utf-8")  # raises UnicodeEncodeError for lone surrogates


def save_report(path, rows, *, force=False, state=None, **options):
    """Render first and publish atomically, retaining ownership across interrupts."""
    state = {} if state is None else state
    data = render_report(rows, **options)
    if path is None:
        out = getattr(sys.stdout, "buffer", None)
        state["stdout_started"] = True
        if out is None:
            sys.stdout.write(data.decode("utf-8"))
        else:
            out.write(data)
            out.flush()
        state["published"] = True
        return
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=".report-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            staged_identity = os.fstat(stream.fileno())
        try:
            if state is not None:
                state["publication_started"] = True
            if force:
                os.replace(temporary, path)
            else:
                try:
                    os.link(temporary, path)
                except FileExistsError:
                    raise ValueError("Output exists; use a new path or explicitly pass --force") from None
                except OSError as exc:
                    raise ValueError("Cannot publish without overwriting: hard links are unavailable here "
                                     f"({exc.strerror or type(exc).__name__}); choose another filesystem or explicitly use --force") from None
            state["published"] = True
        except KeyboardInterrupt:
            # A second interrupt or metadata failure must not permit a retry.
            try:
                owned = os.path.samestat(staged_identity, os.stat(path, follow_symlinks=False))
                if state is not None:
                    if owned:
                        state["published"] = True
                    else:
                        state["publication_started"] = False
            except FileNotFoundError:
                if state is not None:
                    state["publication_started"] = False
            except OSError:
                pass  # Publication outcome remains indeterminate.
            raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _message(exc):
    """A short, single-line, ASCII-safe description of an operational error."""
    if isinstance(exc, UnicodeError):
        return "text could not be encoded or decoded as UTF-8"
    if isinstance(exc, RecursionError):
        return "input is nested too deeply"
    text = str(exc) or type(exc).__name__
    return text[:300].encode("unicode_escape", "backslashreplace").decode("ascii")[:300]


def _validate_arguments(args):
    """Checks that need no input data; run before any file is loaded."""
    _bounded_text(args.build_source, "--build-source")
    _bounded_text(args.brand, "--brand")
    for version in args.package_version:
        _bounded_text(version, "--version")
    if len(args.package_version) > MAX_ENTRIES:
        raise ValueError(f"A run is limited to {MAX_ENTRIES:,} inputs")
    inputs = (*args.inventory, *args.csv_list, *args.source, *args.npm_lock, *args.installed_package)
    if len(inputs) > MAX_FILES:
        raise ValueError(f"A run is limited to {MAX_FILES} input files")
    if args.source and args.source_root is None:
        raise ValueError("--source requires --source-root for relative evidence paths")
    if args.source_root is not None and not args.source_root.is_dir():
        raise ValueError("--source-root must be a directory")
    for path in inputs:
        _require_regular_file(path)
    for path in args.source:
        if path.suffix.lower() not in {".js", ".cjs", ".mjs", ".ts", ".cts", ".mts", ".jsx", ".tsx"}:
            raise ValueError("Source must be an explicitly selected JS/TS file")
        path.resolve().relative_to(args.source_root.resolve())
    if args.output is not None:
        output = args.output
        parent = output.parent
        if not parent.is_dir():
            raise ValueError("Output directory must already exist")
        if os.path.lexists(output):
            if not args.force:
                raise ValueError("Output exists; use a new path or explicitly pass --force")
            if os.path.islink(output) and not output.exists():
                raise ValueError("Output is a dangling or looping symbolic link")
            if output.is_dir() or (output.exists() and not stat.S_ISREG(os.stat(output).st_mode)):
                raise ValueError("Output must be a regular file path")
            for path in inputs:
                if os.path.samefile(output, path):
                    raise ValueError("--output must differ from every input file, even with --force")
        for path in inputs:
            if os.path.realpath(output) == os.path.realpath(path):
                raise ValueError("--output must differ from every input file, even with --force")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, allow_abbrev=False, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit status: 0 success; 1 findings (only with --fail-on-finding: potentially_affected); 2 usage or operational error (nothing assessed or report not written); "
               "130 interrupted (completed results are written with complete=false).")
    parser.add_argument("--tool-version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--version", "--package-version", dest="package_version", action="append", default=[], metavar="VERSION",
                        help="Assess an explicitly supplied simple-git version offline (leading v accepted); repeatable")
    parser.add_argument("--build-source", default="unknown", metavar="SOURCE",
                        help="Provenance of the --version builds, at most 512 characters: unknown (default, compared as upstream), "
                             "upstream, official, or a vendor name")
    for key, description in PRECONDITIONS:
        parser.add_argument("--" + key.replace("_", "-"), choices=("true", "false"), dest=key,
                            help=f"Observation applied to --version inputs: {description}")
    parser.add_argument("--inventory", action="append", default=[], type=Path, metavar="FILE",
                        help="JSON object or array of entries (see docs/REFERENCE.md); repeatable")
    parser.add_argument("--csv-list", action="append", default=[], type=Path, metavar="FILE",
                        help="CSV with a package_version column and optional label, build_source and precondition columns; repeatable")
    parser.add_argument("--npm-lock", action="append", default=[], type=Path, metavar="FILE",
                        help="Explicit npm package-lock/shrinkwrap JSON (versions 1, 2, 3); never invokes npm")
    parser.add_argument("--installed-package", action="append", default=[], type=Path, metavar="FILE",
                        help="Explicit installed simple-git package.json; reads only name/version metadata")
    parser.add_argument("--source", action="append", default=[], type=Path, metavar="FILE",
                        help="Explicit JS/TS file for lexical clone/mirror candidates; repeatable, never executed")
    parser.add_argument("--source-root", type=Path, metavar="DIR",
                        help="Required with --source; evidence paths are relative to this directory")
    parser.add_argument("--format", choices=("csv", "json", "html"), default="csv", help="Output format (default: csv)")
    parser.add_argument("--output", type=Path, help="Save report to a new file; default: stdout")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file explicitly")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Organization name for the HTML report (at most 512 characters)")
    parser.add_argument("--fail-on-finding", action="store_true",
                        help="Exit 1 for potentially_affected results (errors still exit 2)")
    args = parser.parse_args(argv)
    if not (args.package_version or args.inventory or args.csv_list or args.npm_lock or args.installed_package or args.source):
        parser.error("provide --version, --inventory, --csv-list, --npm-lock, --installed-package or --source")
    rows = []
    state = {"validated": False, "published": False, "stdout_started": False}
    options = {"force": args.force, "format": args.format, "brand": args.brand, "state": state}
    try:
        try:
            _validate_arguments(args)
            state["validated"] = True
            observations = {key: _tri_state(getattr(args, key), key, text=True) for key in PRECONDITION_KEYS}
            budget = Budget()
            budget.add_entries(len(args.package_version))
            for version in args.package_version:
                rows.append(assess_entry("simple-git " + version.strip(ASCII_SPACE), "version", version, args.build_source, observations))
            for path in args.inventory:
                load_inventory(path, budget, rows)
            for path in args.csv_list:
                load_csv_list(path, budget, rows)
            for path in args.npm_lock:
                load_npm_lock(path, budget, rows)
            for path in args.installed_package:
                load_installed_package(path, budget, rows)
            for path in args.source:
                load_source(path, args.source_root, budget, rows)
            save_report(args.output, rows, complete=True, **options)
        except KeyboardInterrupt:
            if not state["validated"]:
                print("Interrupted before the output path was validated; nothing was written.", file=sys.stderr)
                return 130
            if state["published"]:
                print("Interrupted after the complete report was written; not retrying.", file=sys.stderr)
                return 130
            if state.get("publication_started"):
                print("Interrupted; publication outcome indeterminate; inspect the output before retrying. No retry was attempted.", file=sys.stderr)
                return 130
            if state["stdout_started"]:
                print("Interrupted while writing to stdout; output may be truncated and no second report is written.", file=sys.stderr)
                return 130
            print("Interrupted; writing completed results.", file=sys.stderr)
            save_report(args.output, rows, complete=False, **options)
            return 130
    except KeyboardInterrupt:
        print("Interrupted again; the partial report may not have been written.", file=sys.stderr)
        return 130
    except (OSError, ValueError, RecursionError, RuntimeError, csv.Error) as exc:  # json errors are ValueError
        print(f"{TOOL_NAME}: error: {_message(exc)}", file=sys.stderr)
        return 2
    if args.fail_on_finding and any(row["status"] in {"potentially_affected"} for row in rows):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
