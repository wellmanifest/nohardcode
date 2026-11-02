#!/usr/bin/env python3
"""
Wellmanifest No-Hardcode Standard Conformance and AST Smell Scanner.
Normative standard: wellmanifest/nohardcode@v1 (0.1.0-dev)

Dependency-free: uses only Python standard library.
"""

from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.2.0-dev"

ALLOWED_PROFILES = frozenset({"strict", "balanced", "permissive"})
ALLOWED_SEVERITIES = frozenset({"error", "warning", "info"})
ALLOWED_RULE_CATEGORIES = frozenset({
    "natural_language_keywords",
    "screen_coordinates",
    "ui_labels",
    "business_logic_branching",
    "secrets_and_credentials",
    "network_endpoints_and_ports",
    "log_and_error_strings",
    "pii_and_fixtures",
    "filesystem_paths",
    "code_duplication",
    "adaptive_thresholds_and_timeouts",
    "rigid_schema_and_dom_parsers",
    "model_and_provider_bindings",
    "procedural_workflows_and_sequences",
    "hardware_and_environment_assumptions",
    "phonetic_and_fuzzy_matching",
    "static_prioritization_and_scoring",
})

# Built-in Detection Regexes
RE_PLAINTEXT_SECRET = re.compile(
    r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/]{16,})["\']'
)
RE_HARDCODED_PORT = re.compile(
    r'(https?://|ws://|tcp://)?(localhost|127\.0\.0\.1|0\.0\.0\.0):([0-9]{2,5})'
)
# Private (RFC 1918) host address, with or without port. Network ranges
# (`192.168.1.0/24`) and network/broadcast addresses are not endpoints.
RE_PRIVATE_HOST = re.compile(
    r"(?<![\d.])(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.(?!0(?![\d.])|255(?![\d.]))\d{1,3}(?![\d.]|/\d)(?::\d{2,5})?"
)
# Default of an environment lookup: the remediation the adoption guide
# prescribes (``os.getenv("WILLMUX_PORT", "7070")``), not a hardcoded endpoint.
RE_ENV_DEFAULT = re.compile(
    r'(?:\bgetenv|\benviron\.get|\benviron\.setdefault)\(\s*["\'][A-Za-z_][A-Za-z0-9_]*["\']\s*,\s*'
    r'(?P<default>["\'][^"\']*["\'])'
)
# The same remedy in JS/TS: fallback of an UPPER_SNAKE configuration key
# (``process.env.BASE_URL || "..."``, ``import.meta.env.X ?? "..."``,
# ``config().API_URL || "..."``) and in shell (``${API_URL:-...}``).
RE_ENV_DEFAULT_JS = re.compile(
    r'\.[A-Z][A-Z0-9_]*\s*(?:\|\||\?\?)\s*(?P<default>"[^"]*"|\'[^\']*\'|`[^`]*`)'
)
RE_ENV_ASSIGNMENT = re.compile(r"\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=")
RE_ENV_DEFAULT_SHELL = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*:?-(?P<default>[^}]*)\}')
ENV_DEFAULT_PATTERNS = (RE_ENV_DEFAULT, RE_ENV_DEFAULT_JS, RE_ENV_DEFAULT_SHELL)
# Reviewed exception on the flagged line; the rule id must match and a
# reason is mandatory. Waived findings stay in the report but do not block.
RE_WAIVER = re.compile(r"#\s*nohardcode:\s*allow\s+(NOHARDCODE-\d{3})\s+--\s+(\S.*?)\s*$")
RE_HARDCODED_COORDINATES = re.compile(
    r'\b(click|moveTo|mouse_down|mouse_up|dragTo)\s*\(\s*(?:x\s*=\s*)?(\d{2,4})\s*,\s*(?:y\s*=\s*)?(\d{2,4})\s*\)'
)
RE_BRITTLE_UI_SELECTOR = re.compile(
    r'(?://[a-zA-Z0-9_-]+\[\d+\]/[a-zA-Z0-9_-]+\[\d+\]|nth-child\(\d+\)\s*>\s*[^"\'\n]*nth-child\(\d+\))'
)
RE_TICKET_ID_LITERAL = re.compile(r"^(?:PLF|TICKET|ISS|GH)-[0-9]{2,}$")
RE_BEARER_OR_TOKEN_LITERAL = re.compile(
    r'["\'](?:Bearer\s+eyJ[A-Za-z0-9_-]{16,}|sk-(?:proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9_]{20,})["\']'
)
RE_HARDCODED_PII_EMAIL = re.compile(
    r'["\']([a-zA-Z0-9_.+-]+@((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}))["\']'
)
SAFE_EMAIL_DOMAINS = frozenset({
    "example.com",
    "example.org",
    "example.net",
    "example.test",
    "test.local",
    "localhost",
    "users.noreply.github.com",
    "wellmanifest.com",
    "wellmanifest.dev",
})
SAFE_EMAIL_TLDS = frozenset({
    ".test",
    ".example",
    ".invalid",
    ".localhost",
    ".local",
})
RE_HARDCODED_HOME = re.compile(
    r'["\'](/home/[a-zA-Z0-9._-]+|/Users/[a-zA-Z0-9._-]+|[A-Z]:\\[Uu]sers\\[a-zA-Z0-9._-]+)'
)
RE_HARDCODED_SLEEP = re.compile(
    r'\b(?:time\.sleep|asyncio\.sleep)\s*\(\s*([1-9][0-9]*(\.[0-9]+)?)\s*\)'
)
RE_HARDCODED_MODEL = re.compile(
    r'(?i)(?:\b(?:model|engine)(?:\s*:\s*[A-Za-z0-9_.\[\]\s|]+)?\s*[:=]\s*|["\']model["\']\s*:\s*|\bDEFAULT_[A-Z0-9_]*MODEL\s*=\s*)["\']'
    r'(gpt-[345o][a-z0-9._-]*|claude-(?:[234]|3-[57]|sonnet|opus|haiku)[a-z0-9._-]*|'
    r'text-davinci[a-z0-9._-]*|gemini-[123]\.[05][a-z0-9._-]*|'
    r'qwen[0-9.a-z_-]*:[0-9.a-z_-]+|llama[0-9.a-z_-]*:[0-9.a-z_-]+|'
    r'deepseek-[a-z0-9._:-]+|mistral-[a-z0-9._:-]+|d1:[0-9a-z._-]+)["\']'
)
RE_HARDCODED_DISPLAY = re.compile(
    r'(?i)(?:DISPLAY\s*[:=]\s*["\']:[0-9]+(\.[0-9]+)?["\']|--display\s+["\']:[0-9]+["\'])'
)
RE_HARDCODED_CUDA = re.compile(
    r'["\']cuda:[0-9]+["\']'
)
RE_REGEX_STEMMER = re.compile(
    r're\.sub\(\s*r?["\']\(\?:[a-z|]{10,}\)\$["\']'
)
NL_MARKER_TOKENS = (
    "otworz", "uruchom", "wylacz", "wlacz", "pokaz", "zrob", "znajdz", "szukaj",
    "wykonaj", "zrealizuj", "przerob", "obsluz", "napraw", "sprawdz", "zbadaj",
    "play", "open", "close", "start", "stop", "help", "execute",
)


class ConformanceError(ValueError):
    """Raised when document or policy violates normative specification."""
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class Violation:
    def __init__(
        self,
        rule_id: str,
        file_path: str,
        line_number: int,
        severity: str,
        message: str,
        replacement: str,
    ) -> None:
        self.rule_id = rule_id
        self.file_path = file_path
        self.line_number = line_number
        self.severity = severity
        self.message = message
        self.replacement = replacement
        self.waiver_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        data = {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity,
            "message": self.message,
            "recommended_replacement": self.replacement,
            "waived": self.waiver_reason is not None,
        }
        if self.waiver_reason is not None:
            data["waiver_reason"] = self.waiver_reason
        return data

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_id} in {self.file_path}:{self.line_number} -> {self.message} (Fix: {self.replacement})"


def validate_policy_document(doc: dict[str, Any]) -> None:
    """Validates policy against wellmanifest.nohardcode/policy/v1 schema rules."""
    if not isinstance(doc, dict):
        raise ConformanceError("NOHARDCODE_POLICY_INVALID", "Policy must be a JSON object")

    schema = doc.get("schema")
    if schema != "wellmanifest.nohardcode/policy/v1":
        raise ConformanceError(
            "NOHARDCODE_POLICY_INVALID",
            f"Invalid schema: expected 'wellmanifest.nohardcode/policy/v1', got {schema!r}",
        )

    version = doc.get("version")
    if not version or not isinstance(version, str):
        raise ConformanceError("NOHARDCODE_POLICY_INVALID", "Missing or invalid policy version")

    profile = doc.get("profile", "balanced")
    if profile not in ALLOWED_PROFILES:
        raise ConformanceError(
            "NOHARDCODE_PROFILE_INVALID",
            f"Unknown profile: {profile!r}. Expected one of {sorted(ALLOWED_PROFILES)}",
        )

    bindings = doc.get("engine_bindings")
    if not isinstance(bindings, dict):
        raise ConformanceError("NOHARDCODE_POLICY_INVALID", "engine_bindings must be an object")

    rules = doc.get("rules")
    if not isinstance(rules, dict):
        raise ConformanceError("NOHARDCODE_POLICY_INVALID", "rules must be an object")

    waivers = doc.get("waivers", [])
    if not isinstance(waivers, list):
        raise ConformanceError("NOHARDCODE_POLICY_INVALID", "waivers must be an array")
    for waiver in waivers:
        if not isinstance(waiver, dict) or set(waiver) - {"path", "rule", "reason", "match"}:
            raise ConformanceError("NOHARDCODE_WAIVER_INVALID", "waiver must be {path, rule, reason, match?}")
        path = waiver.get("path")
        if (not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
                or any(ch in path for ch in "*?[") or ".." in path.split("/")):
            raise ConformanceError("NOHARDCODE_WAIVER_INVALID", f"waiver path must be an exact relative path: {path!r}")
        if not isinstance(waiver.get("rule"), str) or not re.fullmatch(r"NOHARDCODE-[0-9]{3}", waiver["rule"]):
            raise ConformanceError("NOHARDCODE_WAIVER_INVALID", f"waiver rule must be NOHARDCODE-NNN: {waiver.get('rule')!r}")
        if not isinstance(waiver.get("reason"), str) or not waiver["reason"].strip():
            raise ConformanceError("NOHARDCODE_WAIVER_INVALID", f"waiver for {path} needs a non-empty reason")
        if "match" in waiver and (not isinstance(waiver["match"], str) or not waiver["match"]):
            raise ConformanceError("NOHARDCODE_WAIVER_INVALID", f"waiver match for {path} must be a non-empty string")


def validate_detection_rule_document(doc: dict[str, Any]) -> None:
    """Validates detection rule document against detection-rule.schema.json."""
    if not isinstance(doc, dict):
        raise ConformanceError("DETECTION_RULE_INVALID", "Rule must be a JSON object")

    rule_id = doc.get("rule_id", "")
    if not re.match(r"^NOHARDCODE-[0-9]{3}$", rule_id):
        raise ConformanceError("DETECTION_RULE_ID_INVALID", f"Invalid rule_id pattern: {rule_id!r}")

    category = doc.get("category", "")
    if category not in ALLOWED_RULE_CATEGORIES:
        raise ConformanceError(
            "DETECTION_RULE_CATEGORY_INVALID",
            f"Invalid category: {category!r}. Expected one of {sorted(ALLOWED_RULE_CATEGORIES)}",
        )

    severity = doc.get("severity", "")
    if severity not in ALLOWED_SEVERITIES:
        raise ConformanceError("DETECTION_RULE_INVALID", f"Invalid severity: {severity!r}")

    matcher = doc.get("matcher")
    if not isinstance(matcher, dict) or "kind" not in matcher:
        raise ConformanceError("DETECTION_RULE_INVALID", "matcher must be an object with 'kind'")


# Where print() is the interface: CLI tools, scripts, tests and benchmarks.
CLI_DIRECTORIES = {"bin", "scripts", "cli", "test", "tests", "benchmark", "benchmarks"}
CLI_NAME_WORDS = {"check", "cli", "conformance", "test", "tests", "conftest", "benchmark"}


TEST_DIRECTORIES = {"test", "tests", "e2e", "fixture", "fixtures", "mock", "mocks", "__mocks__", "bench", "benchmark", "benchmarks"}
TEST_NAME_WORDS = {"test", "tests", "spec", "fixture", "fixtures", "mock", "mocks", "bench", "benchmark", "conftest"}


def is_test_or_fixture_path(role_path: str) -> bool:
    """Test, fixture, mock or benchmark by path component or filename word."""
    parts = [part for part in re.split(r"[\\/]", role_path.lower()) if part not in {"", "."}]
    if not parts:
        return False
    *directories, name = parts
    return bool(TEST_DIRECTORIES.intersection(directories)) or bool(TEST_NAME_WORDS & set(re.split(r"[_.-]", name)))


def is_cli_or_test_path(role_path: str) -> bool:
    """Match whole path components and filename words, never substrings."""
    parts = [part for part in re.split(r"[\\/]", role_path.lower()) if part not in {"", "."}]
    if not parts:
        return False
    *directories, name = parts
    stem = name.rsplit(".", 1)[0]
    words = set(re.split(r"[_.-]", stem))
    return bool(CLI_DIRECTORIES.intersection(directories)) or stem == "__main__" or bool(CLI_NAME_WORDS & words)


class CodeSmellVisitor(ast.NodeVisitor):
    """AST Visitor detecting hardcoded anti-patterns in Python source files."""

    def __init__(self, filename: str, profile: str = "balanced", role_path: Optional[str] = None) -> None:
        self.filename = filename
        self.profile = profile
        # Repository-relative path used to classify the file's role; host
        # directories above the scanned root must not influence it.
        self.role_path = filename if role_path is None else role_path
        self.violations: list[Violation] = []
        self._elif_chain_members: set[ast.If] = set()
        self._verified_argv: set[ast.AST] = set()
        self._inner_subscripts: set[ast.Subscript] = set()
        self._inner_binops: set[ast.BinOp] = set()
        self._seen_func_bodies: dict[str, tuple[str, int]] = {}

    def visit_Module(self, node: ast.Module) -> None:
        # Resolve only top-level stdlib imports with a unique binding across
        # the file. This deliberately rejects ambiguous/shadowed names even
        # in unrelated scopes; no variable-name or executable-name exemption.
        apis = {"run", "Popen", "call", "check_call", "check_output"}
        bindings: dict[str, int] = {}
        node_bindings: dict[ast.AST, list[str]] = {}
        nodes = list(ast.walk(node))
        for item in nodes:
            names: list[str] = []
            if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
                names = [item.id]
            elif isinstance(item, ast.arg):
                names = [item.arg]
            elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names = [item.name]
            elif isinstance(item, (ast.Import, ast.ImportFrom)):
                names = [alias.asname or (alias.name.split(".")[0] if isinstance(item, ast.Import) else alias.name)
                         for alias in item.names]
            elif isinstance(item, ast.ExceptHandler) and item.name:
                names = [item.name]
            elif isinstance(item, (ast.MatchAs, ast.MatchStar)) and item.name:
                names = [item.name]
            elif isinstance(item, ast.MatchMapping) and item.rest:
                names = [item.rest]
            node_bindings[item] = names
            for name in names:
                bindings[name] = bindings.get(name, 0) + 1

        # Star imports may replace any binding; keep the original findings.
        if any(isinstance(item, ast.ImportFrom) and any(a.name == "*" for a in item.names) for item in nodes):
            self.generic_visit(node)
            return
        modules: set[str] = set()
        functions: set[str] = set()
        for statement in node.body:
            if isinstance(statement, ast.Import):
                modules.update(a.asname or a.name for a in statement.names if a.name == "subprocess")
            elif isinstance(statement, ast.ImportFrom) and statement.module == "subprocess" and statement.level == 0:
                functions.update(a.asname or a.name for a in statement.names if a.name in apis)
        modules = {name for name in modules if bindings.get(name) == 1}
        functions = {name for name in functions if bindings.get(name) == 1}
        # An explicit attribute replacement also makes the module ambiguous.
        modules -= {item.value.id for item in nodes
                    if isinstance(item, ast.Attribute) and isinstance(item.ctx, (ast.Store, ast.Del))
                    and isinstance(item.value, ast.Name)}
        verified_args: dict[ast.Call, Optional[ast.AST]] = {}
        for item in nodes:
            if not isinstance(item, ast.Call):
                continue
            func = item.func
            verified = (isinstance(func, ast.Name) and func.id in functions) or (
                isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in modules and func.attr in apis)
            if not verified:
                continue
            keyword_args = [kw.value for kw in item.keywords if kw.arg == "args"]
            argv = item.args[0] if item.args and not keyword_args else (
                keyword_args[0] if not item.args and len(keyword_args) == 1 else None)
            verified_args[item] = argv
            if isinstance(argv, (ast.List, ast.Tuple)):
                self._verified_argv.add(argv)

        parents = {child: parent for parent in nodes for child in ast.iter_child_nodes(parent)}
        for parent in nodes:
            for _, block in ast.iter_fields(parent):
                if not isinstance(block, list) or not all(isinstance(s, ast.stmt) for s in block):
                    continue
                for assignment, following in zip(block, block[1:]):
                    if (not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1
                            or not isinstance(assignment.targets[0], ast.Name)
                            or not isinstance(assignment.value, (ast.List, ast.Tuple))
                            or not isinstance(following, (ast.Expr, ast.Assign))):
                        continue
                    call = following.value
                    if not isinstance(call, ast.Call):
                        continue
                    argv = verified_args.get(call)
                    name = assignment.targets[0].id
                    if not isinstance(argv, ast.Name) or argv.id != name:
                        continue
                    scope = parent
                    while not isinstance(scope, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                        scope = parents[scope]
                    scoped_nodes = list(ast.walk(scope))
                    # Exactly one binding and one load: reject reuse, mutation,
                    # aliases and alternate definitions, including nested scopes.
                    # Global/nonlocal storage is deliberately left unclassified.
                    if (sum(isinstance(n, ast.Name) and n.id == name for n in scoped_nodes) == 2
                            and sum(node_bindings[n].count(name) for n in scoped_nodes) == 1
                            and not any(isinstance(n, (ast.Global, ast.Nonlocal)) and name in n.names for n in scoped_nodes)):
                        self._verified_argv.add(assignment.value)
        self.generic_visit(node)

    def visit_List(self, node: ast.List) -> None:
        self._check_literal_collection(node, "List")
        self.generic_visit(node)

    def visit_Set(self, node: ast.Set) -> None:
        self._check_literal_collection(node, "Set")
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self._check_literal_collection(node, "Tuple")
        self.generic_visit(node)

    def _check_literal_collection(self, node: ast.AST, col_type: str) -> None:
        if node in self._verified_argv or is_test_or_fixture_path(self.role_path):
            return
        elts = getattr(node, "elts", [])
        if len(elts) > 5:
            str_literals = [e for e in elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if len(str_literals) > 5:
                # Differentiate natural language phrases from technical enum identifiers:
                # Technical enums are usually lowercase / snake_case without spaces or unicode diacritics.
                # Natural language commands contain spaces, punctuation, or non-ascii letters (e.g. Polish: ą, ę, ó, ł, etc.)
                has_spaces = any(" " in s.value for s in str_literals)
                has_non_ascii = any(any(ord(c) > 127 for c in s.value) for s in str_literals)
                has_nl_markers = any(any(token in s.value.lower() for token in ("otworz", "uruchom", "wylacz", "wlacz", "pokaz", "zrob", "znajdz", "szukaj", "play", "open", "close", "start", "stop", "help")) for s in str_literals)

                if has_spaces or has_non_ascii or has_nl_markers:
                    severity = "warning" if self.profile != "strict" else "error"
                    self.violations.append(
                        Violation(
                            rule_id="NOHARDCODE-001",
                            file_path=self.filename,
                            line_number=getattr(node, "lineno", 1),
                            severity=severity,
                            message=f"Static {col_type} of {len(str_literals)} natural language/command string literals indicates hardcoded intent dispatch",
                            replacement="wellmanifest/nl-dsl-llm semantic router or local LLM evaluator",
                        )
                    )

    def visit_If(self, node: ast.If) -> None:
        # Check for hardcoded ticket/issue ID branching in business logic (NOHARDCODE-004)
        if not is_test_or_fixture_path(self.role_path):
            ticket_literals = [
                c.value for c in ast.walk(node.test)
                if isinstance(c, ast.Constant) and isinstance(c.value, str)
                and RE_TICKET_ID_LITERAL.fullmatch(c.value.strip())
            ]
            if ticket_literals:
                severity = "warning" if self.profile != "strict" else "error"
                self.violations.append(
                    Violation(
                        rule_id="NOHARDCODE-004",
                        file_path=self.filename,
                        line_number=node.lineno,
                        severity=severity,
                        message=f"Hardcoded ticket/issue ID branching ({', '.join(ticket_literals[:3])}) couples logic to specific records",
                        replacement="Declarative label/metadata policy expression (wellmanifest/policy-dsl)",
                    )
                )

        if node in self._elif_chain_members:
            # Still visit the body: it may contain an independent nested chain.
            self.generic_visit(node)
            return
        # Check depth of elif chains (NOHARDCODE-004: Declarative Business Logic)
        depth = 0
        curr: Optional[ast.AST] = node
        while curr and isinstance(curr, ast.If):
            depth += 1
            if curr.orelse and len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
                self._elif_chain_members.add(curr.orelse[0])
                curr = curr.orelse[0]
            else:
                break

        if depth > 4:
            severity = "warning" if self.profile != "strict" else "error"
            self.violations.append(
                Violation(
                    rule_id="NOHARDCODE-004",
                    file_path=self.filename,
                    line_number=node.lineno,
                    severity=severity,
                    message=f"Deeply nested conditional logic ({depth} branches) should be externalized",
                    replacement="Declarative JEV policy expression or wellmanifest/policy-dsl",
                )
            )

        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        # NOHARDCODE-016: Static inflection/typo alias dictionary mapping >= 6 surface variants to <= 2 targets
        if not is_test_or_fixture_path(self.role_path) and len(node.keys) >= 6:
            str_keys = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
            const_vals = [
                v.value for v in node.values
                if isinstance(v, ast.Constant) and isinstance(v.value, (str, int))
            ]
            if len(str_keys) >= 6 and len(const_vals) == len(node.keys):
                distinct_vals = {repr(v) for v in const_vals}
                if 1 <= len(distinct_vals) <= 2 and all(re.fullmatch(r"[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]{3,}", k) for k in str_keys):
                    severity = "warning" if self.profile != "strict" else "error"
                    self.violations.append(
                        Violation(
                            rule_id="NOHARDCODE-016",
                            file_path=self.filename,
                            line_number=node.lineno,
                            severity=severity,
                            message=f"Static inflection/typo alias map ({len(str_keys)} surface keys -> {len(distinct_vals)} target(s))",
                            replacement="Bounded Levenshtein / phonetic matcher or semantic router (wellmanifest/nl-dsl-llm)",
                        )
                    )
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # NOHARDCODE-012: Deeply chained constant string dictionary subscripts (depth >= 4)
        if node not in self._inner_subscripts and not is_test_or_fixture_path(self.role_path):
            depth = 0
            curr: ast.AST = node
            while isinstance(curr, ast.Subscript):
                sl = curr.slice
                if isinstance(sl, ast.Constant) and isinstance(sl.value, str):
                    depth += 1
                    if isinstance(curr.value, ast.Subscript):
                        self._inner_subscripts.add(curr.value)
                    curr = curr.value
                else:
                    break
            if depth >= 4:
                severity = "warning" if self.profile != "strict" else "error"
                self.violations.append(
                    Violation(
                        rule_id="NOHARDCODE-012",
                        file_path=self.filename,
                        line_number=node.lineno,
                        severity=severity,
                        message=f"Rigid chained dictionary subscript traversal ({depth} levels) is fragile to schema changes",
                        replacement="Schema-tolerant extractor or typed contract validator (wellmanifest/nl-dsl-llm)",
                    )
                )
        self.generic_visit(node)

    def _check_imperative_retry_loop(self, node: ast.AST) -> None:
        # NOHARDCODE-014: Imperative loop with fixed sleep delay instead of declarative backoff/DAG
        if is_test_or_fixture_path(self.role_path):
            return
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if (isinstance(child.func.value, ast.Name)
                        and child.func.value.id in {"time", "asyncio"}
                        and child.func.attr == "sleep"
                        and child.args
                        and isinstance(child.args[0], ast.Constant)
                        and isinstance(child.args[0].value, (int, float))):
                    severity = "warning" if self.profile != "strict" else "error"
                    self.violations.append(
                        Violation(
                            rule_id="NOHARDCODE-014",
                            file_path=self.filename,
                            line_number=getattr(node, "lineno", 1),
                            severity=severity,
                            message="Imperative retry/polling loop with fixed sleep delay",
                            replacement="Declarative DAG workflow (wellmanifest/poa) or adaptive exponential jitter backoff",
                        )
                    )
                    break

    def visit_For(self, node: ast.For) -> None:
        self._check_imperative_retry_loop(node)
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self._check_imperative_retry_loop(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_duplicate_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_duplicate_function(node)
        self.generic_visit(node)

    def _check_duplicate_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # NOHARDCODE-010: Intra-file duplicate non-trivial function AST bodies
        if is_test_or_fixture_path(self.role_path):
            return
        body = list(node.body)
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
            body = body[1:]
        if len(body) < 4:
            return
        sig = "|".join(ast.dump(stmt, annotate_fields=True, include_attributes=False) for stmt in body)
        prev = self._seen_func_bodies.get(sig)
        if prev is not None:
            prev_name, prev_line = prev
            severity = "warning" if self.profile != "strict" else "error"
            self.violations.append(
                Violation(
                    rule_id="NOHARDCODE-010",
                    file_path=self.filename,
                    line_number=node.lineno,
                    severity=severity,
                    message=f"Function '{node.name}' duplicates AST body of '{prev_name}' (line {prev_line})",
                    replacement="Extract single canonical helper (wellmanifest/ssot & wellmanifest/reuse)",
                )
            )
        else:
            self._seen_func_bodies[sig] = (node.name, node.lineno)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        # NOHARDCODE-017: Hardcoded linear scoring formula (e.g. 0.7 * urgency + 0.3 * impact)
        if (node not in self._inner_binops
                and not is_test_or_fixture_path(self.role_path)
                and isinstance(node.op, (ast.Add, ast.Sub))):
            terms: list[ast.AST] = []
            stack: list[ast.AST] = [node]
            while stack:
                curr = stack.pop()
                if isinstance(curr, ast.BinOp) and isinstance(curr.op, (ast.Add, ast.Sub)):
                    self._inner_binops.add(curr)
                    stack.append(curr.left)
                    stack.append(curr.right)
                else:
                    terms.append(curr)
            weighted_terms = 0
            for term in terms:
                if isinstance(term, ast.BinOp) and isinstance(term.op, ast.Mult):
                    sides = (term.left, term.right)
                    has_float_weight = any(
                        isinstance(s, ast.Constant) and isinstance(s.value, float) and not isinstance(s.value, bool)
                        for s in sides
                    )
                    has_var = any(not isinstance(s, ast.Constant) for s in sides)
                    if has_float_weight and has_var:
                        weighted_terms += 1
            if weighted_terms >= 2:
                severity = "warning" if self.profile != "strict" else "error"
                self.violations.append(
                    Violation(
                        rule_id="NOHARDCODE-017",
                        file_path=self.filename,
                        line_number=node.lineno,
                        severity=severity,
                        message=f"Hardcoded linear scoring formula with {weighted_terms} static float weights",
                        replacement="Thompson Sampling / adaptive ranking governor or declarative scoring policy",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check for raw print() calls (NOHARDCODE-007)
        # Exclude CLI tools, scripts, and test runners where print is standard CLI output
        if not is_cli_or_test_path(self.role_path) and isinstance(node.func, ast.Name) and node.func.id == "print":
            severity = "error" if self.profile in {"strict", "balanced"} else "warning"
            self.violations.append(
                Violation(
                    rule_id="NOHARDCODE-007",
                    file_path=self.filename,
                    line_number=node.lineno,
                    severity=severity,
                    message="Raw print() call used for logging/output",
                    replacement="Structured JSONL logger with codified errors (wellmanifest/logs)",
                )
            )

        # Check for coordinate click calls (positional or keyword x=..., y=...) (NOHARDCODE-002)
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"click", "moveTo", "dragTo", "mouse_down", "mouse_up"}:
            coords: Optional[tuple[int, int]] = None
            if len(node.args) >= 2 and all(isinstance(a, ast.Constant) and isinstance(a.value, int) and not isinstance(a.value, bool) for a in node.args[:2]):
                coords = (node.args[0].value, node.args[1].value)
            else:
                kw_map = {
                    kw.arg: kw.value.value
                    for kw in node.keywords
                    if kw.arg in {"x", "y"} and isinstance(kw.value, ast.Constant)
                    and isinstance(kw.value.value, int) and not isinstance(kw.value.value, bool)
                }
                if "x" in kw_map and "y" in kw_map:
                    coords = (kw_map["x"], kw_map["y"])
            if coords is not None:
                severity = "warning" if self.profile != "strict" else "error"
                self.violations.append(
                    Violation(
                        rule_id="NOHARDCODE-002",
                        file_path=self.filename,
                        line_number=node.lineno,
                        severity=severity,
                        message=f"Hardcoded pixel coordinates ({coords[0]}, {coords[1]}) in {node.func.attr}()",
                        replacement="YOLO element detection (twinerd-vision) or Tesseract OCR bounding box",
                    )
                )

        # NOHARDCODE-001: Pipe-delimited NL phrase helpers (_phrases/_synonyms("a|b|c|d|e|f") or "a|b|...".split("|"))
        pipe_str: Optional[str] = None
        if not is_test_or_fixture_path(self.role_path):
            if (isinstance(node.func, ast.Name)
                    and node.func.id not in {"compile", "search", "match", "fullmatch", "sub", "split"}
                    and len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                pipe_str = node.args[0].value
            elif (isinstance(node.func, ast.Attribute) and node.func.attr == "split"
                  and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)
                  and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "|"):
                pipe_str = node.func.value.value
        if pipe_str is not None:
            parts = [p.strip() for p in pipe_str.split("|") if p.strip()]
            if len(parts) > 5:
                has_spaces = any(" " in p for p in parts)
                has_non_ascii = any(any(ord(c) > 127 for c in p) for p in parts)
                has_nl_markers = any(any(tok in p.lower() for tok in NL_MARKER_TOKENS) for p in parts)
                if has_spaces or has_non_ascii or has_nl_markers:
                    severity = "warning" if self.profile != "strict" else "error"
                    self.violations.append(
                        Violation(
                            rule_id="NOHARDCODE-001",
                            file_path=self.filename,
                            line_number=node.lineno,
                            severity=severity,
                            message=f"Pipe-delimited string of {len(parts)} natural language phrases indicates hardcoded intent dispatch",
                            replacement="Declarative wellmanifest/nl-api-llm or wellmanifest/nl-uri-dsl-llm catalog",
                        )
                    )

        # NOHARDCODE-001: Regex keyword alternation with >= 6 NL words in re.compile/search/match/fullmatch
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re"
                and node.func.attr in {"compile", "search", "match", "fullmatch"}
                and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
            pattern_text = node.args[0].value
            for group_match in re.finditer(r"\((?:\?:)?([a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ0-9_\s|]{18,})\)", pattern_text):
                branches = [b.strip() for b in group_match.group(1).split("|") if b.strip()]
                word_branches = [b for b in branches if re.fullmatch(r"[a-zA-ZąćęłńóśźżĄĆĘŁŃÓŚŹŻ]{3,}(?:\\[a-zA-Z*+]+)?", b)]
                if len(word_branches) >= 6:
                    has_nl = any(any(ord(c) > 127 for c in b) or b.lower() in NL_MARKER_TOKENS for b in word_branches)
                    if has_nl:
                        severity = "warning" if self.profile != "strict" else "error"
                        self.violations.append(
                            Violation(
                                rule_id="NOHARDCODE-001",
                                file_path=self.filename,
                                line_number=node.lineno,
                                severity=severity,
                                message=f"Regex alternation of {len(word_branches)} natural language keywords indicates hardcoded intent matching",
                                replacement="wellmanifest/nl-uri-dsl-llm semantic router or declarative intent catalog",
                            )
                        )
                        break

        self.generic_visit(node)


def _inside_env_default(line: str, position: int) -> bool:
    """True when ``position`` lies in the default argument of an env lookup."""
    return any(
        match.start("default") <= position < match.end("default")
        for pattern in ENV_DEFAULT_PATTERNS
        for match in pattern.finditer(line)
    )


def apply_policy_waivers(violations: list[Violation], waivers: list[dict[str, Any]], root: Path) -> None:
    """Mark findings covered by an exact policy waiver (path + rule [+ match]) as waived."""
    for violation in violations:
        if violation.waiver_reason is not None:
            continue
        try:
            rel = Path(violation.file_path).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = violation.file_path
        for waiver in waivers:
            if (waiver["path"] == rel and waiver["rule"] == violation.rule_id
                    and waiver.get("match", "") in violation.message):
                violation.waiver_reason = waiver["reason"]
                break


def apply_policy_rules(violations: list[Violation], rules: dict[str, Any]) -> list[Violation]:
    """Apply a repository policy's per-rule ``enabled`` and ``severity``."""
    kept: list[Violation] = []
    for violation in violations:
        config = rules.get(violation.rule_id)
        if isinstance(config, dict):
            if config.get("enabled") is False:
                continue
            if config.get("severity") in ALLOWED_SEVERITIES:
                violation.severity = config["severity"]
        kept.append(violation)
    return kept


# Line rules (005/006/009/011) are language-neutral; AST rules stay Python-only.
SCANNED_SUFFIXES = frozenset({
    ".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".sh", ".yaml", ".yml",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".oql", ".toml", ".conf", ".ini",
    ".service", ".container",
})
_SLASH_COMMENT_SUFFIXES = frozenset({".c", ".h", ".cc", ".cpp", ".hpp", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


def is_scanned_file(name: str) -> bool:
    return (
        Path(name).suffix.lower() in SCANNED_SUFFIXES
        or name.startswith(".env")
        or name.startswith("Dockerfile")
    )


def _is_comment(line: str, path: Path) -> bool:
    stripped = line.strip()
    if path.suffix.lower() in _SLASH_COMMENT_SUFFIXES:
        # In C, `#define` and `#include` are code, not comments.
        return stripped.startswith(("//", "/*", "*"))
    return stripped.startswith("#")


def scan_file_content(
    path: Path, content: str, profile: str = "balanced", role_path: Optional[str] = None
) -> list[Violation]:
    violations: list[Violation] = []
    lines = content.splitlines()

    # Regex line scanning
    for idx, line in enumerate(lines, start=1):
        # NOHARDCODE-005: Secrets
        m_secret = RE_PLAINTEXT_SECRET.search(line)
        if m_secret:
            val = m_secret.group(2)
            # Exclude known mock strings
            if not any(k in val.lower() for k in ("dummy", "example", "mock", "placeholder", "test", "todo")):
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-005",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile in {"strict", "balanced"} else "warning",
                        message=f"Potential plaintext credential detected: '{m_secret.group(1)}'",
                        replacement="AES-256-GCM authenticated envelope (wellmanifest/secrets)",
                    )
                )
        elif not _is_comment(line, path):
            m_tok = RE_BEARER_OR_TOKEN_LITERAL.search(line)
            if m_tok and not any(k in m_tok.group(0).lower() for k in ("dummy", "example", "mock", "placeholder", "test")):
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-005",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile in {"strict", "balanced"} else "warning",
                        message="Potential plaintext API/bearer token literal detected",
                        replacement="AES-256-GCM authenticated envelope (wellmanifest/secrets)",
                    )
                )

        # NOHARDCODE-002 (non-Python line rule): Hardcoded pixel coordinates
        if path.suffix.lower() != ".py" and not _is_comment(line, path):
            m_coord = RE_HARDCODED_COORDINATES.search(line)
            if m_coord:
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-002",
                        file_path=str(path),
                        line_number=idx,
                        severity="warning" if profile != "strict" else "error",
                        message=f"Hardcoded pixel coordinates ({m_coord.group(2)}, {m_coord.group(3)}) in {m_coord.group(1)}()",
                        replacement="YOLO element detection (twinerd-vision) or Tesseract OCR bounding box",
                    )
                )

        # NOHARDCODE-006: Hardcoded localhost ports
        m_port = RE_HARDCODED_PORT.search(line) or RE_PRIVATE_HOST.search(line)
        # A .env file is the env-dsl configuration itself: a loopback default
        # there is configuration. Private LAN hosts still pin rig topology.
        if path.name.startswith(".env") and RE_ENV_ASSIGNMENT.match(line):
            m_port = RE_PRIVATE_HOST.search(line)
        if m_port and _inside_env_default(line, m_port.start()):
            m_port = None
        if m_port and not _is_comment(line, path):
            violations.append(
                Violation(
                    rule_id="NOHARDCODE-006",
                    file_path=str(path),
                    line_number=idx,
                    severity="error" if profile in {"strict", "balanced"} else "warning",
                    message=f"Hardcoded network endpoint/port: '{m_port.group(0)}'",
                    replacement="Environment variable configuration (wellmanifest/env-dsl)",
                )
            )

        # NOHARDCODE-009: Hardcoded user paths
        m_home = RE_HARDCODED_HOME.search(line)
        if m_home and not _is_comment(line, path):
            violations.append(
                Violation(
                    rule_id="NOHARDCODE-009",
                    file_path=str(path),
                    line_number=idx,
                    severity="error" if profile in {"strict", "balanced"} else "warning",
                    message=f"Hardcoded user home path: '{m_home.group(1)}'",
                    replacement="Path.home(), XDG paths, or runtime lease (wellmanifest/account-runtime)",
                )
            )

        # NOHARDCODE-011: Hardcoded static sleep delays
        is_test_or_fixture = is_test_or_fixture_path(str(path) if role_path is None else role_path)
        if not is_test_or_fixture and not _is_comment(line, path):
            # NOHARDCODE-003: Brittle positional XPath/CSS UI selectors
            m_sel = RE_BRITTLE_UI_SELECTOR.search(line)
            if m_sel:
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-003",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile == "strict" else "warning",
                        message=f"Brittle positional UI selector '{m_sel.group(0)}'",
                        replacement="Tesseract OCR text localization or semantic accessibility label",
                    )
                )

            # NOHARDCODE-008: Hardcoded PII email literals outside anonymized domains
            if path.name not in {"pyproject.toml", "package.json", "Cargo.toml"}:
                for m_email in RE_HARDCODED_PII_EMAIL.finditer(line):
                    domain = m_email.group(2).lower()
                    if (domain not in SAFE_EMAIL_DOMAINS
                            and not domain.endswith(".example.com")
                            and not any(domain.endswith(tld) for tld in SAFE_EMAIL_TLDS)):
                        violations.append(
                            Violation(
                                rule_id="NOHARDCODE-008",
                                file_path=str(path),
                                line_number=idx,
                                severity="error" if profile == "strict" else "warning",
                                message=f"Hardcoded email identifier '{m_email.group(1)}' outside anonymized domain",
                                replacement="Synthetic anonymized fixture or environment identity (wellmanifest/anonym)",
                            )
                        )
                        break

            # NOHARDCODE-016: Regex suffix-stripping stemmer
            if RE_REGEX_STEMMER.search(line):
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-016",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile == "strict" else "warning",
                        message="Hardcoded regex suffix-stripping stemmer indicates brittle inflection heuristic",
                        replacement="Bounded Levenshtein / phonetic matcher or semantic router (wellmanifest/nl-dsl-llm)",
                    )
                )

            m_sleep = RE_HARDCODED_SLEEP.search(line)
            if m_sleep:
                dur = float(m_sleep.group(1))
                if dur >= 2.0:
                    violations.append(
                        Violation(
                            rule_id="NOHARDCODE-011",
                            file_path=str(path),
                            line_number=idx,
                            severity="error" if profile == "strict" else "warning",
                            message=f"Hardcoded sleep delay of {dur}s indicates brittle procedural timing",
                            replacement="Adaptive latency backoff (EWMA/jitter) or event-driven completion wait",
                        )
                    )

        # NOHARDCODE-013: Hardcoded model/provider bindings
        if not is_test_or_fixture and not _is_comment(line, path):
            m_model = RE_HARDCODED_MODEL.search(line)
            if m_model and not _inside_env_default(line, m_model.start(1)):
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-013",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile in {"strict", "balanced"} else "warning",
                        message=f"Hardcoded AI model binding: '{m_model.group(1)}'",
                        replacement="Capability-based Model Router with fallback chain (wellmanifest/nl-dsl-llm)",
                    )
                )

        # NOHARDCODE-015: Hardcoded display or hardware accelerators
        if not is_test_or_fixture and not _is_comment(line, path):
            m_disp = RE_HARDCODED_DISPLAY.search(line)
            if m_disp:
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-015",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile in {"strict", "balanced"} else "warning",
                        message=f"Hardcoded display identifier: '{m_disp.group(0)}'",
                        replacement="Dynamic display socket probing and viewport auto-scaling",
                    )
                )
            m_cuda = RE_HARDCODED_CUDA.search(line)
            if m_cuda:
                violations.append(
                    Violation(
                        rule_id="NOHARDCODE-015",
                        file_path=str(path),
                        line_number=idx,
                        severity="error" if profile in {"strict", "balanced"} else "warning",
                        message=f"Hardcoded CUDA device target: '{m_cuda.group(0)}'",
                        replacement="Hardware capability discovery (torch.cuda.is_available() probe)",
                    )
                )

    # AST scanning for Python files
    if path.suffix == ".py":
        try:
            tree = ast.parse(content, filename=str(path))
            visitor = CodeSmellVisitor(str(path), profile=profile, role_path=role_path)
            visitor.visit(tree)
            violations.extend(visitor.violations)
        except SyntaxError:
            pass

    for violation in violations:
        if 1 <= violation.line_number <= len(lines):
            waiver = RE_WAIVER.search(lines[violation.line_number - 1])
            # Formats without trailing comments (Dockerfile) waive on the
            # comment-only line directly above the finding.
            if not waiver and violation.line_number >= 2:
                above = lines[violation.line_number - 2]
                if _is_comment(above, path):
                    waiver = RE_WAIVER.search(above)
            if waiver and waiver.group(1) == violation.rule_id:
                violation.waiver_reason = waiver.group(2)
    return violations


def is_excluded(rel_path: str, exclusions: list[str]) -> bool:
    for pat in exclusions:
        clean = pat.strip()
        if not clean:
            continue
        if clean.endswith("/**"):
            prefix = clean[:-3]
            if rel_path == prefix or rel_path.startswith(prefix + "/"):
                return True
        elif fnmatch.fnmatch(rel_path, clean) or fnmatch.fnmatch(Path(rel_path).name, clean):
            return True
        elif clean in rel_path:
            return True
    return False


def audit_repository(
    target_dir: Path,
    profile: str = "balanced",
    exclusions: Optional[list[str]] = None,
    coverage: Optional[dict[str, int]] = None,
) -> list[Violation]:
    """Audit ``target_dir``; ``coverage`` (if given) receives file counts."""
    all_violations: list[Violation] = []
    counts = coverage if coverage is not None else {}
    for key in ("scanned", "excluded_by_policy", "unsupported"):
        counts[key] = 0
    # An explicit empty list requests a full scan; only an absent policy
    # value falls back to the defaults.
    excl = exclusions if exclusions is not None else [
        ".git/**",
        "venv/**",
        ".venv/**",
        "node_modules/**",
        "__pycache__/**",
        "fixtures/**",
        "tests/fixtures/**",
        "docs/**",
    ]

    env_endpoint_sources: dict[str, tuple[str, int]] = {}
    for root, dirs, files in os.walk(target_dir):
        # Prune excluded directories in-place before traversing
        kept = []
        for d in sorted(dirs):
            if (d.startswith(".") and d != ".") or d in {"node_modules", "venv", ".venv", "__pycache__", "dist", "build"}:
                continue
            if is_excluded(str((Path(root) / d).relative_to(target_dir)), excl):
                counts["excluded_by_policy"] += sum(
                    1 for _r, _d, fs in os.walk(Path(root) / d) for f in fs if is_scanned_file(f)
                )
                continue
            kept.append(d)
        dirs[:] = kept

        for file_name in sorted(files):
            p = Path(root) / file_name
            rel = str(p.relative_to(target_dir))
            if not is_scanned_file(file_name):
                counts["unsupported"] += 1
                continue
            if is_excluded(rel, excl):
                counts["excluded_by_policy"] += 1
                continue
            counts["scanned"] += 1
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                all_violations.extend(scan_file_content(p, content, profile=profile, role_path=rel))
                if not is_test_or_fixture_path(rel):
                    for idx, line in enumerate(content.splitlines(), start=1):
                        if _is_comment(line, p):
                            continue
                        for pat in ENV_DEFAULT_PATTERNS:
                            for m_env in pat.finditer(line):
                                default_val = m_env.group("default").strip("\"'`")
                                if RE_HARDCODED_PORT.search(default_val) or RE_PRIVATE_HOST.search(default_val):
                                    prev = env_endpoint_sources.get(default_val)
                                    if prev is not None and prev[0] != rel:
                                        all_violations.append(
                                            Violation(
                                                rule_id="NOHARDCODE-010",
                                                file_path=str(p),
                                                line_number=idx,
                                                severity="error" if profile == "strict" else "warning",
                                                message=f"Duplicate environment endpoint default '{default_val}' across files (already defined in {prev[0]}:{prev[1]})",
                                                replacement="Single configuration source binding (wellmanifest/ssot SSOT-CONFIG-001)",
                                            )
                                        )
                                    elif prev is None:
                                        env_endpoint_sources[default_val] = (rel, idx)
            except Exception:
                pass

    return all_violations


def main() -> int:
    parser = argparse.ArgumentParser(description=f"Wellmanifest No-Hardcode Conformance Checker v{VERSION}")
    parser.add_argument("--target", type=str, default=".", help="Target repository directory to audit")
    parser.add_argument("--policy", type=str, help="Path to nohardcode-policy.json")
    parser.add_argument("--profile", type=str, choices=sorted(ALLOWED_PROFILES), default="balanced")
    parser.add_argument("--format", type=str, choices=["text", "json"], default="text")
    args = parser.parse_args()

    policy_profile = args.profile
    exclusions = None
    target_path = Path(args.target).resolve()
    policy_path = Path(args.policy) if args.policy else (target_path / "nohardcode-policy.json")
    if not args.policy and not policy_path.exists():
        alt_paths = [
            target_path / ".governance" / "nohardcode-policy.json",
            target_path / ".governance" / "wellmanifest" / "nohardcode" / "nohardcode-policy.json",
        ]
        for alt in alt_paths:
            if alt.exists():
                policy_path = alt
                break

    policy_rules: dict[str, Any] = {}
    policy_waivers: list[dict[str, Any]] = []
    if policy_path.exists():
        try:
            p_data = json.loads(policy_path.read_text(encoding="utf-8"))
            validate_policy_document(p_data)
            policy_profile = p_data.get("profile", policy_profile)
            exclusions = p_data.get("exclusions")
            policy_rules = p_data.get("rules") or {}
            policy_waivers = p_data.get("waivers") or []
        except ConformanceError as ce:
            print(f"Policy validation failed: {ce}", file=sys.stderr)
            return 1
        except Exception as ex:
            print(f"Error parsing policy: {ex}", file=sys.stderr)
            return 2
    elif args.policy:
        print(f"Error: Policy file not found: {policy_path}", file=sys.stderr)
        return 2

    coverage: dict[str, int] = {}
    violations = apply_policy_rules(
        audit_repository(target_path, profile=policy_profile, exclusions=exclusions, coverage=coverage),
        policy_rules,
    )
    apply_policy_waivers(violations, policy_waivers, target_path)
    if policy_path.exists():
        # The policy is the waiver registry; its own match strings are not findings.
        violations = [v for v in violations if Path(v.file_path).resolve() != policy_path.resolve()]

    blocking_errors = [v for v in violations if v.severity == "error" and v.waiver_reason is None]

    if args.format == "json":
        out = {
            "version": VERSION,
            "profile": policy_profile,
            "target": str(target_path),
            "summary": {
                "total_violations": len(violations),
                "errors": len(blocking_errors),
                "warnings": len([v for v in violations if v.severity == "warning"]),
                "waived": len([v for v in violations if v.waiver_reason is not None]),
                "coverage": coverage,
            },
            "violations": [v.to_dict() for v in violations],
        }
        print(json.dumps(out, indent=2))
    else:
        print(f"=== Wellmanifest No-Hardcode Audit: {target_path.name} (Profile: {policy_profile}) ===")
        if not violations:
            print("✓ No hardcoded anti-patterns found. GOV-PASS.")
        else:
            for v in violations:
                print(f"  {v}")
            print("----------------------------------------------------------------------")
            print(f"Audit completed: {len(violations)} finding(s) ({len(blocking_errors)} blocking errors).")
        print(
            f"Coverage: {coverage['scanned']} file(s) scanned, "
            f"{coverage['excluded_by_policy']} excluded by policy, "
            f"{coverage['unsupported']} unsupported."
        )

    return 1 if blocking_errors else 0


if __name__ == "__main__":
    sys.exit(main())
