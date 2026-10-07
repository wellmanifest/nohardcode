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
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

VERSION = "0.1.0-dev"

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
})

# Built-in Detection Regexes
RE_PLAINTEXT_SECRET = re.compile(
    r'(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|private[_-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/]{16,})["\']'
)
RE_HARDCODED_PORT = re.compile(
    r'(https?://|ws://|tcp://)?(localhost|127\.0\.0\.1|0\.0\.0\.0):([0-9]{2,5})'
)
RE_HARDCODED_HOME = re.compile(
    r'["\'](/home/[a-zA-Z0-9._-]+|[A-Z]:\\[Uu]sers\\[a-zA-Z0-9._-]+)'
)
RE_HARDCODED_COORDINATES = re.compile(
    r'\b(click|moveTo|mouse_down|mouse_up|dragTo)\s*\(\s*(\d{2,4})\s*,\s*(\d{2,4})\s*\)'
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity,
            "message": self.message,
            "recommended_replacement": self.replacement,
        }

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


class CodeSmellVisitor(ast.NodeVisitor):
    """AST Visitor detecting hardcoded anti-patterns in Python source files."""

    def __init__(self, filename: str, profile: str = "balanced") -> None:
        self.filename = filename
        self.profile = profile
        self.violations: list[Violation] = []

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
        # Check depth of elif chains (NOHARDCODE-004: Declarative Business Logic)
        depth = 0
        curr: Optional[ast.AST] = node
        while curr and isinstance(curr, ast.If):
            depth += 1
            if curr.orelse and len(curr.orelse) == 1 and isinstance(curr.orelse[0], ast.If):
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

    def visit_Call(self, node: ast.Call) -> None:
        # Check for raw print() calls (NOHARDCODE-007)
        # Exclude CLI tools, scripts, and test runners where print is standard CLI output
        is_cli_or_test = any(marker in self.filename.lower() for marker in ("check", "conformance", "cli", "test", "benchmark", "scripts/"))
        if not is_cli_or_test and isinstance(node.func, ast.Name) and node.func.id == "print":
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

        # Check for coordinate click calls
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"click", "moveTo", "dragTo"}:
            if len(node.args) >= 2 and all(isinstance(a, ast.Constant) and isinstance(a.value, int) for a in node.args[:2]):
                severity = "warning" if self.profile != "strict" else "error"
                self.violations.append(
                    Violation(
                        rule_id="NOHARDCODE-002",
                        file_path=self.filename,
                        line_number=node.lineno,
                        severity=severity,
                        message=f"Hardcoded pixel coordinates ({node.args[0].value}, {node.args[1].value}) in {node.func.attr}()",
                        replacement="YOLO element detection (twinerd-vision) or Tesseract OCR bounding box",
                    )
                )

        self.generic_visit(node)


def scan_file_content(path: Path, content: str, profile: str = "balanced") -> list[Violation]:
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

        # NOHARDCODE-006: Hardcoded localhost ports
        m_port = RE_HARDCODED_PORT.search(line)
        if m_port and not line.strip().startswith("#"):
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
        if m_home and not line.strip().startswith("#"):
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

    # AST scanning for Python files
    if path.suffix == ".py":
        try:
            tree = ast.parse(content, filename=str(path))
            visitor = CodeSmellVisitor(str(path), profile=profile)
            visitor.visit(tree)
            violations.extend(visitor.violations)
        except SyntaxError:
            pass

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
) -> list[Violation]:
    all_violations: list[Violation] = []
    excl = exclusions or [
        ".git/**",
        "venv/**",
        ".venv/**",
        "node_modules/**",
        "__pycache__/**",
        "fixtures/**",
        "tests/fixtures/**",
        "docs/**",
    ]

    for p in target_dir.rglob("*"):
        if not p.is_file():
            continue
        rel = str(p.relative_to(target_dir))
        if is_excluded(rel, excl):
            continue
        if p.suffix in {".py", ".ts", ".js", ".json", ".sh", ".yaml", ".yml"}:
            try:
                content = p.read_text(encoding="utf-8", errors="replace")
                v = scan_file_content(p, content, profile=profile)
                all_violations.extend(v)
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
    target_path = Path(args.target).resolve()
    policy_path = Path(args.policy) if args.policy else (target_path / "nohardcode-policy.json")

    if policy_path.exists():
        try:
            p_data = json.loads(policy_path.read_text(encoding="utf-8"))
            validate_policy_document(p_data)
            policy_profile = p_data.get("profile", policy_profile)
            exclusions = p_data.get("exclusions")
        except ConformanceError as ce:
            print(f"Policy validation failed: {ce}", file=sys.stderr)
            return 1
        except Exception as ex:
            print(f"Error parsing policy: {ex}", file=sys.stderr)
            return 2
    elif args.policy:
        print(f"Error: Policy file not found: {policy_path}", file=sys.stderr)
        return 2

    violations = audit_repository(target_path, profile=policy_profile, exclusions=exclusions)

    blocking_errors = [v for v in violations if v.severity == "error"]

    if args.format == "json":
        out = {
            "version": VERSION,
            "profile": policy_profile,
            "target": str(target_path),
            "summary": {
                "total_violations": len(violations),
                "errors": len(blocking_errors),
                "warnings": len([v for v in violations if v.severity == "warning"]),
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

    return 1 if blocking_errors else 0


if __name__ == "__main__":
    sys.exit(main())
