#!/usr/bin/env python3
"""
Dependency-free conformance checker for wellmanifest/nohardcode v0.1.0-dev.
Validates schemas, manifests, documentation, valid/invalid fixtures, and AST scanner.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from nohardcode_check import (
    ConformanceError,
    scan_file_content,
    validate_detection_rule_document,
    validate_policy_document,
)

ROOT = Path(__file__).resolve().parent
PACK = ROOT.parent

REQUIRED_DOCS = (
    PACK / "README.md",
    PACK / "AGENTS.md",
    PACK / "GEMINI.md",
    PACK / "VERSION",
    PACK / "dsl-manifest.json",
    PACK / "docs/SPEC.md",
    PACK / "docs/ARCHITECTURE.md",
    PACK / "docs/ADOPTION_GUIDE.md",
    PACK / "docs/TAXONOMY_AND_USE_CASES.md",
    PACK / "schemas/nohardcode-policy.schema.json",
    PACK / "schemas/detection-rule.schema.json",
)

VALID_FIXTURES = (
    ROOT / "fixtures/valid/policy.json",
    ROOT / "fixtures/valid/detection-rule.json",
)

INVALID_FIXTURES = {
    ROOT / "fixtures/invalid/policy-invalid-schema.json": "NOHARDCODE_POLICY_INVALID",
    ROOT / "fixtures/invalid/policy-invalid-profile.json": "NOHARDCODE_PROFILE_INVALID",
    ROOT / "fixtures/invalid/detection-rule-invalid-id.json": "DETECTION_RULE_ID_INVALID",
    ROOT / "fixtures/invalid/detection-rule-invalid-category.json": "DETECTION_RULE_CATEGORY_INVALID",
}


def load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as error:
        raise ConformanceError("PARSE_ERROR", f"Invalid JSON in {path.name}: {error}") from error
    if not isinstance(data, dict):
        raise ConformanceError("PARSE_ERROR", f"Expected JSON object in {path.name}")
    return data


def validate_fixture(path: Path) -> None:
    data = load_json(path)
    if "rule_id" in data:
        validate_detection_rule_document(data)
    else:
        validate_policy_document(data)


def test_code_smell_scanner() -> None:
    # Test synthetic snippet with violations
    smelly_code = """
import pyautogui
import time

KEYWORDS = ["uruchom", "włącz", "graj", "otwórz", "startuj", "odtwarzaj"]

def bad_worker():
    api_key = "abcdef1234567890abcdef1234567890"
    pyautogui.click(500, 200)
    print("starting worker on localhost:7070")
    home_dir = "/home/tom/data"
    time.sleep(10)
    model = "gpt-4"
    device = "cuda:0"
"""
    violations = scan_file_content(Path("worker_service.py"), smelly_code, profile="strict")
    rule_ids = {v.rule_id for v in violations}

    expected_rules = {
        "NOHARDCODE-001",
        "NOHARDCODE-002",
        "NOHARDCODE-005",
        "NOHARDCODE-006",
        "NOHARDCODE-007",
        "NOHARDCODE-009",
        "NOHARDCODE-011",
        "NOHARDCODE-013",
        "NOHARDCODE-015",
    }
    missing = expected_rules - rule_ids
    if missing:
        raise ConformanceError("SCANNER_FAILURE", f"AST scanner missed expected rules: {missing}")

    # The env-dsl remediation must not be reported as the smell it replaces.
    env_code = """
import os
HOST = os.getenv("WILLMUX_HOST", "127.0.0.1:7070")
OLLAMA = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("API_URL", "localhost:8080")
BAD = "http://localhost:8080/api"
MIXED = os.getenv("PORT", "8080") or "localhost:9090"
"""
    flagged = sorted(
        v.line_number for v in scan_file_content(Path("svc.py"), env_code)
        if v.rule_id == "NOHARDCODE-006"
    )
    if flagged != [6, 7]:
        raise ConformanceError(
            "SCANNER_FAILURE",
            f"NOHARDCODE-006 must skip env-lookup defaults only; flagged lines {flagged}",
        )



def test_conditional_chain_findings_are_distinct() -> None:
    """Only chain heads report; nested and adjacent chains remain independent."""
    def chain(length: int, indent: str = "") -> str:
        return "".join(
            f"{indent}{'if' if index == 0 else 'elif'} flag == {index}:\n{indent}    pass\n"
            for index in range(length)
        )

    def findings(code: str, profile: str = "balanced") -> list:
        return [v for v in scan_file_content(Path("business_rules.py"), code, profile=profile)
                if v.rule_id == "NOHARDCODE-004"]

    for profile in ("balanced", "strict", "permissive"):
        for length in (4, 5, 8):
            found = findings(chain(length), profile)
            expected = [] if length == 4 else [1]
            if [v.line_number for v in found] != expected:
                raise ConformanceError("SCANNER_FAILURE", f"duplicate chain findings: {profile}/{length}: {found}")
            for violation in found:
                severity = "error" if profile == "strict" else "warning"
                if violation.severity != severity or f"({length} branches)" not in violation.message:
                    raise ConformanceError("SCANNER_FAILURE", "conditional chain severity or depth changed")

    first = chain(6)
    adjacent = first + "\n" + chain(5)
    if [v.line_number for v in findings(adjacent)] != [1, len(first.splitlines()) + 2]:
        raise ConformanceError("SCANNER_FAILURE", "adjacent independent chains were merged")
    nested = first.replace("    pass\n", chain(6, "    "), 1)
    if [v.line_number for v in findings(nested)] != [1, 2]:
        raise ConformanceError("SCANNER_FAILURE", "nested independent chain was suppressed")
    prefix, _ = chain(5).rsplit("    pass\n", 1)
    nested_in_elif = prefix + chain(6, "    ")
    if [v.line_number for v in findings(nested_in_elif)] != [1, len(prefix.splitlines()) + 1]:
        raise ConformanceError("SCANNER_FAILURE", "nested chain inside elif body was suppressed")


def test_direct_subprocess_argv_context() -> None:
    """Only direct argv of an unshadowed stdlib subprocess import is technical."""
    argv = '["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", target, "echo ok"]'
    positive = [
        f"import subprocess\nsubprocess.{api}({argv})\n"
        for api in ("run", "Popen", "call", "check_call", "check_output")
    ] + [
        f"import subprocess as sp\nsp.run(args={argv})\n",
        f"from subprocess import run as launch\nlaunch({argv})\n",
        f"import subprocess\nsubprocess.run({argv.replace('[', '(', 1).replace(']', ')')})\n",
    ]
    negative = [
        f"subprocess.run({argv})\n",  # no verified import
        f"import other as subprocess\nsubprocess.run({argv})\n",
        f"from other import run\nrun({argv})\n",
        f"import subprocess\ndef f(subprocess):\n    subprocess.run({argv})\n",
        f"from subprocess import run\nrun = router\nrun({argv})\n",
        f"import subprocess\nsubprocess.run = router\nsubprocess.run({argv})\n",
        f"import subprocess\nsubprocess.run(None, vocabulary={argv})\n",
        f"import subprocess\nsubprocess.unknown({argv})\n",
        f"import subprocess\nKEYWORDS = {argv}\n",
        f"import subprocess\nfrom unknown import *\nsubprocess.run({argv})\n",
        f"import subprocess\ntry:\n    pass\nexcept Exception as subprocess:\n    pass\nsubprocess.run({argv})\n",
        f"import subprocess\nmatch value:\n    case subprocess:\n        subprocess.run({argv})\n",
        f"import subprocess\ndef subprocess():\n    pass\nsubprocess.run({argv})\n",
        f"def f():\n    import subprocess\n    subprocess.run({argv})\n",
        f"import subprocess as sp\nsp = router\nsp.run({argv})\n",
        f"import subprocess\nsubprocess.run({argv.replace('[', '{', 1).replace(']', '}')})\n",
    ]
    for profile in ("balanced", "strict", "permissive"):
        for expected, cases in ((0, positive), (1, negative)):
            for code in cases:
                found = [v for v in scan_file_content(Path("worker.py"), code, profile=profile)
                         if v.rule_id == "NOHARDCODE-001"]
                if len(found) != expected:
                    raise ConformanceError("SCANNER_FAILURE", f"argv context {profile}: expected {expected}, got {len(found)}: {code}")
                if found and found[0].severity != ("error" if profile == "strict" else "warning"):
                    raise ConformanceError("SCANNER_FAILURE", "NL dispatch severity changed")

    # A technical argv context must retain line rules and nested NL collections.
    code = '''import subprocess
subprocess.run(["tool", "--start", "-a", "-b", "-c", "echo ok",
    "http://localhost:8080",
    'api_key="Abcdef1234567890Abcdef1234567890"',
    ["open one", "open two", "open three", "open four", "open five", "open six"]])
'''
    rules = [v.rule_id for v in scan_file_content(Path("worker.py"), code, profile="strict")]
    if sorted(rules) != ["NOHARDCODE-001", "NOHARDCODE-005", "NOHARDCODE-006"]:
        raise ConformanceError("SCANNER_FAILURE", f"argv hid unrelated findings: {rules}")

    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for source, expected_exit, expected_rules in (
            (positive[0], 0, []), (negative[0], 1, ["NOHARDCODE-001"]),
            (code, 1, ["NOHARDCODE-001", "NOHARDCODE-005", "NOHARDCODE-006"]),
        ):
            (root / "worker.py").write_text(source, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(PACK / "standard/nohardcode_check.py"),
                 "--target", str(root), "--profile", "strict", "--format", "json"],
                capture_output=True, text=True, check=False,
            )
            found = json.loads(result.stdout)["violations"]
            if (result.returncode != expected_exit
                    or sorted(v["rule_id"] for v in found) != expected_rules
                    or any(v["severity"] != "error" for v in found)):
                raise ConformanceError("SCANNER_FAILURE", "strict CLI argv/intent blocking contract changed")


def test_adjacent_assigned_subprocess_argv_context() -> None:
    argv = '["docker", "exec", "-i", "db", "psql", "-v", "ON_ERROR_STOP=1"]'
    positive = [
        f"import subprocess\ncmd = {argv}\nsubprocess.run(cmd)\n",
        f"import subprocess\ndef f():\n    if ready:\n        cmd = {argv}\n        p = subprocess.Popen(cmd, stdout=subprocess.PIPE)\n",
        f"from subprocess import run as launch\ncmd = {argv}\np = launch(args=cmd)\n",
        f"import subprocess\ncmd = {argv.replace('[', '(', 1).replace(']', ')')}\nsubprocess.run(cmd)\n",
    ]
    negative = [
        f"cmd = {argv}\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\nother(cmd)\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\nsubprocess.run(cmd)\nother(cmd)\n",
        f"import subprocess\ncmd = {argv}\ncmd.append('help')\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\ncmd = external\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = alias = {argv}\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\nif ready:\n    subprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\npass\nsubprocess.run(cmd)\n",
        f"import subprocess\ncmd = {argv}\nrouter(cmd)\n",
        f"import subprocess\ncmd = {argv}\nsubprocess.run(None, vocabulary=cmd)\n",
        f"import subprocess\ncmd = {argv}\nsubprocess.run(cmd, env=mutate(cmd))\n",
        f"import subprocess\ncmd = {argv}\nsubprocess.run(cmd)\ndef nested():\n    return cmd\n",
        f"import subprocess\ndef f():\n    global cmd\n    cmd = {argv}\n    subprocess.run(cmd)\n",
        f"import subprocess\ndef f(cmd):\n    cmd = {argv}\n    subprocess.run(cmd)\n",
        f"import subprocess\nif ready:\n    cmd = {argv}\n    subprocess.run(cmd)\nelse:\n    cmd = []\n",
    ]
    for profile in ("balanced", "strict", "permissive"):
        for expected, cases in ((0, positive), (1, negative)):
            for code in cases:
                found = [v for v in scan_file_content(Path("worker.py"), code, profile=profile)
                         if v.rule_id == "NOHARDCODE-001"]
                if len(found) != expected:
                    raise ConformanceError("SCANNER_FAILURE", f"assigned argv {profile}: expected {expected}, got {len(found)}: {code}")
                if found and found[0].severity != ("error" if profile == "strict" else "warning"):
                    raise ConformanceError("SCANNER_FAILURE", "assigned argv NL severity changed")

    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for code, expected_exit, expected_rules in (
            (positive[0], 0, []),
            (negative[2], 1, ["NOHARDCODE-001"]),
            (positive[0].replace('"ON_ERROR_STOP=1"', '"http://localhost:8080"'),
             1, ["NOHARDCODE-006"]),
            (positive[0].replace('"ON_ERROR_STOP=1"', '\'api_key="Abcdef1234567890Abcdef1234567890"\''),
             1, ["NOHARDCODE-005"]),
        ):
            (root / "worker.py").write_text(code, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(PACK / "standard/nohardcode_check.py"),
                 "--target", str(root), "--profile", "strict", "--format", "json"],
                capture_output=True, text=True, check=False,
            )
            found = json.loads(result.stdout)["violations"]
            if (result.returncode != expected_exit
                    or sorted(v["rule_id"] for v in found) != expected_rules
                    or any(v["severity"] != "error" for v in found)):
                raise ConformanceError("SCANNER_FAILURE", "assigned argv strict CLI changed blocking of unrelated rules or NL reuse")


def test_policy_rules_are_applied() -> None:
    """Per-rule enabled/severity in a repository policy must change the result."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "app.py").write_text('print("x")\nURL = "http://localhost:8080"\n', encoding="utf-8")
        policy = load_json(PACK / "nohardcode-policy.json")
        policy["rules"]["NOHARDCODE-006"] = {"enabled": False, "severity": "error"}
        policy["rules"]["NOHARDCODE-007"] = {"enabled": True, "severity": "warning"}
        (root / "nohardcode-policy.json").write_text(json.dumps(policy), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(PACK / "standard" / "nohardcode_check.py"),
             "--target", str(root), "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        found = {(v["rule_id"], v["severity"]) for v in json.loads(result.stdout)["violations"]}
        if found != {("NOHARDCODE-007", "warning")} or result.returncode != 0:
            raise ConformanceError(
                "POLICY_RULES_IGNORED",
                f"repository policy rules not applied: {sorted(found)} rc={result.returncode}",
            )


def test_inline_waiver() -> None:
    """A reasoned waiver for the matching rule keeps the finding but unblocks it."""
    code = (
        'A = "localhost:8080"  # nohardcode: allow NOHARDCODE-006 -- default for API_URL env lookup\n'
        'B = "localhost:8081"  # nohardcode: allow NOHARDCODE-006\n'
        'C = "localhost:8082"  # nohardcode: allow NOHARDCODE-009 -- wrong rule\n'
    )
    found = {v.line_number: v.waiver_reason for v in scan_file_content(Path("cfg.py"), code)
             if v.rule_id == "NOHARDCODE-006"}
    if found != {1: "default for API_URL env lookup", 2: None, 3: None}:
        raise ConformanceError("WAIVER_FAILURE", f"unexpected waivers: {found}")


def test_waiver_above_finding() -> None:
    """Dockerfile has no trailing comments: a comment-only line directly above waives."""
    code = (
        "# nohardcode: allow NOHARDCODE-006 -- container probes its own port\n"
        "HEALTHCHECK CMD curl -f http://127.0.0.1:8080/health\n"
        "RUN echo http://127.0.0.1:9000\n"
        "# nohardcode: allow NOHARDCODE-006 -- not directly above\n"
        "\n"
        "RUN echo http://127.0.0.1:9001\n"
    )
    found = {v.line_number: v.waiver_reason for v in scan_file_content(Path("Dockerfile"), code)
             if v.rule_id == "NOHARDCODE-006"}
    if found != {2: "container probes its own port", 3: None, 6: None}:
        raise ConformanceError("WAIVER_FAILURE", f"unexpected waivers above findings: {found}")


def test_policy_waivers() -> None:
    """Exact path + rule (+ match) waivers cover comment-less formats such as JSON."""
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "cfg").mkdir()
        (root / "cfg" / "ap.json").write_text('{\n  "ap": "192.168.4.1",\n  "peer": "192.168.1.20"\n}\n', encoding="utf-8")
        (root / "other.json").write_text('{"ap": "192.168.4.1"}\n', encoding="utf-8")
        policy = load_json(PACK / "nohardcode-policy.json")
        policy["waivers"] = [{"path": "cfg/ap.json", "rule": "NOHARDCODE-006", "match": "192.168.4.1",
                              "reason": "device SoftAP's own address"}]
        (root / "nohardcode-policy.json").write_text(json.dumps(policy), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(PACK / "standard" / "nohardcode_check.py"),
             "--target", str(root), "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        out = json.loads(result.stdout)
        waived = {(Path(v["file_path"]).name, v["line_number"], v.get("waiver_reason")) for v in out["violations"]}
        expected = {("ap.json", 2, "device SoftAP's own address"), ("ap.json", 3, None), ("other.json", 1, None)}
        if waived != expected or out["summary"]["errors"] != 2 or result.returncode != 1:
            raise ConformanceError("POLICY_WAIVER_FAILURE", f"unexpected policy waivers: {sorted(waived, key=str)} rc={result.returncode}")
    for bad in ({"path": "cfg/*.json", "rule": "NOHARDCODE-006", "reason": "x"},
                {"path": "../ap.json", "rule": "NOHARDCODE-006", "reason": "x"},
                {"path": "ap.json", "rule": "NOHARDCODE-006", "reason": " "},
                {"path": "ap.json", "rule": "006", "reason": "x"},
                {"path": "ap.json", "rule": "NOHARDCODE-006", "reason": "x", "scope": "all"}):
        policy = load_json(PACK / "nohardcode-policy.json")
        policy["waivers"] = [bad]
        try:
            validate_policy_document(policy)
        except ConformanceError:
            continue
        raise ConformanceError("POLICY_WAIVER_FAILURE", f"invalid waiver accepted: {bad}")


def test_print_exemption_and_explicit_exclusions() -> None:
    """NOHARDCODE-007 exempts CLI/test files by path component, not substring."""
    import tempfile

    from nohardcode_check import audit_repository

    code = 'print("status")\n'

    def flagged(name: str) -> bool:
        return any(v.rule_id == "NOHARDCODE-007" for v in scan_file_content(Path(name), code))

    production = ["latest.py", "checkout.py", "client.py", "pkg/contest/app.py", "attestation.py"]
    tooling = ["tests/test_app.py", "scripts/run.py", "nohardcode_check.py", "pkg/cli.py",
               "app_test.py", "conftest.py", "pkg/__main__.py", "bin/tool.py", "check-docs.py"]
    wrong = [n for n in production if not flagged(n)] + [n for n in tooling if flagged(n)]
    if wrong:
        raise ConformanceError("SCANNER_FAILURE", f"print() exemption misclassified: {wrong}")
    with tempfile.TemporaryDirectory() as tmp:
        # Directories above the scanned root never classify a file as tooling.
        root = Path(tmp) / "tests" / "repo"
        (root / "docs").mkdir(parents=True)
        (root / "app.py").write_text(code, encoding="utf-8")
        (root / "docs" / "example.py").write_text(code, encoding="utf-8")

        def files(exclusions: object) -> list[str]:
            found = audit_repository(root, exclusions=exclusions)  # type: ignore[arg-type]
            return sorted(str(Path(v.file_path).relative_to(root)) for v in found if v.rule_id == "NOHARDCODE-007")

        if files(None) != ["app.py"]:
            raise ConformanceError("SCANNER_FAILURE", f"default scan wrong: {files(None)}")
        if files([]) != ["app.py", "docs/example.py"]:
            raise ConformanceError("SCANNER_FAILURE", f"explicit empty exclusions must scan everything: {files([])}")


def test_env_defaults_in_js_and_shell() -> None:
    """Env-lookup defaults are the env-dsl remedy in JS/TS and shell too."""
    js = (
        "const a = process.env.BASE_URL || 'http://localhost:8100';\n"   # 1 env default
        "const b = import.meta.env.VITE_API ?? \"http://localhost:8106\";\n"  # 2 env default
        "const c = config().PROTOCOL_URL || `http://localhost:8120/api`;\n"  # 3 config key default
        "const d = res.value.ip || '192.168.1.100';\n"                    # 4 not a config key
        "const e = 'http://localhost:8094/';\n"                           # 5 plain literal
        "const f = process.env.BASE_URL || other || 'http://localhost:1234';\n"  # 6 not the key's default
    )
    hits = [v.line_number for v in scan_file_content(Path("app.ts"), js) if v.rule_id == "NOHARDCODE-006"]
    if hits != [4, 5, 6]:
        raise ConformanceError("SCANNER_FAILURE", f"JS env defaults wrong: {hits}")
    sh = 'BASE="${CONNECT_RUNTIME_URL:-http://localhost:8115}"\nURL="http://localhost:8115"\n'
    hits = [v.line_number for v in scan_file_content(Path("smoke.sh"), sh) if v.rule_id == "NOHARDCODE-006"]
    if hits != [2]:
        raise ConformanceError("SCANNER_FAILURE", f"shell env defaults wrong: {hits}")
    code = "import time\ntime.sleep(5)\n"

    def sleeps(name: str) -> bool:
        return any(v.rule_id == "NOHARDCODE-011" for v in scan_file_content(Path(name), code, role_path=name))

    production = ["latest.py", "contest/app.py", "attestation.py", "mockingbird.py"]
    tooling = ["tests/test_a.py", "app_test.py", "fixtures/load.py", "bench/run.py", "conftest.py"]
    wrong = [n for n in production if not sleeps(n)] + [n for n in tooling if sleeps(n)]
    if wrong:
        raise ConformanceError("SCANNER_FAILURE", f"sleep test exemption misclassified: {wrong}")


def test_env_file_loopback_values() -> None:
    """Loopback defaults in .env files are configuration; LAN hosts are not."""
    env = (
        "API_URL=http://localhost:8100\n"          # 1 loopback default
        "export WS=ws://127.0.0.1:8101\n"          # 2 loopback default
        "STACKNET=192.168.188.229:8080\n"          # 3 rig LAN pin
        "echo http://localhost:8100\n"             # 4 not an assignment
        "BASE_URL = http://localhost:8080\n"       # 5 dotenv with spaces
        "export API = http://127.0.0.1:9000\n"     # 6 dotenv with spaces
    )
    hits = [v.line_number for v in scan_file_content(Path(".env.fleet"), env) if v.rule_id == "NOHARDCODE-006"]
    if hits != [3, 4]:
        raise ConformanceError("SCANNER_FAILURE", f".env loopback/LAN handling wrong: {hits}")
    other = [v.line_number for v in scan_file_content(Path("settings.ini"), env) if v.rule_id == "NOHARDCODE-006"]
    if other != [1, 2, 3, 4, 5, 6]:
        raise ConformanceError("SCANNER_FAILURE", f"only .env files may carry loopback defaults: {other}")


def test_non_python_line_rules_and_coverage() -> None:
    """Line rules run on firmware/config files and coverage is reported."""
    import tempfile

    from nohardcode_check import audit_repository

    c_code = '#define MASKFLEET_URL "http://192.168.188.212:8188"\n// see 127.0.0.1:9000 in docs\n'
    hits = [v.line_number for v in scan_file_content(Path("cfg.h"), c_code) if v.rule_id == "NOHARDCODE-006"]
    if hits != [1]:
        raise ConformanceError("SCANNER_FAILURE", f"C #define must be scanned and // comments skipped: {hits}")
    lan = (
        'A = "192.168.188.224"\n'           # 1 private host
        'B = "10.0.4.7:8080"\n'             # 2 private host with port
        'NET = "192.168.188.0/24"\n'        # network range, not an endpoint
        'BC = "192.168.1.255"\n'            # broadcast
        'PUB = "8.8.8.8"\n'                 # public, out of scope
        'V = "1.192.168.1.5"\n'             # not an address
        'E = os.getenv("H", "192.168.1.9")\n'
    )
    lan_hits = [v.line_number for v in scan_file_content(Path("net.py"), lan) if v.rule_id == "NOHARDCODE-006"]
    if lan_hits != [1, 2]:
        raise ConformanceError("SCANNER_FAILURE", f"private host detection wrong: {lan_hits}")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "main.c").write_text(c_code, encoding="utf-8")
        (root / ".env").write_text("API=http://192.168.1.50:8080\n", encoding="utf-8")
        (root / "tools").mkdir()
        (root / "tools" / "flash.py").write_text('IP = "127.0.0.1:8080"\n', encoding="utf-8")
        (root / "logo.png").write_bytes(b"\x89PNG")
        coverage: dict = {}
        found = audit_repository(root, exclusions=["tools/**"], coverage=coverage)
        files = sorted({Path(v.file_path).name for v in found if v.rule_id == "NOHARDCODE-006"})
        if files != [".env", "main.c"] or coverage != {"scanned": 2, "excluded_by_policy": 1, "unsupported": 1}:
            raise ConformanceError("COVERAGE_FAILURE", f"files={files} coverage={coverage}")


def test_javascript_module_cli_coverage() -> None:
    """Module discovery and comments keep the existing CLI/policy contract."""
    import subprocess
    import tempfile

    for suffix in (".mjs", ".cjs", ".MJS"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            root.mkdir()
            (root / "excluded").mkdir()
            module = root / ("service" + suffix)
            safe = (
                "// Example endpoint: http://localhost:8120\n"
                "/* Example endpoint: http://localhost:8121 */\n"
                "const endpoint = process.env.API_URL || 'http://localhost:8122';\n"
            )
            module.write_text(safe + "const rigid = 'http://localhost:8123';\n", encoding="utf-8")
            (root / "excluded" / ("vendor" + suffix)).write_text(
                "const endpoint = 'http://localhost:8124';\n", encoding="utf-8",
            )
            (root / "opaque.unsupported").write_text("http://localhost:8125\n", encoding="utf-8")
            policy = load_json(PACK / "nohardcode-policy.json")
            policy["exclusions"] = ["excluded/**"]
            policy_path = Path(temporary) / "policy.json"
            policy_path.write_text(json.dumps(policy), encoding="utf-8")

            def run() -> tuple[int, dict]:
                result = subprocess.run(
                    [sys.executable, str(PACK / "standard/nohardcode_check.py"),
                     "--target", str(root), "--policy", str(policy_path), "--format", "json"],
                    capture_output=True, text=True, check=False,
                )
                return result.returncode, json.loads(result.stdout)

            code, report = run()
            hits = [(Path(v["file_path"]).name, v["line_number"], v["rule_id"])
                    for v in report["violations"]]
            expected_coverage = {"scanned": 1, "excluded_by_policy": 1, "unsupported": 1}
            if (code != 1 or report["summary"]["errors"] != 1
                    or hits != [(module.name, 4, "NOHARDCODE-006")]
                    or report["summary"]["coverage"] != expected_coverage):
                raise ConformanceError(
                    "SCANNER_FAILURE", f"JavaScript module CLI coverage incorrect for {suffix}: {report}",
                )
            module.write_text(safe, encoding="utf-8")
            code, report = run()
            if code != 0 or report["violations"] or report["summary"]["coverage"] != expected_coverage:
                raise ConformanceError(
                    "SCANNER_FAILURE", f"Module comments/env defaults incorrectly flagged for {suffix}: {report}",
                )


def run_conformance() -> int:
    print("=== Wellmanifest No-Hardcode Conformance Suite ===")

    # 1. Required Documents
    for req in REQUIRED_DOCS:
        if not req.exists():
            print(f"✗ Missing required document: {req.relative_to(PACK)}", file=sys.stderr)
            return 1
    print(f"✓ All {len(REQUIRED_DOCS)} required documents and schemas present.")

    # 2. Version Consistency
    version_text = (PACK / "VERSION").read_text(encoding="utf-8").strip()
    manifest_data = load_json(PACK / "dsl-manifest.json")
    if manifest_data.get("version") != version_text:
        print(f"✗ Version mismatch: VERSION is '{version_text}', manifest is '{manifest_data.get('version')}'", file=sys.stderr)
        return 1
    print(f"✓ Version consistency verified: {version_text}")

    # 3. Valid Fixtures
    for vf in VALID_FIXTURES:
        if not vf.exists():
            print(f"✗ Missing valid fixture: {vf.name}", file=sys.stderr)
            return 1
        try:
            validate_fixture(vf)
            print(f"✓ Valid fixture passed: {vf.name}")
        except Exception as ex:
            print(f"✗ Valid fixture failed unexpectedly: {vf.name} -> {ex}", file=sys.stderr)
            return 1

    # 4. Invalid Fixtures
    for inv, expected_code in INVALID_FIXTURES.items():
        if not inv.exists():
            print(f"✗ Missing invalid fixture: {inv.name}", file=sys.stderr)
            return 1
        try:
            validate_fixture(inv)
            print(f"✗ Invalid fixture was unexpectedly accepted: {inv.name}", file=sys.stderr)
            return 1
        except ConformanceError as ce:
            if ce.code != expected_code:
                print(f"✗ Invalid fixture raised wrong code: expected {expected_code}, got {ce.code}", file=sys.stderr)
                return 1
            print(f"✓ Invalid fixture rejected as expected ({ce.code}): {inv.name}")
        except Exception as ex:
            print(f"✗ Unexpected exception on invalid fixture {inv.name}: {ex}", file=sys.stderr)
            return 1

    # 5. Scanner Unit Test
    try:
        test_code_smell_scanner()
        test_conditional_chain_findings_are_distinct()
        test_direct_subprocess_argv_context()
        test_adjacent_assigned_subprocess_argv_context()
        print("✓ Smell detection AST scanner verified against normative rules.")
    except Exception as ex:
        print(f"✗ Smell detection scanner test failed: {ex}", file=sys.stderr)
        return 1

    try:
        test_non_python_line_rules_and_coverage()
        test_javascript_module_cli_coverage()
        print("✓ Line rules cover firmware/config files and coverage is reported.")
        test_print_exemption_and_explicit_exclusions()
        print("✓ print() exemption matches path components; empty exclusions scan everything.")
        test_env_defaults_in_js_and_shell()
        test_env_file_loopback_values()
        print("✓ JS/TS and shell env-lookup defaults skipped; sleep test exemption matches path components.")
    except Exception as ex:
        print(f"✗ Coverage test failed: {ex}", file=sys.stderr)
        return 1

    try:
        test_inline_waiver()
        print("✓ Inline waivers require a matching rule and a reason.")
    except Exception as ex:
        print(f"✗ Inline waiver test failed: {ex}", file=sys.stderr)
        return 1

    try:
        test_waiver_above_finding()
        test_policy_waivers()
        print("✓ Waivers above findings and exact policy waivers work; vague waivers are rejected.")
    except Exception as ex:
        print(f"✗ Waiver extension test failed: {ex}", file=sys.stderr)
        return 1

    try:
        test_policy_rules_are_applied()
        print("✓ Repository policy rules (enabled/severity) applied.")
    except Exception as ex:
        print(f"✗ Policy rules test failed: {ex}", file=sys.stderr)
        return 1

    print("\nAll conformance tests PASSED. Status: COMPLIANT.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Wellmanifest No-Hardcode Conformance Runner")
    parser.add_argument("--all", action="store_true", help="Run full suite")
    args = parser.parse_args()
    return run_conformance()


if __name__ == "__main__":
    sys.exit(main())
