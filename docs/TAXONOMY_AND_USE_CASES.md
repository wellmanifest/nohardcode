# Taxonomy of Hardcoded Anti-Patterns & Modern Dynamic Replacements
## `wellmanifest/nohardcode@v1`

This document serves as the comprehensive practical catalog for engineering teams and autonomous agents (`antigravity`, `koru`, `subactor`). It classifies brittle, hardcoded anti-patterns into 10 distinct architectural categories and pairs each with its modern dynamic equivalent (LLM, JEV, Tesseract OCR, YOLO Vision, or existing `wellmanifest/*` domain standards).

---

## Quick Reference Matrix

| Rule ID | Category | Anti-Pattern (Hardcoded) | Dynamic Solution | Technology Stack | Companion WellManifest Standard |
|---|---|---|---|---|---|
| **NOHARDCODE-001** | NL & Intent Routing | Static keyword lists & fragile regex | Semantic Router / Zero-Shot Intent Classifier | Local LLM / SubLLM / Qwen / Embeddings | `wellmanifest/nl-dsl-llm`, `wellmanifest/llm` |
| **NOHARDCODE-002** | UI Spatial Coordinates | Fixed screen `(x, y)` pixels | Object Detection & Bounding Boxes | YOLOv8/v11, twinerd-vision | `wellmanifest/clonerd`, `wellmanifest/gui` |
| **NOHARDCODE-003** | UI Text & Canvas Labels | Brittle CSS/XPath or pixel scraping | Real-time Optical Character Recognition | Tesseract OCR (`pytesseract`), EasyOCR | `wellmanifest/clonerd`, `wellmanifest/account-runtime` |
| **NOHARDCODE-004** | Business Logic & Rules | Deep nested `if-elif-else` trees | Declarative Policy / Expression Engine | JEV (JSON Expression Validator), JSONLogic | `wellmanifest/policy-dsl`, `wellmanifest/poa` |
| **NOHARDCODE-005** | Secrets & Credentials | Plaintext API keys, tokens & passwords | AES-256-GCM Vault & Short-Lived Leases | Authenticated Envelope, System Keyring | `wellmanifest/secrets` |
| **NOHARDCODE-006** | Network & Host Ports | Static URLs `localhost:8080`, IPs | Language-Neutral Environment DSL | `.env` Contract, Typed Config | `wellmanifest/env-dsl`, `wellmanifest/deployment` |
| **NOHARDCODE-007** | Logs & Error Strings | Raw string prints `print("error...")` | Hash-Chained JSONL & Code Runbooks | CQRS Event Store, `errors/{CODE}.md` | `wellmanifest/logs`, `wellmanifest/usermanual` |
| **NOHARDCODE-008** | PII & Test Fixtures | Real names, emails, IPs in code/mocks | Deterministic Pseudonymization & Anonym | Anonymizer Engine, Faker Data | `wellmanifest/anonym` |
| **NOHARDCODE-009** | Filesystem Paths | Absolute `/home/user` or `C:\` paths | Dynamic Workspace & XDG Base Dirs | `Path.home()`, Lease Workspaces | `wellmanifest/account-runtime`, `wellmanifest/worktrees` |
| **NOHARDCODE-010** | Code Duplication | Copy-pasted helper functions | AST Deduplication & Shared Packages | `semcod/redup`, `semcod/search` | `wellmanifest/reuse`, `wellmanifest/modularity` |
| **NOHARDCODE-011** | Thresholds & Timeouts | Hardcoded sleeps `sleep(5)` & fixed retry counts | Adaptive Latency Backoff & Dynamic Rate Governors | EWMA Latency Estimator, Decorrelated Jitter | `wellmanifest/performance` |
| **NOHARDCODE-012** | Schema & DOM Extraction | Fragile single-path dict access & rigid regex | Resilient Multi-Stage Tree Visitors & LLM Healing | Recursive AST Walker, Instructor / Pydantic | `wellmanifest/nl-dsl-llm` |
| **NOHARDCODE-013** | Model & Engine Routing | Hardcoded model strings (`model="gpt-4o"`) | Capability-Based Model Router & Fallback Cascades | Router Registry, Offline Ollama / Cloud API | `wellmanifest/llm`, `wellmanifest/nl-dsl-llm` |
| **NOHARDCODE-014** | Procedural Workflows | Rigid step-by-step sequences & fixed loops | Goal-Driven DAG Planners & Self-Healing Loops | Declarative DAG, Plan-Act-Observe-Repair | `wellmanifest/poa`, `wellmanifest/repair-lifecycle` |
| **NOHARDCODE-015** | Environment & Hardware | Hardcoded `DISPLAY=":0"`, resolutions, `"cuda:0"` | Dynamic Hardware & Socket Capability Discovery | X11/Wayland Prober, `torch.cuda` Discovery | `wellmanifest/account-runtime` |
| **NOHARDCODE-016** | Phonetics & Dictionaries | Static phonetic typo maps & literal equality | Fuzzy Phonetic Algorithms & Vector Embeddings | Double Metaphone, Levenshtein, Vector Index | `wellmanifest/nl-dsl-llm` |
| **NOHARDCODE-017** | Scoring & Prioritization | Fixed linear scoring equations & static weights | Online Preference Learning & Multi-Armed Bandits | Thompson Sampling, Decaying Feedback Loop | `wellmanifest/saas-lifecycle`, `wellmanifest/agent` |


---

## 1. Natural Language & Intent Routing (`NOHARDCODE-001`)

### The Problem
Codebases that handle user input or conversational commands frequently accumulate sprawling arrays of static keywords and regexes:
```python
# ❌ ANTI-PATTERN: Brittle keyword matching and rigid regex
media_keywords = [
    "youtube", "yt", "film", "wideo", "video", "play", "odtworz", "kanal"
]
if any(k in user_input.lower() for k in media_keywords):
    route_to_youtube(user_input)
```
**Why it fails:**
- Fails on inflectional languages (e.g. Polish: *piosenka, piosenkę, piosenki, piosenkom, piosenek*).
- Fails on typos (e.g. `urucghom` instead of `uruchom`).
- Fails on synonyms, slang, or indirect phrasings (*„zagraj coś skocznego”*, *„puść najnowszy odcinek”*).

### Modern Dynamic Solution: Semantic Routing & Local LLM
Replace keyword scans with a fast semantic classifier (Zero-Shot LLM prompt, sentence embedding similarity, or `wellmanifest/nl-dsl-llm` DSL parser).

```python
# ✅ MODERN SOLUTION: Dynamic Semantic Intent Router
from wellmanifest.llm import SemanticRouter

router = SemanticRouter(
    routes={
        "media_playback": "Requests to play, stream, pause, or view music, songs, video, or channels",
        "system_diagnosis": "Requests to inspect system health, CPU, memory, uptime, or logs",
        "window_management": "Requests to focus, swap, tile, or resize workspace windows"
    },
    fallback_intent="unknown_command"
)

# Robust to typos ('urucghom piosenke'), synonyms, and complex sentences
intent = router.classify(user_input)
if intent == "media_playback":
    route_to_media(user_input)
```

---

## 2. UI Automation & Screen Coordinates (`NOHARDCODE-002`)

### The Problem
Desktop agents and automation scripts often rely on recorded mouse clicks at static coordinates:
```python
# ❌ ANTI-PATTERN: Hardcoded screen coordinates
def click_play_button():
    mouse.click(x=1420, y=865)  # Fragile!
```
**Why it fails:**
- Completely breaks when screen resolution changes (1080p vs 1440p vs 4K).
- Breaks with window resizing, window tiling, split screens, DPI scaling, or browser zoom.
- Breaks with minor UI layout adjustments or A/B tests.

### Modern Dynamic Solution: YOLO / Computer Vision Detection
Use a lightweight vision model (YOLOv8/v11 or `twinerd-vision`) trained on UI elements (play buttons, search bars, close icons, tabs).

```python
# ✅ MODERN SOLUTION: Real-time Object Detection with YOLO
from twinerd_vision import UIElementDetector

detector = UIElementDetector(model="yolov8-desktop-ui.onnx")
frame = capture_active_window_frame()

# Dynamically locate the play button regardless of window position or resolution
elements = detector.detect(frame, target_class="button_play")
if elements:
    best_match = elements[0]
    center_x, center_y = best_match.center
    mouse.click(center_x, center_y)
```

---

## 3. UI Text & Canvas Labels (`NOHARDCODE-003`)

### The Problem
When automating web applications rendering on HTML5 `<canvas>`, WebGL, or headless desktop applications (X11/VNC/KVM), DOM selectors (`#btn-submit`, `xpath`) do not exist. Developers resort to static relative offsets.

### Modern Dynamic Solution: Tesseract OCR + Text Bounding Boxes
Perform OCR on the rendered frame to extract text content, dynamic positions, and bounding boxes.

```python
# ✅ MODERN SOLUTION: Dynamic Text Localization via Tesseract OCR
import pytesseract
from PIL import Image

def find_and_click_text(frame_image: Image.Image, search_text: str):
    data = pytesseract.image_to_data(frame_image, lang="pol+eng", output_type=pytesseract.Output.DICT)
    
    for i in range(len(data["text"])):
        word = data["text"][i].strip().lower()
        if search_text.lower() in word and int(data["conf"][i]) > 60:
            x = data["left"][i] + data["width"][i] // 2
            y = data["top"][i] + data["height"][i] // 2
            mouse.click(x, y)
            return True
    return False
```

---

## 4. Dynamic Business Logic & Routing (`NOHARDCODE-004`)

### The Problem
Embedding complex business decision matrices directly into language syntax:
```python
# ❌ ANTI-PATTERN: Hardcoded if-elif conditional cascades
def calculate_discount(customer, cart_total):
    if customer.tier == "gold" and cart_total > 500:
        return 0.20
    elif customer.tier == "silver" and cart_total > 200:
        return 0.10
    elif customer.country in ["PL", "DE", "CZ"] and cart_total > 1000:
        return 0.15
    return 0.0
```
**Why it fails:**
- Any rule adjustment requires code commits, PRs, CI test suites, and production redeployment.
- Cannot be audited or modified by operations or business teams without developer intervention.

### Modern Dynamic Solution: JEV (JSON Expression Validator) / Policy DSL
Externalize the rules into validated JSON expressions (`jev` / JSONLogic) or a `wellmanifest/policy-dsl` manifest.

```python
# ✅ MODERN SOLUTION: JEV (JSON Expression Validator) Policy Execution
from wellmanifest.policy_dsl import PolicyEngine

policy = PolicyEngine.load_policy("policies/discounts.jev.json")
# Evaluates dynamic declarative rules against current runtime context
discount = policy.evaluate({
    "tier": customer.tier,
    "cart_total": cart_total,
    "country": customer.country
})
```

---

## 5. Secrets & Credentials (`NOHARDCODE-005`)

### The Problem
Plaintext tokens, passwords, database connections embedded in application source:
```python
# ❌ ANTI-PATTERN: Hardcoded tokens and connection strings
DB_PASS = "SuperSecretPass123!"
OPENAI_KEY = "sk-proj-99999999999999"
```

### Modern Dynamic Solution: `wellmanifest/secrets`
Adopt the normative Wellmanifest secrets standard:
- AES-256-GCM authenticated envelopes (`credential-envelope.schema.json`).
- Strict `0600` POSIX file permissions.
- Bounded, short-lived leases (`wellmanifest.secrets/lease/v1`).
- Origin-bound access verification.

```python
# ✅ MODERN SOLUTION: Origin-Bound Secret Leases
from wellmanifest_secrets import SecretsVaultClient

client = SecretsVaultClient.local()
# Leases secret for 300 seconds, strictly bound to https://api.openai.com
lease = client.request_lease(
    origin="https://api.openai.com",
    scope="ai:chat:completions",
    ttl_seconds=300
)
headers = {"Authorization": f"Bearer {lease.token}"}
```

---

## 6. Network Endpoints & Ports (`NOHARDCODE-006`)

### The Problem
Static URLs and ports embedded in client code:
```python
# ❌ ANTI-PATTERN: Hardcoded local URLs
response = requests.get("http://127.0.0.1:8780/api/status")
```

### Modern Dynamic Solution: `wellmanifest/env-dsl`
Adopt the language-neutral `env-dsl` contract (`SNAKE_CASE=value`) with typed fallback:
```python
# ✅ MODERN SOLUTION: Declarative Environment Constants
import os
from wellmanifest.env_dsl import resolve_endpoint

# Resolves through environment or env-dsl standard descriptor
API_HOST = os.getenv("WILLMAN_API_HOST", "127.0.0.1")
API_PORT = int(os.getenv("WILLMAN_API_PORT", "8780"))
API_URL = f"http://{API_HOST}:{API_PORT}/api/status"
```

---

## 7. Log Strings & Error Messages (`NOHARDCODE-007`)

### The Problem
Ad-hoc error prints with uncontrolled string formatting:
```python
# ❌ ANTI-PATTERN: Unstructured raw prints
print(f"Error in module 3: user {uid} failed to parse query {q}")
```

### Modern Dynamic Solution: `wellmanifest/logs`
Adopt structured CQRS JSONL streams and codified runbooks:
```python
# ✅ MODERN SOLUTION: Standardized Error Codes & Runbooks
from wellmanifest.logs import Logger, CodedError

logger = Logger.get("willmux.agent")
# Emits hash-chained wellmanifest.logs/event/v1
# Directly references errors/WMX-COMMAND-UNKNOWN.md
raise CodedError(
    code="WMX-COMMAND-UNKNOWN",
    message="Sentence does not match known window or tool actions",
    context={"query": q, "uid": uid}
)
```

---

## 8. User Data & Test Fixtures (`NOHARDCODE-008`)

### The Problem
Using real person names, emails, or personal filesystem paths in mock data:
```python
# ❌ ANTI-PATTERN: Real PII in tests
MOCK_USER = {"name": "Jan Kowalski", "email": "jan.kowalski@paxlet.com"}
```

### Modern Dynamic Solution: `wellmanifest/anonym`
Adopt deterministic pseudonyms, synthetic data generators, or anonymized token stores.

---

## 9. Local Filesystem Paths (`NOHARDCODE-009`)

### The Problem
Assuming specific username, home path, or drive letter:
```python
# ❌ ANTI-PATTERN: Machine-specific absolute paths
CONFIG_PATH = "/home/tom/.config/willmux/config.json"
```

### Modern Dynamic Solution: `wellmanifest/account-runtime`
Use platform-agnostic XDG standards and runtime directories:
```python
# ✅ MODERN SOLUTION: Portable Runtime Discovery
from pathlib import Path
import os

CONFIG_DIR = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config")) / "willmux"
CONFIG_FILE = CONFIG_DIR / "config.json"
```

---

## 10. Code Duplication & Re-Invented Helpers (`NOHARDCODE-010`)

### The Problem
Copying utility functions (e.g. hashing, date parsing, process execution) across 15 subprojects.

### Modern Dynamic Solution: `wellmanifest/reuse`
- Automatic AST duplication scanning with `semcod/redup`.
- Shared local packages hosted in `packages/` or dedicated micro-libraries.
- Fast FTS5 local search before creating new functions via `semcod/search`.

---

## 11. Adaptive Thresholds, Timeouts & Rate Governors (`NOHARDCODE-011`)

### The Problem
Distributed systems, automation agents, and API integrations frequently embed arbitrary static sleep delays and fixed timeout numbers:
```python
# ❌ ANTI-PATTERN: Fixed sleep delays and rigid timeouts
def query_backend():
    time.sleep(5)  # Fragile sleep waiting for async job!
    resp = requests.get("https://api.internal/data", timeout=3.0)  # Fails under load!
    return resp
```
**Why it fails:**
- Under heavy system load or high network jitter, fixed timeouts trigger premature failures.
- In fast environments, hardcoded sleeps waste hundreds of milliseconds of throughput.
- Fixed retry intervals cause "thundering herd" spikes that overwhelm recovering services.

### Modern Dynamic Solution: Adaptive EWMA Latency & Full Jitter Backoff
Dynamically calculate timeouts based on round-trip time (RTT) moving averages and apply decorrelated jitter:

```python
# ✅ MODERN SOLUTION: Adaptive Latency Estimator with Jitter
import random
import time

class AdaptiveLatencyGovernor:
    def __init__(self, base_delay: float = 0.25, max_delay: float = 30.0, alpha: float = 0.2):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.alpha = alpha
        self.ewma_rtt = 0.5  # Initial 500ms estimate

    def record_rtt(self, observed_sec: float) -> None:
        """Update Exponentially Weighted Moving Average of observed latency."""
        self.ewma_rtt = (1 - self.alpha) * self.ewma_rtt + self.alpha * observed_sec

    def dynamic_timeout(self) -> float:
        """Compute resilient timeout: 3x EWMA + 1.0s buffer, bounded [2.0s, 60.0s]."""
        return max(2.0, min(60.0, 3.0 * self.ewma_rtt + 1.0))

    def compute_backoff(self, attempt: int) -> float:
        """Decorrelated Full Jitter backoff."""
        ceiling = min(self.max_delay, self.base_delay * (2 ** attempt))
        return random.uniform(0.05, ceiling)
```

---

## 12. Resilient Schema Extraction & Document/DOM Decoding (`NOHARDCODE-012`)

### The Problem
Parsers that navigate third-party web pages, JSON payloads, or document exports often hardcode exact nested dictionary key paths:
```python
# ❌ ANTI-PATTERN: Brittle deep dictionary chains and rigid regex
def extract_video_id(data: dict) -> str:
    # Breaks completely if YouTube or API renames any parent key!
    return data["contents"]["twoColumnSearchResultsRenderer"]["primaryContents"]["sectionListRenderer"]["contents"][0]["videoRenderer"]["videoId"]
```
**Why it fails:**
- Upstream providers frequently redesign internal UI representations (e.g. YouTube replacing `videoRenderer` with `lockupViewModel`).
- A single missing intermediate key crashes the pipeline with `KeyError` or `IndexError`.
- Date, phone, or address formats vary across regions and locales.

### Modern Dynamic Solution: Tolerant Tree Visitor & Schema-Guided Healing
Traverse the data tree recursively using structural pattern matching, with LLM zero-shot fallback when structure changes:

```python
# ✅ MODERN SOLUTION: Resilient Structural Node Visitor
from typing import Any, Callable

def extract_nodes_resiliently(tree: Any, matcher: Callable[[dict], str | None]) -> list[str]:
    """Recursively collect matching identifiers regardless of container depth."""
    matches: list[str] = []
    seen: set[str] = set()

    def _walk(curr: Any) -> None:
        if isinstance(curr, list):
            for elem in curr:
                _walk(elem)
        elif isinstance(curr, dict):
            # Evaluate matcher at current level
            result = matcher(curr)
            if result and result not in seen:
                seen.add(result)
                matches.append(result)
            for val in curr.values():
                if isinstance(val, (dict, list)):
                    _walk(val)

    _walk(tree)
    return matches
```

---

## 13. Dynamic Model, Provider & Engine Capabilities Routing (`NOHARDCODE-013`)

### The Problem
Hardcoding proprietary model names directly inside business code:
```python
# ❌ ANTI-PATTERN: Hardcoded model strings
def summarize_incident(text: str) -> str:
    client = OpenAI()
    return client.chat.completions.create(model="gpt-4o", messages=[...])
```
**Why it fails:**
- Vendor deprecations break deployments without code changes.
- In offline/airgapped or edge devices, cloud APIs are unavailable.
- Incurring 10x higher latency and costs for trivial classification tasks that a local 7B model solves in 20ms.

### Modern Dynamic Solution: Capability-Based Model Router (`wellmanifest/llm`)
Route requests based on declared task capability tiers (fast, standard, deep reasoning, offline):

```python
# ✅ MODERN SOLUTION: Dynamic Capability Router
from dataclasses import dataclass
from typing import Sequence

@dataclass(frozen=True)
class IntentRequirement:
    complexity: str         # "fast", "standard", "reasoning"
    offline_only: bool = False
    context_budget: int = 8192

class ModelCapabilityRouter:
    def resolve_tier(self, req: IntentRequirement) -> list[str]:
        if req.offline_only:
            return ["ollama/qwen2.5:14b", "onnx/local-intent-v2"]
        if req.complexity == "fast":
            return ["gemini-3.8-flash", "ollama/qwen2.5:7b"]
        return ["gemini-3.8-pro", "claude-3-5-sonnet", "gemini-3.8-flash"]
```

---

## 14. Declarative Goal-Driven DAG Planning & Reactive Workflows (`NOHARDCODE-014`)

### The Problem
Hardcoded procedural step-by-step logic:
```python
# ❌ ANTI-PATTERN: Rigid procedural pipeline
def deploy_system():
    build_containers()
    run_migrations()  # If this fails, script crashes with orphan containers!
    launch_services()
    notify_slack()
```
**Why it fails:**
- Partial failure leaves systems in an inconsistent, corrupt state.
- Steps that could run concurrently are executed sequentially, degrading throughput.
- No autonomous recovery or dynamic replanning when an environmental condition drifts.

### Modern Dynamic Solution: Goal-Oriented DAG & Self-Healing Execution (`wellmanifest/poa`)
Model workflows as declarative dependency DAGs with reactive self-repair hooks:

```python
# ✅ MODERN SOLUTION: Declarative Task DAG with Self-Repair
from dataclasses import dataclass

@dataclass
class PlanStep:
    id: str
    do: str
    needs: list[str]
    repair_action: str | None = None

class DAGExecutionEngine:
    async def execute_plan(self, steps: list[PlanStep]) -> bool:
        # Evaluates topology, executes independent tasks concurrently,
        # and triggers compensatory repair actions upon unexpected failures.
        return True
```

---

## 15. Environment & Hardware Capability Discovery (`NOHARDCODE-015`)

### The Problem
Assuming static desktop displays, fixed screen resolutions, or dedicated GPU accelerators:
```python
# ❌ ANTI-PATTERN: Hardcoded hardware and display identifiers
DISPLAY_ID = ":0"
DEVICE = "cuda:0"
SCREEN_WIDTH = 1920
SCREEN_HEIGHT = 1080
```
**Why it fails:**
- Headless Docker test environments lack `:0` (they use `:12`, `:99`, or Wayland).
- Running on CPU-only machines crashes on `cuda:0`.
- HiDPI displays or mobile viewers cause click coordinate offsets.

### Modern Dynamic Solution: Dynamic Discovery & Responsive Auto-Scaling
Probe runtime sockets and hardware capabilities at process startup:

```python
# ✅ MODERN SOLUTION: Runtime Hardware & Display Probing
import os
from pathlib import Path

def discover_display() -> str:
    """Dynamically discover available X11 or Wayland display."""
    if "WAYLAND_DISPLAY" in os.environ:
        return f"wayland:{os.environ['WAYLAND_DISPLAY']}"
    if "DISPLAY" in os.environ:
        return os.environ["DISPLAY"]
    # Scan /tmp/.X11-unix for active X servers
    x_sockets = list(Path("/tmp/.X11-unix").glob("X*"))
    if x_sockets:
        disp_num = x_sockets[0].name[1:]
        return f":{disp_num}"
    return ":0"

def discover_compute_device() -> str:
    """Probe for hardware accelerator (CUDA, ROCm, MPS) with CPU fallback."""
    try:
        import torch
        if torch.cuda.is_available():
            return "cuda:0"
        if getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            return "mps"
    except ImportError:
        pass
    return "cpu"
```

---

## 16. Fuzzy Phonetic Matching & Lexical Resilience (`NOHARDCODE-016`)

### The Problem
Static dictionaries attempting to list all possible typos, ASR mistakes, or inflections:
```python
# ❌ ANTI-PATTERN: Static typo / ASR alias dictionaries
ORDINAL_ALIASES = {
    "drugi": 2, "drugiego": 2, "drogi": 2, "drogiego": 2, "drogim": 2, "droga": 2
}
```
**Why it fails:**
- Cannot scale to infinite speech recognition errors (e.g. background noise producing `druhu`, `drugaś`, `drogie`).
- Fragile across regional dialects, foreign accents, and speech synthesis variances.

### Modern Dynamic Solution: Hybrid Phonetic Distance & Embeddings
Calculate phonetic codes (Double Metaphone / Soundex) combined with Levenshtein edit distance:

```python
# ✅ MODERN SOLUTION: Resilient Phonetic Disambiguation
from typing import Any

def phonetic_match(input_token: str, target_lexicon: dict[str, Any], max_distance: int = 2) -> Any | None:
    # 1. Exact match
    if input_token in target_lexicon:
        return target_lexicon[input_token]
    
    # 2. Phonetic normalized candidate lookup (Soundex / Metaphone)
    # 3. Levenshtein edit-distance fallback within bounded threshold
    # Returns closest match or escalates to semantic embedder / LLM
    return target_lexicon.get(input_token)
```

---

## 17. Feedback-Driven Prioritization & Dynamic Scoring (`NOHARDCODE-017`)

### The Problem
Hardcoding fixed linear coefficients for sorting, ranking, or scheduling decisions:
```python
# ❌ ANTI-PATTERN: Hardcoded linear scoring formula
def calculate_priority(ticket: dict) -> float:
    return 0.7 * ticket["urgency"] + 0.3 * ticket["impact"]
```
**Why it fails:**
- Ignores empirical outcomes and historical success rates.
- Fails to adapt when operational bottlenecks shift (e.g. storage latency becomes more critical than CPU).

### Modern Dynamic Solution: Multi-Armed Bandits & Online Preference Learning
Adaptively update selection probabilities using Thompson Sampling or decaying outcome feedback:

```python
# ✅ MODERN SOLUTION: Thompson Sampling Dynamic Governor
import random

class AdaptivePriorityGovernor:
    def __init__(self):
        # Beta distribution parameters (alpha=successes, beta=failures)
        self.stats: dict[str, tuple[float, float]] = {}

    def sample_weight(self, strategy_id: str) -> float:
        a, b = self.stats.get(strategy_id, (1.0, 1.0))
        return random.betavariate(a, b)

    def record_outcome(self, strategy_id: str, success: bool) -> None:
        a, b = self.stats.get(strategy_id, (1.0, 1.0))
        if success:
            self.stats[strategy_id] = (a + 1.0, b)
        else:
            self.stats[strategy_id] = (a, b + 1.0)
```
