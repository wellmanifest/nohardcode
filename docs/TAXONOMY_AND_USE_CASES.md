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
