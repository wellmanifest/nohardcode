# Wellmanifest No-Hardcode Standard Specification
## `wellmanifest/nohardcode@v1`

## 1. Scope & Status

This specification defines normative rules for identifying, preventing, and eliminating hardcoded values, brittle static heuristics, rigid algorithms, and static assumptions across all repositories complying with the `wellmanifest` standard.

Status: `0.2.0-dev`.

---

## 2. Normative Rules

### `NOHARDCODE-001`: Natural Language & Intent Decoupling
1. Codebases MUST NOT maintain static arrays of more than 5 natural language keyword literals for intent classification where semantic classification is required.
2. User intent mapping MUST use a semantic router, embedding model, or local LLM prompt (`wellmanifest/nl-dsl-llm`) with tolerance for grammatical inflection, typos, and phrasing variations.
3. Keyword lists in legacy bridges MUST provide a deterministic fallback or escalation to an LLM evaluator before raising an unknown-command error.

### `NOHARDCODE-002`: UI Spatial Coordinate Decoupling
1. Automation scripts MUST NOT emit fixed, hardcoded absolute mouse click coordinates `(x, y)` without explicit dynamic bounding box calculation.
2. Element positioning MUST be derived dynamically using visual object detection (YOLO / `twinerd-vision`), accessibility trees, or OCR text bounding boxes.

### `NOHARDCODE-003`: Visual Label & Text Dynamic Extraction
1. Canvas, VNC, and KVM screen interactions MUST use OCR (Tesseract OCR / EasyOCR) to dynamically localize target text elements when DOM selectors are unavailable.
2. OCR confidence thresholds MUST be configurable per environment (defaulting to `>= 60.0`).

### `NOHARDCODE-004`: Declarative Business Logic (JEV / Policy DSL)
1. Multi-branch decision logic containing more than 3 consecutive conditional branches based on data values SHOULD be externalized into declarative JSON/YAML expressions (JEV / JSONLogic / `wellmanifest/policy-dsl`).
2. Hardcoded thresholds and coefficients MUST be loadable from external policy manifests.

### `NOHARDCODE-005`: Plaintext Credential Prohibition
1. Source files, documentation, and configuration templates MUST NOT contain plaintext API keys, tokens, passwords, or cryptographic private keys.
2. All persistent secrets MUST comply with `wellmanifest/secrets` (AES-256-GCM authenticated envelopes, `0600` permissions, origin-bound access).

### `NOHARDCODE-006`: Environment & Port Externalization
1. Hostnames, IP addresses, and TCP/UDP ports MUST NOT be hardcoded as string/int literals in application logic.
2. Configuration MUST resolve through standard environment variables conforming to `wellmanifest/env-dsl` (`SNAKE_CASE=value`).

### `NOHARDCODE-007`: Structured Logging & Codified Errors
1. Applications MUST NOT emit unstructured raw string prints (`print()`, `console.log()`) for operational events or fatal conditions.
2. All errors and exceptions MUST adopt structured error codes documented in `errors/{CODE}.md` runbooks according to `wellmanifest/logs`.

### `NOHARDCODE-008`: PII & Test Fixture Hygiene
1. Test fixtures, sample datasets, and mock objects MUST NOT contain real personal data (PII) of real individuals or production systems.
2. Data masking, synthetic generation, or pseudonymization conforming to `wellmanifest/anonym` MUST be applied.

### `NOHARDCODE-009`: Filesystem Path Portability
1. Code MUST NOT assume user home directory names (e.g. `/home/tom`, `C:\Users\tom`).
2. Paths MUST be resolved dynamically via standard platform APIs (`Path.home()`, `XDG_*`, or `tempfile`) and bounded runtime leases (`wellmanifest/account-runtime`).

### `NOHARDCODE-010`: Code Duplication & Shared Module Reuse
1. Codebases MUST NOT copy-paste identical logic across multiple repositories or subdirectories.
2. Duplication detected by AST analysis (`semcod/redup`) MUST be extracted into modular packages under `packages/` or dedicated micro-libraries conforming to `wellmanifest/reuse` and `wellmanifest/modularity`.

### `NOHARDCODE-011`: Adaptive Thresholds, Timeouts & Rate Governors
1. Applications MUST NOT rely on arbitrary, hardcoded static sleeps (`sleep(5)`), fixed timeouts, or static retry limits in production workflows.
2. Network calls, IPC requests, and LLM queries MUST employ dynamic latency tracking (Exponentially Weighted Moving Average — EWMA RTT estimation), exponential backoff with full jitter, and circuit breaker governors (`wellmanifest/performance`).
3. Concurrency limits and batch sizes MUST scale adaptively based on available memory, queue depth, and provider token-rate feedback.

### `NOHARDCODE-012`: Resilient Schema Extraction & Document/DOM Decoding
1. Ingestion and automation pipelines MUST NOT hardcode rigid, brittle single-path object navigation (e.g. deep static dict key chains) or fragile regex parsers that break on upstream schema evolution or UI redesigns.
2. Extraction MUST use tolerant recursive tree visitors with candidate node filtering, schema-guided healing, or zero-shot structured LLM/vision fallback extractors (`wellmanifest/nl-dsl-llm`).
3. When parsing structured web/API payloads, parsers MUST maintain multi-tier fallback ladders (primary component $\to$ secondary component $\to$ semantic extraction) rather than failing closed on non-critical format deviations.

### `NOHARDCODE-013`: Dynamic Model, Provider & Engine Capabilities Routing
1. AI agent systems MUST NOT hardcode specific proprietary model strings (e.g. `"gpt-4o"`, `"claude-3-5-sonnet"`) or provider endpoints directly into operational task handlers.
2. Model invocation MUST be dispatched through a Capability-Based Model Router (`wellmanifest/llm`, `wellmanifest/nl-dsl-llm`) specifying abstract requirements (e.g. `speed: low-latency`, `reasoning: deep`, `context_budget: 128k`, `offline_capable: true`).
3. Systems MUST implement dynamic fallback cascades: Local Embedded/ONNX/Ollama $\to$ Cloud API $\to$ degraded deterministic heuristic fallback.

### `NOHARDCODE-014`: Declarative Goal-Driven DAG Planning & Reactive Workflows
1. Multi-step operations MUST NOT be hardcoded into rigid procedural functions or static step-by-step sequences.
2. Complex workflows MUST be structured as declarative Directed Acyclic Graphs (DAG) or Goal-Driven Plans evaluated by an execution engine (`wellmanifest/poa`).
3. Workflow engines MUST support autonomous self-healing reflection loops (Plan-Act-Observe-Diagnose-Repair) and reactive CQRS event chains (`wellmanifest/repair-lifecycle`) to recover from unexpected environmental drift.

### `NOHARDCODE-015`: Environment & Hardware Capability Discovery
1. Systems MUST NOT hardcode display server targets (`DISPLAY=":0"`), viewport resolutions (`1920x1080`), CPU core counts (`threads=8`), or hardware accelerator strings (`"cuda:0"`).
2. Runtimes MUST discover display sockets dynamically (X11 / Wayland / Xvnc), probe hardware capabilities via standard APIs (`os.sched_getaffinity()`, `torch.cuda.is_available()`, Vulkan/OpenCL probes), and dynamically scale canvas/viewport dimensions.

### `NOHARDCODE-016`: Fuzzy Phonetic Matching & Lexical Resilience
1. Natural language and voice processing systems MUST NOT rely solely on hardcoded static dictionaries of phonetic typo variants, dialect slang, or grammatical inflections.
2. Systems MUST combine fuzzy string metrics (Levenshtein edit distance, Jaro-Winkler) and phonetic algorithms (Double Metaphone, Soundex) with vector embedding nearest-neighbor search and LLM context disambiguation.

### `NOHARDCODE-017`: Feedback-Driven Prioritization & Dynamic Scoring
1. Decision, recommendation, and scheduling engines MUST NOT hardcode fixed linear scoring equations or arbitrary static prioritization weights.
2. Priority scores and recommendation rankings MUST adjust adaptively using online feedback loops, Multi-Armed Bandit policies (Thompson Sampling / Upper Confidence Bound), and outcome tracking (`wellmanifest/saas-lifecycle`, `wellmanifest/agent`).

---

## 3. Conformance Profiles

- **Strict**: All rules (`NOHARDCODE-001` through `NOHARDCODE-017`) are evaluated as blocking errors (`exit code 1`).
- **Balanced (Default)**:
  - Blocking errors: `NOHARDCODE-005` (Secrets), `NOHARDCODE-006` (Endpoints), `NOHARDCODE-007` (Logging), `NOHARDCODE-009` (Paths), `NOHARDCODE-013` (Model Bindings), `NOHARDCODE-015` (Hardware Assumptions).
  - Warnings with remediation guidance: `NOHARDCODE-001` through `NOHARDCODE-004`, `NOHARDCODE-008`, `NOHARDCODE-010`, `NOHARDCODE-011`, `NOHARDCODE-012`, `NOHARDCODE-014`, `NOHARDCODE-016`, `NOHARDCODE-017`.
- **Permissive**: All findings are advisory warnings with automated planfile ticket suggestions.
