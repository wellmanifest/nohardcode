# Subactor & AI agent instructions (wellmanifest/nohardcode)

HOME vs ADOPT: this pack is `HOME wellmanifest`, `shape domain_pack`
(normative unhardcoding, dynamic replacement, and codebase adaptability standard).
It does **not** HOME runtime model inference engines, OCR binaries, or secret stores.
Runtimes (such as `twinerd`, `willmux`, `willman`, `premesh`, `dockuri`)
ADOPT this standard for replacing brittle static constants, coordinates, and keyword tables
with verified dynamic technologies (LLM, JEV, Tesseract OCR, YOLO, Vaults, env-dsl).

Closed vocabulary:
- `HOME` wellmanifest|subactor|semcod;
- `SHAPE` domain_pack|runtime_service|both;
- `ADOPT` wellmanifest/new-project, wellmanifest/secrets, wellmanifest/env-dsl, wellmanifest/logs, wellmanifest/reuse, wellmanifest/anonym, wellmanifest/poa.

Fail-closed rules:
1. Never introduce new static lists of natural language keywords when semantic routing or LLMs are applicable.
2. Never hardcode absolute pixel coordinates for UI interactions when YOLO or OCR bounding boxes are available.
3. Never embed plaintext credentials, API keys, or bearer tokens; adopt `wellmanifest/secrets`.
4. Never embed hardcoded hostnames, ports, or environment-dependent paths; adopt `wellmanifest/env-dsl` and `account-runtime`.
5. Run `python3 standard/nohardcode_check.py --all` before claiming conformance.
