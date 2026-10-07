# GEMINI.md

This file is the Gemini / Antigravity entry point for `wellmanifest/nohardcode`.
The normative instructions are in [AGENTS.md](AGENTS.md).

This domain pack follows the `wellmanifest/new-project` policy-as-code standard.
Fail-closed:
1. Adhere to the boundary matrix in [README.md](README.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
2. Validate unhardcoded configurations against [schemas/nohardcode-policy.schema.json](schemas/nohardcode-policy.schema.json).
3. Follow the remediation strategies in [docs/TAXONOMY_AND_USE_CASES.md](docs/TAXONOMY_AND_USE_CASES.md).
4. Ensure conformance checks pass: `python3 standard/nohardcode_check.py --all`.
