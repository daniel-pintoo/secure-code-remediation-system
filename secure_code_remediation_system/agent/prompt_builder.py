from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, List, Mapping


SYSTEM_PROMPT = """You are a cybersecurity expert specializing in secure coding practices.
You must follow the requested output schema exactly. Do not return Markdown."""


OUTPUT_CONTRACT = """Output contract:
- Return exactly one JSON object.
- Do not wrap the JSON in Markdown fences.
- Do not include any text before or after the JSON object.
- The JSON object must have exactly these keys:
  - "explanation": a short string explaining the fix
  - "fixed_code": a string containing the complete corrected Python code
- "fixed_code" must contain the full corrected snippet, not a diff.
- Preserve unrelated logic, functions, classes, names, and behavior.
- Do not remove unrelated code to make the analyzer pass."""


def build_initial_prompt(code: str, report: Mapping[str, Any], patterns: Iterable[Mapping[str, Any]]) -> str:
    return f"""Here is a Python code snippet:
```python
{code}
```

Detected vulnerabilities:
```json
{json.dumps(report, indent=2)}
```

Relevant analyzer patterns from 5_patterns.json:
```json
{json.dumps(list(patterns), indent=2)}
```

Use only sanitizers listed in the relevant analyzer patterns when applying sanitizer-based fixes. The
deterministic analyzer will only validate sanitizers configured in these patterns.

Tasks:
1. Explain each vulnerability.
2. Fix the vulnerabilities.
3. Return improved code.
4. Do not modify unrelated logic.

{OUTPUT_CONTRACT}
"""


def build_feedback_prompt(code: str, remaining_report: Mapping[str, Any], patterns: Iterable[Mapping[str, Any]]) -> str:
    return f"""The following vulnerabilities remain:
```json
{json.dumps(remaining_report, indent=2)}
```

Relevant analyzer patterns from 5_patterns.json:
```json
{json.dumps(list(patterns), indent=2)}
```

Current Python code:
```python
{code}
```

Fix ONLY these issues. Do not rewrite the entire code. Use only sanitizers listed in the relevant analyzer
patterns when applying sanitizer-based fixes.
{OUTPUT_CONTRACT}
"""


def load_relevant_patterns(patterns_path: str, report: Mapping[str, Any]) -> List[Mapping[str, Any]]:
    patterns = json.loads(Path(patterns_path).read_text(encoding="utf-8"))
    vulnerability_types = {
        str(item.get("type"))
        for item in report.get("vulnerabilities", [])
        if isinstance(item, Mapping) and item.get("type")
    }
    return [
        pattern for pattern in patterns
        if isinstance(pattern, Mapping) and str(pattern.get("vulnerability")) in vulnerability_types
    ]
