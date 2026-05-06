from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class LLMConfig:
    use_ai: bool = False
    api_key: Optional[str] = None
    api_url: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o-mini"
    mock_responses_path: str = "mock/responses.json"
    timeout_seconds: int = 60

    @classmethod
    def from_env(cls) -> "LLMConfig":
        use_ai = os.getenv("USE_AI", "false").strip().lower() in {"1", "true", "yes"}
        return cls(
            use_ai=use_ai,
            api_key=os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY"),
            api_url=os.getenv("LLM_API_URL", cls.api_url),
            model=os.getenv("LLM_MODEL", cls.model),
            mock_responses_path=os.getenv("MOCK_RESPONSES_PATH", cls.mock_responses_path),
            timeout_seconds=int(os.getenv("LLM_TIMEOUT_SECONDS", str(cls.timeout_seconds))),
        )


class LLMClient:
    def __init__(self, config: LLMConfig) -> None:
        self.config = config
        self._mock_responses = self._load_mock_responses(config.mock_responses_path)

    def generate(self, system_prompt: str, user_prompt: str, iteration: int) -> str:
        if self.config.use_ai:
            return self._call_chat_completion(system_prompt, user_prompt)
        return self._mock_response(user_prompt, iteration)

    def _call_chat_completion(self, system_prompt: str, user_prompt: str) -> str:
        if not self.config.api_key:
            raise ValueError("USE_AI is enabled, but LLM_API_KEY or OPENAI_API_KEY is not set.")

        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        request = urllib.request.Request(
            self.config.api_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM API request failed with status {exc.code}: {details}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM API request failed: {exc.reason}") from exc

        return str(body["choices"][0]["message"]["content"])

    def _mock_response(self, user_prompt: str, iteration: int) -> str:
        if not self._mock_responses:
            raise ValueError("Mock mode is enabled, but no mock responses were found.")
        heuristic_code = _build_heuristic_mock_fix(user_prompt)
        if heuristic_code is not None:
            return json.dumps(
                {
                    "explanation": (
                        "Mock remediation preserved the submitted code and applied configured "
                        "sanitizers to the detected vulnerable sinks."
                    ),
                    "fixed_code": heuristic_code,
                }
            )

        item = self._select_mock_response(user_prompt, iteration)
        if isinstance(item, dict):
            code = item.get("code")
            explanation = item.get("explanation", "Mock remediation response.")
            if code:
                return json.dumps({"explanation": explanation, "fixed_code": code})
        return str(item)

    def _select_mock_response(self, user_prompt: str, iteration: int) -> Any:
        prompt = user_prompt.lower()
        fallback_items: List[Any] = []

        for item in self._mock_responses:
            if not isinstance(item, dict):
                fallback_items.append(item)
                continue

            matches = [str(value).lower() for value in item.get("match", [])]
            if not matches:
                fallback_items.append(item)
                continue

            if any(match in prompt for match in matches):
                return item

        candidates = fallback_items or self._mock_responses
        index = min(iteration, len(candidates) - 1)
        return candidates[index]

    @staticmethod
    def _load_mock_responses(path: str) -> List[Any]:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = Path(__file__).resolve().parents[1] / candidate
        if not candidate.exists():
            return []
        raw: Dict[str, Any] | List[Any] = json.loads(candidate.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            return list(raw.get("responses", []))
        return list(raw)


def _build_heuristic_mock_fix(user_prompt: str) -> Optional[str]:
    code = _extract_prompt_code(user_prompt)
    if code is None:
        return None

    fixed = code
    fixed = _ensure_sanitizer_assignment(fixed, "user_id", "safe_user_id", "parametrize")
    fixed = fixed.replace('"SELECT * FROM users WHERE id = " + user_id', '"SELECT * FROM users WHERE id = " + safe_user_id')
    fixed = _ensure_sanitizer_assignment(fixed, "display_name", "safe_display_name", "escape")
    fixed = fixed.replace('"<h1>" + display_name + "</h1>"', '"<h1>" + safe_display_name + "</h1>"')
    fixed = _ensure_sanitizer_assignment(fixed, "host", "safe_host", "shlex_quote")
    fixed = fixed.replace('"ping -c 1 " + host', '"ping -c 1 " + safe_host')
    fixed = _ensure_sanitizer_assignment(fixed, "filename", "safe_filename", "secure_filename")
    fixed = fixed.replace("open(filename)", "open(safe_filename)")
    fixed = _ensure_sanitizer_assignment(fixed, "target_url", "safe_url", "validate_url")
    fixed = fixed.replace("urlopen(target_url)", "urlopen(safe_url)")

    if fixed == code:
        return None
    return fixed.rstrip() + "\n"


def _extract_prompt_code(user_prompt: str) -> Optional[str]:
    blocks = re.findall(r"```python\s*(.*?)```", user_prompt, flags=re.DOTALL | re.IGNORECASE)
    if not blocks:
        return None
    return blocks[-1].strip() + "\n"


def _ensure_sanitizer_assignment(code: str, source_name: str, safe_name: str, sanitizer_name: str) -> str:
    if safe_name in code:
        return code

    lines = code.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(f"{source_name} = ") or stripped.startswith(f"{source_name}="):
            indent = line[: len(line) - len(line.lstrip())]
            lines.insert(index + 1, f"{indent}{safe_name} = {sanitizer_name}({source_name})")
            return "\n".join(lines) + "\n"

    return code
