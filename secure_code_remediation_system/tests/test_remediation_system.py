from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.prompt_builder import build_initial_prompt, load_relevant_patterns
from agent.llm_client import LLMClient, LLMConfig
from agent.remediation_loop import RemediationLoop, missing_top_level_definitions, parse_remediation_response
from validation.validator import validate_code


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PATTERNS_PATH = PROJECT_ROOT / "5_patterns.json"
EXAMPLE_INPUT = PROJECT_ROOT / "examples" / "input.py"
MOCK_RESPONSES = PROJECT_ROOT / "mock" / "responses.json"


class RemediationSystemTests(unittest.TestCase):
    def test_mock_remediation_reduces_example_to_zero_active_vulnerabilities(self) -> None:
        code = EXAMPLE_INPUT.read_text(encoding="utf-8")
        baseline = validate_code(code, str(PATTERNS_PATH))
        self.assertEqual(len(baseline.vulnerabilities), 1)

        client = LLMClient(
            LLMConfig(
                use_ai=False,
                mock_responses_path=str(MOCK_RESPONSES),
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            result = RemediationLoop(
                llm_client=client,
                patterns_path=str(PATTERNS_PATH),
                output_dir=tmpdir,
            ).run(code)

            self.assertEqual(len(result.final_report["vulnerabilities"]), 0)
            self.assertEqual(result.comparative_report()["improvement_percent"], 100.0)
            self.assertTrue((Path(tmpdir) / "final_output.py").exists())
            self.assertTrue((Path(tmpdir) / "comparison_report.json").exists())

    def test_parse_remediation_response_accepts_strict_json(self) -> None:
        response = '{"explanation": "Fixed SQLi.", "fixed_code": "print(\\"fixed\\")"}'
        self.assertEqual(parse_remediation_response(response), 'print("fixed")\n')

    def test_parse_remediation_response_rejects_unstructured_output(self) -> None:
        response = """Here is the fix:

```python
print("fixed")
```
"""
        with self.assertRaises(ValueError):
            parse_remediation_response(response)

    def test_validation_ignores_sanitized_flows_as_active_vulnerabilities(self) -> None:
        code = """def lookup(request, cursor):
    user_id = request.args.get("id")
    safe_user_id = parametrize(user_id)
    query = "SELECT * FROM users WHERE id = " + safe_user_id
    cursor.execute(query)
"""
        result = validate_code(code, str(PATTERNS_PATH))
        self.assertEqual(result.vulnerabilities, [])
        self.assertGreater(len(result.raw_report), 0)

    def test_prompt_includes_only_relevant_analyzer_patterns(self) -> None:
        code = EXAMPLE_INPUT.read_text(encoding="utf-8")
        report = validate_code(code, str(PATTERNS_PATH)).to_dict()
        patterns = load_relevant_patterns(str(PATTERNS_PATH), report)
        prompt = build_initial_prompt(code, report, patterns)

        self.assertIn("Relevant analyzer patterns from 5_patterns.json", prompt)
        self.assertIn('"vulnerability": "SQLi"', prompt)
        self.assertIn('"parametrize"', prompt)
        self.assertIn('"execute"', prompt)
        self.assertNotIn('"vulnerability": "XSS"', prompt)

    def test_mock_remediation_supports_multiple_vulnerability_types(self) -> None:
        snippets = [
            """def vulnerable_profile(request):
    display_name = request.args.get("name")
    html = "<h1>" + display_name + "</h1>"
    render_template_string(html)
""",
            """def vulnerable_command(request):
    host = request.args.get("host")
    command = "ping -c 1 " + host
    system(command)
""",
            """def vulnerable_download(request):
    filename = request.args.get("file")
    open(filename)
""",
            """def vulnerable_fetch(request):
    target_url = request.args.get("url")
    urlopen(target_url)
""",
        ]
        client = LLMClient(
            LLMConfig(
                use_ai=False,
                mock_responses_path=str(MOCK_RESPONSES),
            )
        )

        for snippet in snippets:
            with self.subTest(snippet=snippet.splitlines()[0]):
                baseline = validate_code(snippet, str(PATTERNS_PATH))
                self.assertGreater(len(baseline.vulnerabilities), 0)

                result = RemediationLoop(
                    llm_client=client,
                    patterns_path=str(PATTERNS_PATH),
                ).run(snippet)

                self.assertEqual(result.final_report["vulnerabilities"], [])

    def test_mock_remediation_preserves_code_when_fixing_multiple_findings(self) -> None:
        snippet = """def vulnerable_profile(request):
    display_name = request.args.get("name")
    html = "<h1>" + display_name + "</h1>"
    render_template_string(html)

def vulnerable_download(request):
    filename = request.args.get("file")
    open(filename)
"""
        client = LLMClient(
            LLMConfig(
                use_ai=False,
                mock_responses_path=str(MOCK_RESPONSES),
            )
        )

        result = RemediationLoop(
            llm_client=client,
            patterns_path=str(PATTERNS_PATH),
        ).run(snippet)

        self.assertIn("def vulnerable_profile", result.final_code)
        self.assertIn("def vulnerable_download", result.final_code)
        self.assertIn("render_template_string(html)", result.final_code)
        self.assertIn("open(safe_filename)", result.final_code)
        self.assertEqual(result.final_report["vulnerabilities"], [])

    def test_missing_top_level_definition_guard_detects_removed_functions(self) -> None:
        original = "def keep_me():\n    pass\n\ndef also_keep_me():\n    pass\n"
        candidate = "def keep_me():\n    pass\n"
        self.assertEqual(missing_top_level_definitions(original, candidate), ["also_keep_me"])


if __name__ == "__main__":
    unittest.main()
