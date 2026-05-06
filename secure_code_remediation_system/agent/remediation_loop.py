from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from agent.llm_client import LLMClient
from agent.prompt_builder import SYSTEM_PROMPT, build_feedback_prompt, build_initial_prompt, load_relevant_patterns
from utils.scoring import improved, improvement_percentage
from validation.validator import ValidationResult, validate_code, write_report


MAX_ITERATIONS = 3


@dataclass
class IterationResult:
    iteration: int
    accepted: bool
    reason: str
    code: str
    report: Dict[str, Any]
    ai_response: str


@dataclass
class RemediationResult:
    initial_code: str
    final_code: str
    initial_report: Dict[str, Any]
    final_report: Dict[str, Any]
    iterations: List[IterationResult] = field(default_factory=list)

    def comparative_report(self) -> Dict[str, Any]:
        initial_count = len(self.initial_report["vulnerabilities"])
        final_count = len(self.final_report["vulnerabilities"])
        return {
            "initial_vulnerabilities": initial_count,
            "final_vulnerabilities": final_count,
            "improvement_percent": improvement_percentage(initial_count, final_count),
            "initial_report": self.initial_report,
            "final_report": self.final_report,
            "iterations": [
                {
                    "iteration": item.iteration,
                    "accepted": item.accepted,
                    "reason": item.reason,
                    "report": item.report,
                }
                for item in self.iterations
            ],
        }


class RemediationLoop:
    def __init__(
        self,
        llm_client: LLMClient,
        patterns_path: str,
        max_iterations: int = MAX_ITERATIONS,
        output_dir: Optional[str] = None,
    ) -> None:
        self.llm_client = llm_client
        self.patterns_path = patterns_path
        self.max_iterations = max(1, int(max_iterations))
        self.output_dir = Path(output_dir) if output_dir else None

    def run(self, code: str) -> RemediationResult:
        current_code = code
        baseline = validate_code(current_code, self.patterns_path)
        initial_report = baseline.to_dict()
        iterations: List[IterationResult] = []

        if not baseline.vulnerabilities:
            result = RemediationResult(code, current_code, initial_report, initial_report, iterations)
            self._write_outputs(result)
            return result

        for iteration in range(self.max_iterations):
            report_for_prompt = baseline.to_dict()
            relevant_patterns = load_relevant_patterns(self.patterns_path, report_for_prompt)
            prompt = (
                build_initial_prompt(current_code, report_for_prompt, relevant_patterns)
                if iteration == 0
                else build_feedback_prompt(current_code, report_for_prompt, relevant_patterns)
            )
            ai_response = self.llm_client.generate(SYSTEM_PROMPT, prompt, iteration)
            try:
                candidate_code = parse_remediation_response(ai_response)
                missing_defs = missing_top_level_definitions(current_code, candidate_code)
                if missing_defs:
                    raise ValueError(
                        "AI response removed top-level definitions that must be preserved: "
                        + ", ".join(missing_defs)
                    )
            except ValueError as exc:
                iterations.append(
                    IterationResult(
                        iteration=iteration + 1,
                        accepted=False,
                        reason=f"AI response rejected: {exc}",
                        code=current_code,
                        report=baseline.to_dict(),
                        ai_response=ai_response,
                    )
                )
                break

            try:
                candidate_validation = validate_code(candidate_code, self.patterns_path)
            except SyntaxError as exc:
                iterations.append(
                    IterationResult(
                        iteration=iteration + 1,
                        accepted=False,
                        reason=f"Candidate code is not valid Python: {exc.msg}.",
                        code=candidate_code,
                        report=baseline.to_dict(),
                        ai_response=ai_response,
                    )
                )
                break

            accepted, reason = self._assess_candidate(candidate_validation, baseline)
            iteration_result = IterationResult(
                iteration=iteration + 1,
                accepted=accepted,
                reason=reason,
                code=candidate_code,
                report=candidate_validation.to_dict(),
                ai_response=ai_response,
            )
            iterations.append(iteration_result)
            self._write_iteration(iteration_result)

            if not accepted:
                break

            current_code = candidate_code
            baseline = candidate_validation

            if not baseline.vulnerabilities:
                break

        final_report = baseline.to_dict()
        result = RemediationResult(code, current_code, initial_report, final_report, iterations)
        self._write_outputs(result)
        return result

    @staticmethod
    def _assess_candidate(candidate: ValidationResult, baseline: ValidationResult) -> tuple[bool, str]:
        if not candidate.vulnerabilities:
            return True, "All active vulnerabilities were remediated."
        if improved(candidate.vulnerabilities, baseline.vulnerabilities):
            return True, "The candidate reduced active vulnerability count or severity."
        return False, "No deterministic improvement was detected by the analyzer."

    def _write_iteration(self, iteration: IterationResult) -> None:
        if not self.output_dir:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / f"iteration_{iteration.iteration}.py").write_text(iteration.code, encoding="utf-8")
        write_report(str(self.output_dir / f"iteration_{iteration.iteration}.report.json"), iteration.report)

    def _write_outputs(self, result: RemediationResult) -> None:
        if not self.output_dir:
            return
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "final_output.py").write_text(result.final_code, encoding="utf-8")
        write_report(str(self.output_dir / "comparison_report.json"), result.comparative_report())


def parse_remediation_response(ai_output: str) -> str:
    payload = _parse_json_payload(ai_output)
    if not isinstance(payload, dict):
        raise ValueError("response must be a JSON object.")

    required_keys = {"explanation", "fixed_code"}
    if set(payload.keys()) != required_keys:
        raise ValueError('response JSON must contain exactly "explanation" and "fixed_code".')

    explanation = payload.get("explanation")
    fixed_code = payload.get("fixed_code")
    if not isinstance(explanation, str) or not explanation.strip():
        raise ValueError('"explanation" must be a non-empty string.')
    if not isinstance(fixed_code, str) or not fixed_code.strip():
        raise ValueError('"fixed_code" must be a non-empty string.')

    return fixed_code.strip() + "\n"


def _parse_json_payload(ai_output: str) -> Any:
    text = ai_output.strip()
    if text.startswith("```"):
        match = re.fullmatch(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
        if match is None:
            raise ValueError("response must be raw JSON or a single JSON code block.")
        text = match.group(1).strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"response is not valid JSON: {exc.msg}.") from exc


def missing_top_level_definitions(original_code: str, candidate_code: str) -> List[str]:
    original_defs = _top_level_definitions(original_code)
    candidate_defs = _top_level_definitions(candidate_code)
    return [name for name in original_defs if name not in candidate_defs]


def _top_level_definitions(code: str) -> List[str]:
    tree = ast.parse(code)
    names: List[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.append(node.name)
    return names
