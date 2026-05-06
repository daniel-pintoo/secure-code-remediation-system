from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from agent.llm_client import LLMClient, LLMConfig
from agent.remediation_loop import MAX_ITERATIONS, RemediationLoop


from utils.env import load_env

PROJECT_ROOT = Path(__file__).resolve().parent


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("max-iterations must be >= 1")
    return parsed




def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-assisted secure code remediation system.")
    parser.add_argument("code_path", help="Path to the Python file to analyze and remediate.")
    parser.add_argument(
        "--patterns",
        default=str(PROJECT_ROOT / "5_patterns.json"),
        help="Path to the analyzer vulnerability patterns JSON file.",
    )
    parser.add_argument(
        "--output-dir",
        default=str(PROJECT_ROOT / "output" / "remediation"),
        help="Directory where iteration code and reports will be written.",
    )
    parser.add_argument("--max-iterations", type=positive_int, default=MAX_ITERATIONS)
    parser.add_argument("--use-ai", action="store_true", help="Call the configured LLM API instead of mock mode.")
    return parser.parse_args()


def main() -> int:
    load_env(PROJECT_ROOT / ".env")
    args = parse_args()

    config = LLMConfig.from_env()
    if args.use_ai:
        config = LLMConfig(
            use_ai=True,
            api_key=config.api_key,
            api_url=config.api_url,
            model=config.model,
            mock_responses_path=config.mock_responses_path,
            timeout_seconds=config.timeout_seconds,
        )

    code = Path(args.code_path).read_text(encoding="utf-8")
    loop = RemediationLoop(
        llm_client=LLMClient(config),
        patterns_path=args.patterns,
        max_iterations=args.max_iterations,
        output_dir=args.output_dir,
    )
    result = loop.run(code)

    print(json.dumps(result.comparative_report(), indent=2))
    print(f"\nFinal code written to: {Path(args.output_dir) / 'final_output.py'}")
    print(f"Comparison report written to: {Path(args.output_dir) / 'comparison_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
