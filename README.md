# AI-Assisted Secure Code Remediation System

This project detects, explains, and remediates vulnerabilities in Python code by combining deterministic static analysis with an LLM-based remediation loop.

The core design principle is simple: do not trust the AI output blindly. Every generated fix is re-scanned by the local analyzer before it is accepted.

## Project Status

This project is still in progress. The deterministic analyzer, mock remediation mode, visual interface,
validation loop, and tests are working. ChatGPT/OpenAI API support is implemented, but it has not yet been
tested end to end with a real API key and active billing.

For now, the recommended demo path is mock mode, which requires no paid API access.

## Architecture

```text
User Python Code
      |
      v
Static Analyzer Baseline Scan
      |
      v
Structured Vulnerability Report
      |
      v
AI Remediation Agent or Mock Response
      |
      v
Generated Code Fix
      |
      v
Validation Layer Re-runs Analyzer
      |
      +--> vulnerabilities remain and improvement exists: iterate
      |
      +--> no vulnerabilities or no improvement: stop
```

## Remediation Pipeline

```text
1. Input Layer
   CLI input.py or FastAPI / visual web UI
          |
          v
2. Baseline Scan
   py_analyzer.scan_code(code, 5_patterns.json)
          |
          v
3. Report Normalization
   validation/validator.py converts raw taint flows into active vulnerabilities
          |
          v
4. Pattern-Aware Prompt Construction
   agent/prompt_builder.py adds:
   - submitted code
   - active vulnerability report
   - relevant source/sanitizer/sink patterns from 5_patterns.json
   - strict JSON response contract
          |
          v
5. Remediation Generation
   agent/llm_client.py uses either:
   - OpenAI-compatible ChatGPT API
   - offline mock responses for free demos
          |
          v
6. Strict Response Analysis
   agent/remediation_loop.py rejects AI output if it:
   - is not valid JSON
   - does not contain explanation + fixed_code
   - returns invalid Python
   - removes unrelated top-level functions/classes
          |
          v
7. Deterministic Validation
   The generated code is scanned again with the same analyzer and patterns
          |
          v
8. Iterative Decision
   Stop if:
   - no active vulnerabilities remain
   - no improvement is detected
   - MAX_ITERATIONS = 3 is reached
          |
          v
9. Output Layer
   Final fixed code + comparative report + saved iteration artifacts
```

The important security boundary is between steps 6 and 7: the AI may propose a fix, but only the deterministic
analyzer decides whether the fix is accepted.

## Run Locally

The easiest way to review the project is through the visual FastAPI interface. It runs in mock mode by
default, so no ChatGPT/OpenAI API key is required.

1. Clone the repository and enter the project directory:

```sh
git clone https://github.com/daniel-pintoo/secure-code-remediation-system
cd secure-code-remediation-system/secure_code_remediation_system
```

1. Install the Python dependencies:

```sh
pip install -r requirements.txt
```

1. Start the local web app:

```sh
python -m uvicorn api.main:app --reload
```

1. Open the visual interface:

```text
http://127.0.0.1:8000
```

From the page, choose one of the built-in vulnerable snippets, keep `Use real AI API` unchecked, and click
`Run remediation`. The app will run the analyzer-backed remediation loop and show the final fixed code plus
a readable comparative report.

## Visual Demo

The visual interface lets reviewers run the analyzer-backed remediation flow locally, inspect the selected
vulnerability pattern, compare initial and final findings, and review the fixed code.

![AI-Assisted Secure Code Remediation System visual interface](https://raw.githubusercontent.com/daniel-pintoo/secure-code-remediation-system/main/Demo.png)

## Components

- `py_analyzer.py` is the deterministic AST taint analyzer. It detects flows from configured sources to sensitive sinks and exposes `scan_code()` and `scan_file()` for programmatic use.
- `validation/validator.py` re-runs the analyzer and normalizes raw taint flows into active vulnerabilities. Sanitized flows remain in `raw_analyzer_report` for auditability.
- `agent/prompt_builder.py` contains the system prompt and user prompt templates.
- `agent/llm_client.py` supports OpenAI-compatible chat completion APIs and offline mock mode.
- `agent/remediation_loop.py` runs the iterative remediation workflow with `MAX_ITERATIONS = 3`.
- `utils/scoring.py` calculates vulnerability counts, severity averages, and improvement percentages.
- `input.py` is the CLI input layer.
- `api/main.py` provides an optional FastAPI endpoint at `POST /analyze`.
- `examples/` and `mock/` provide a demo that runs without a paid API.

## Vulnerability Patterns

The included `5_patterns.json` file defines configurable sources, sanitizers, sinks, and implicit-flow rules for:

- XSS
- SQL injection
- command injection
- path traversal
- SSRF

## Offline Demo

Mock mode is enabled by default, so the project works without an API key.

```sh
python input.py examples/input.py
```

The CLI writes:

- `output/remediation/iteration_1.py`
- `output/remediation/iteration_1.report.json`
- `output/remediation/final_output.py`
- `output/remediation/comparison_report.json`

The comparison report includes:

```json
{
  "initial_vulnerabilities": 1,
  "final_vulnerabilities": 0,
  "improvement_percent": 100.0
}
```

## Tests

Run the full test suite with:

```sh
python -m unittest discover -s tests
```

The tests include:

- regression checks against the official Software Security specification slices
- offline mock remediation loop validation
- validation behavior for sanitized flows
- generated output/report checks

The specification regression test uses `SPECIFICATION_SLICES_ROOT` when set. In the original workspace it
automatically looks for the sibling `specification-master/specification-master/slices` directory.

## AI Mode

Copy `.env.example` to `.env` and set an API key:

```env
USE_AI=true
LLM_API_KEY=your_api_key_here
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_MODEL=gpt-4o-mini
```

Run:

```sh
python input.py examples/input.py --use-ai
```

The LLM is instructed to:

1. Explain each vulnerability.
2. Fix the vulnerabilities.
3. Return improved code.
4. Avoid modifying unrelated logic.

If vulnerabilities remain, the feedback prompt only asks the model to fix the remaining issues.

AI responses are parsed with a strict contract. The model must return exactly one JSON object with:

```json
{
  "explanation": "Short explanation of the fix.",
  "fixed_code": "Complete corrected Python code."
}
```

Responses that are not valid JSON, omit required fields, return empty code, or remove existing top-level
functions/classes are rejected gracefully and reported as failed iterations. The analyzer still remains the
final validation authority before any candidate fix is accepted.

Prompts include the relevant entries from `5_patterns.json` for the active findings only. This gives the AI
the exact analyzer-recognized sources, sanitizers, sinks, and implicit-flow settings, so generated fixes are
aligned with deterministic validation instead of relying on guessed sanitizer names.

## Visual Web Interface

FastAPI is optional. Install it only if you want to use the browser interface or expose the remediation
system as an HTTP API:

```sh
pip install -r requirements.txt
uvicorn api.main:app --reload
```

Open the visual interface at:

```text
http://127.0.0.1:8000
```

The page lets you paste Python code or load a predefined vulnerable example, select mock mode or real AI
mode, run up to three remediation iterations, and inspect the final code plus a readable analyzer-backed
comparative report.

The automatic API documentation is also available at:

```text
http://127.0.0.1:8000/docs
```

## FastAPI Endpoint

Request:

```http
POST /analyze
Content-Type: application/json

{
  "code": "def handler(request, cursor):\n    user_id = request.args.get(\"id\")\n    cursor.execute(\"SELECT * FROM users WHERE id = \" + user_id)\n",
  "max_iterations": 3,
  "use_ai": false
}
```

Response:

```json
{
  "final_code": "...",
  "report": {
    "initial_vulnerabilities": 1,
    "final_vulnerabilities": 0,
    "improvement_percent": 100.0
  }
}
```

## Raw Analyzer Usage

The original analyzer CLI still works:

```sh
python py_analyzer.py examples/input.py 5_patterns.json
```

It writes the raw analyzer output to:

```text
output/input.output.json
```

## Validation Rules

The remediation loop stops when:

- no active vulnerabilities remain
- the analyzer does not detect an improvement
- the loop reaches `MAX_ITERATIONS = 3`

An improvement means the candidate has fewer active vulnerabilities or a lower weighted severity score.

The analyzer expects syntactically valid Python code. The visual API returns a clear validation error for  
invalid Python syntax. It does not attempt full semantic/runtime validation; undefined variables and framework  
objects are handled according to the static taint-analysis model.

