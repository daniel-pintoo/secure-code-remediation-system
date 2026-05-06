from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from agent.llm_client import LLMClient, LLMConfig
from agent.remediation_loop import MAX_ITERATIONS, RemediationLoop
from utils.env import load_env

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PATTERNS = str(PROJECT_ROOT / "5_patterns.json")

load_env(PROJECT_ROOT / ".env")

app = FastAPI(title="AI-Assisted Secure Code Remediation System")


INDEX_HTML_PATH = Path(__file__).with_name("index.html")


class AnalyzeRequest(BaseModel):
    code: str
    patterns_path: Optional[str] = None
    max_iterations: int = Field(default=MAX_ITERATIONS, ge=1, le=MAX_ITERATIONS)
    use_ai: Optional[bool] = None


class AnalyzeResponse(BaseModel):
    final_code: str
    report: Dict[str, Any]


@app.get("/patterns")
def patterns() -> List[Dict[str, Any]]:
    return json.loads(Path(DEFAULT_PATTERNS).read_text(encoding="utf-8"))


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_HTML_PATH.read_text(encoding="utf-8")


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(request: AnalyzeRequest) -> AnalyzeResponse:
    config = LLMConfig.from_env()
    if request.use_ai is not None:
        config = LLMConfig(
            use_ai=request.use_ai,
            api_key=config.api_key,
            api_url=config.api_url,
            model=config.model,
            mock_responses_path=config.mock_responses_path,
            timeout_seconds=config.timeout_seconds,
        )

    loop = RemediationLoop(
        llm_client=LLMClient(config),
        patterns_path=request.patterns_path or DEFAULT_PATTERNS,
        max_iterations=request.max_iterations,
    )
    try:
        result = loop.run(request.code)
    except SyntaxError as exc:
        raise HTTPException(status_code=400, detail=f"Input code is not valid Python: {exc.msg}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Remediation failed: {exc}") from exc

    return AnalyzeResponse(final_code=result.final_code, report=result.comparative_report())
