from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Target
from ..schemas import InspectRequest, InspectResponse
from ..services.request_inspector import get_corpus, inspect_session
from ..services.response_inspector import inspect_response
from ..services.analyzer import generate_finding_and_remediation
from ..services.judge import judge
from ..services.adapter import call_target

router = APIRouter(tags=["inspect"])


class PipelineRequest(BaseModel):
    target_id: int
    prompt_text: str
    session_id: str = "default-session"
    attack_category: str | None = None
    mutation: str | None = None
    expected_safe_behaviour: str | None = None
    success_indicators: list[str] = []
    failure_indicators: list[str] = []
    enforce_block: bool = False


@router.post("/inspect/request")
def inspect_req(body: InspectRequest, db: Session = Depends(get_db)):
    return inspect_session(body.prompt_text, body.session_id, get_corpus(db))


@router.post("/inspect/response")
async def inspect_resp(body: InspectResponse):
    j = await judge(body.original_attack, body.response_text, body.objective, body.expected_safe_behaviour, body.declared_policy)
    return inspect_response(body.response_text, body.success_indicators, body.failure_indicators, body.canary, j)


@router.post("/inspect/pipeline")
async def inspect_pipeline(body: PipelineRequest, db: Session = Depends(get_db)):
    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    req_verdict = inspect_session(body.prompt_text, body.session_id, get_corpus(db))
    reached_target = not (body.enforce_block and req_verdict["action"] == "BLOCK")
    raw_response, resp_verdict, target_error = None, None, None

    if reached_target:
        try:
            raw_response = await call_target(target, body.prompt_text, body.session_id)
            j_eval = await judge(body.prompt_text, raw_response, body.attack_category or "prompt injection test", body.expected_safe_behaviour or target.declared_policy, target.declared_policy)
            resp_verdict = inspect_response(raw_response, body.success_indicators, body.failure_indicators, target.system_prompt_canary, j_eval)
        except Exception as exc:
            target_error = str(exc)

    return {
        "prompt": body.prompt_text,
        "mutation": body.mutation,
        "attack_category": body.attack_category or req_verdict.get("attack_type"),
        "target": {"id": target.id, "name": target.name, "model_name": target.model_name},
        "request_verdict": req_verdict,
        "reached_target": reached_target,
        "target_response": raw_response,
        "target_error": target_error,
        "response_verdict": resp_verdict,
        "analyzer": generate_finding_and_remediation(req_verdict, resp_verdict)
    }
