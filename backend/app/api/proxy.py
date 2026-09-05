from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Alert, Target
from ..schemas import ProxyRequest
from ..services.adapter import call_target
from ..services.request_inspector import get_corpus, inspect_session
from ..services.response_inspector import inspect_response
from ..services.analyzer import severity_from_score
from ..services.judge import judge
from ..config import settings

router = APIRouter(tags=["proxy"])


@router.post("/proxy/chat")
async def proxy_chat(
    body: ProxyRequest,
    db: Session = Depends(get_db),
    x_eaglei_proxy_key: str | None = Header(default=None)
):
    if settings.proxy_api_key and x_eaglei_proxy_key != settings.proxy_api_key:
        raise HTTPException(401, "invalid or missing X-eagleI-Proxy-Key")

    target = db.get(Target, body.target_id)
    if not target:
        raise HTTPException(404, "target not found")

    req = inspect_session(body.message, body.session_id, get_corpus(db))
    if req["action"] == "BLOCK":
        db.add(Alert(
            severity=severity_from_score(req["risk_score"]),
            category=req.get("attack_type") or "prompt_injection",
            message=f"Blocked prompt injection: {req.get('attack_type') or 'malicious prompt'}",
            evidence={"request": req, "session_id": body.session_id, "target_name": target.name}
        ))
        db.commit()
        return {"response": None, "request_verdict": req, "response_verdict": None, "notice": "blocked by proxy"}

    response = await call_target(target, body.message, body.session_id)
    resp = inspect_response(
        response,
        [],
        [],
        target.system_prompt_canary,
        await judge(body.message, response, "live inspection", "safe assistance", target.declared_policy)
    )
    final = None if resp["action"] == "BLOCK" else resp["redacted_response"] if resp["action"] == "REDACT" else response
    if resp["action"] in {"BLOCK", "REDACT"}:
        db.add(Alert(
            severity=severity_from_score(resp["risk_score"]),
            category=resp.get("leakage_type") or "leakage",
            message=f"Intervened on model response: {resp['action']}",
            evidence={"request": req, "response": resp, "session_id": body.session_id, "target_name": target.name}
        ))
        db.commit()

    return {"response": final, "request_verdict": req, "response_verdict": resp}
