import re
import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Target, TestRun, TestExecution, Report
from ..schemas import TargetCreate
from ..services.secrets import protect
from ..config import settings

router = APIRouter(tags=["targets"])


def sanitize_endpoint_url(url: str) -> str:
    """Normalizes and fixes malformed URLs (e.g. https://https:// or missing scheme)."""
    clean = (url or "").strip()
    # Strip duplicated schemes like https://https:// or http://https://
    while re.match(r"^(https?:\/\/)+(https?:\/\/)", clean, re.IGNORECASE):
        clean = re.sub(r"^(https?:\/\/)+", "", clean, flags=re.IGNORECASE)
        clean = "https://" + clean
    if not clean.startswith("http://") and not clean.startswith("https://"):
        clean = "https://" + clean
    return clean


@router.post("/targets", status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    clean_url = sanitize_endpoint_url(body.api_endpoint)
    target = Target(
        name=body.name,
        api_endpoint=clean_url,
        auth_config_encrypted=protect(body.auth_header, settings.encryption_key),
        model_name=body.model_name,
        request_format={"preset": body.format_preset, **body.request_format},
        response_format=body.response_format,
        capabilities=body.capabilities,
        system_prompt_canary=body.canary,
        declared_policy=body.declared_policy,
        authorized=True
    )
    db.add(target)
    db.commit()
    return {"target_id": target.id, "name": target.name, "api_endpoint": clean_url}


@router.get("/targets")
def list_targets(db: Session = Depends(get_db)):
    return [
        {
            "id": x.id,
            "name": x.name,
            "api_endpoint": x.api_endpoint,
            "model_name": x.model_name,
            "capabilities": x.capabilities,
            "system_prompt_canary": x.system_prompt_canary,
            "declared_policy": x.declared_policy,
            "authorized": x.authorized
        }
        for x in db.query(Target).all()
    ]


@router.get("/targets/{target_id}/ping")
async def ping_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    endpoint = target.api_endpoint
    health_url = endpoint
    if "/chat" in endpoint:
        health_url = endpoint.replace("/chat", "/health")
    elif "/v1/chat/completions" in endpoint:
        health_url = endpoint.replace("/v1/chat/completions", "/health")

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
            resp = await client.get(health_url)
            return {
                "reachable": resp.status_code in [200, 204, 404, 405],
                "status_code": resp.status_code,
                "endpoint": endpoint
            }
    except Exception as e:
        return {
            "reachable": False,
            "error": str(e)[:150],
            "endpoint": endpoint
        }


@router.delete("/targets/{target_id}")
def delete_target(target_id: int, db: Session = Depends(get_db)):
    target = db.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")

    # Clean up any test runs associated with this target
    runs = db.query(TestRun).filter_by(target_id=target_id).all()
    for r in runs:
        db.query(Report).filter_by(test_run_id=r.id).delete()
        db.query(TestExecution).filter_by(test_run_id=r.id).delete()
        db.delete(r)

    db.delete(target)
    db.commit()
    return {"status": "ok", "deleted_target_id": target_id}
