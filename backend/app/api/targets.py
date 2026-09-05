from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Target
from ..schemas import TargetCreate
from ..services.secrets import protect
from ..config import settings

router = APIRouter(tags=["targets"])


@router.post("/targets", status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    target = Target(
        name=body.name,
        api_endpoint=body.api_endpoint,
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
    return {"target_id": target.id, "name": target.name}


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
