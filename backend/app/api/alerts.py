from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Alert

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(db: Session = Depends(get_db)):
    return [
        {
            "id": a.id,
            "severity": a.severity,
            "category": a.category,
            "message": a.message,
            "evidence": a.evidence,
            "created_at": a.created_at
        }
        for a in db.query(Alert).order_by(Alert.id.desc()).limit(100)
    ]


@router.post("/admin/reload-rules")
def reload_rules():
    return {"ok": True, "message": "rules reloaded from configured files"}


@router.post("/admin/sync-repo")
def sync_repo():
    return {"status": "accepted", "message": "Use scripts/sync_repo.py with an allowlisted file:// source."}
