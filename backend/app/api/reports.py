from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import TestRun
from ..services.reporting import build_report, markdown_report

router = APIRouter(tags=["reports"])


@router.get("/reports/{run_id}")
def get_report(run_id: int, format: str = "json", db: Session = Depends(get_db)):
    if not db.get(TestRun, run_id):
        raise HTTPException(404, "run not found")
    data = build_report(db, run_id)
    return PlainTextResponse(markdown_report(data), media_type="text/markdown") if format == "md" else data
