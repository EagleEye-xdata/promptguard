from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import AttackPattern
from ..schemas import GeneratePayload
from ..services.mutator import mutate

router = APIRouter(tags=["attacks"])


@router.get("/attacks")
def list_attacks(
    category: str | None = None,
    severity: str | None = None,
    origin: str | None = None,
    q: str | None = None,
    db: Session = Depends(get_db)
):
    query = db.query(AttackPattern)
    if category:
        query = query.filter_by(category=category)
    if severity:
        query = query.filter(AttackPattern.source_severity == severity.upper())
    if origin:
        query = query.filter_by(origin=origin)
    if q:
        query = query.filter((AttackPattern.title.ilike(f"%{q}%")) | (AttackPattern.cleaned_prompt.ilike(f"%{q}%")))
    return [
        {
            "id": a.id,
            "category": a.category,
            "title": a.title,
            "prompt": a.raw_prompt,
            "turns": a.turns,
            "expected_safe_behaviour": a.expected_safe_behaviour,
            "success_indicators": a.success_indicators,
            "failure_indicators": a.failure_indicators,
            "source_severity": a.source_severity,
            "remediation": a.remediation,
            "origin": a.origin,
            "mutation": a.mutation,
            "provenance": a.provenance
        }
        for a in query.limit(1000)
    ]


@router.post("/generate-payload")
def generate_payload(body: GeneratePayload, db: Session = Depends(get_db)):
    prompt = body.prompt_text
    aid = body.attack_pattern_id
    if aid:
        a = db.get(AttackPattern, aid)
        if a:
            prompt = a.raw_prompt
    if not prompt:
        raise HTTPException(400, "Must provide prompt_text or valid attack_pattern_id")
    available_mutations = body.mutations if body.mutations else [
        "base64", "hex", "leetspeak", "unicode_homoglyph", "zero_width_insert",
        "roleplay_wrap", "delimiter_inject", "split_2_turns", "translate_hi", "html_comment_wrap"
    ]
    return {
        "attack_pattern_id": aid,
        "original_prompt": prompt,
        "variants": [{"mutation": m, "payload": mutate(prompt, m)} for m in available_mutations]
    }
