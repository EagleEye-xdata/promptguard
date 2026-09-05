import uuid
from datetime import datetime
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from ..database import SessionLocal, get_db
from ..models import AttackPattern, Target, TestExecution, TestRun
from ..schemas import TestCreate
from ..services.adapter import call_target
from ..services.request_inspector import get_corpus, inspect_request
from ..services.response_inspector import inspect_response
from ..services.analyzer import severity_from_score
from ..services.judge import judge
from ..services.mutator import mutate

router = APIRouter(tags=["tests"])


async def execute_run(run_id: int):
    db = SessionLocal()
    try:
        run = db.get(TestRun, run_id)
        target = db.get(Target, run.target_id)
        run.status, run.started_at = "running", datetime.utcnow()
        db.commit()

        q = db.query(AttackPattern).filter_by(origin="seed")
        cats = run.config.get("categories") or []
        if cats:
            q = q.filter(AttackPattern.category.in_(cats))
        selected = q.limit(run.config["count"]).all()
        work = []

        for a in selected:
            work.append((a, a.raw_prompt, a.mutation))
            for m in run.config.get("mutations", [])[:run.config.get("variants_per_attack", 0)]:
                value = mutate(a.raw_prompt, m)
                prompt = "\n".join(value) if isinstance(value, list) else value
                mid = f"MUT-{uuid.uuid4().hex[:12]}"
                ma = AttackPattern(
                    id=mid, category=a.category, title=f"{a.title} [{m}]",
                    raw_prompt=prompt, cleaned_prompt=prompt, raw_hash=uuid.uuid4().hex,
                    parameters={}, presumptions=a.presumptions, expected_safe_behaviour=a.expected_safe_behaviour,
                    success_indicators=a.success_indicators, failure_indicators=a.failure_indicators,
                    source_severity=a.source_severity, remediation=a.remediation, origin="mutated",
                    parent_pattern_id=a.id, mutation=m, turns=value if isinstance(value, list) else None,
                    provenance={"parent": a.id}
                )
                db.add(ma); db.flush()
                work.append((ma, prompt, m))

        run.total = len(work); db.commit()

        for seq, (a, prompt, mutation_name) in enumerate(work, 1):
            root_id = a.parent_pattern_id or a.id
            family = {str(row.id) for row in db.query(AttackPattern).filter((AttackPattern.id == root_id) | (AttackPattern.parent_pattern_id == root_id)).all()}
            req = inspect_request(prompt, get_corpus(db), exclude_ids=family)
            reached = not (run.config.get("enforce_request_block") and req["action"] == "BLOCK")
            started, response = datetime.utcnow(), None

            try:
                if not target.capabilities.get("multi_turn", True) and a.turns:
                    outcome, reached, resp = "SKIPPED_INCOMPATIBLE", False, {"risk_score": 0, "action": "ALLOW", "confidence": 1, "evidence": {"reason": "target lacks multi_turn"}, "leakage_type": None}
                    run.skipped += 1
                elif reached:
                    response = await call_target(target, prompt, f"run-{run_id}-{seq}")
                    j = await judge(prompt, response, a.title, a.expected_safe_behaviour, target.declared_policy) if run.config.get("judge_enabled") else None
                    resp = inspect_response(response, a.success_indicators, a.failure_indicators, target.system_prompt_canary, j)
                    outcome = resp["outcome"]
                else:
                    outcome, resp = "INCONCLUSIVE", {"risk_score": 0, "action": "ALLOW", "confidence": 0.5, "evidence": {"reason": "request_blocked"}, "leakage_type": None}
                    run.inconclusive += 1
            except Exception as exc:
                outcome, resp = "ERROR", {"risk_score": 0, "action": "ALLOW", "confidence": 0, "evidence": {"error": str(exc)[:500]}, "leakage_type": None}
                run.errors += 1

            if outcome == "SUCCESSFUL": run.successful += 1
            elif outcome == "RESISTED": run.resisted += 1
            elif outcome == "INCONCLUSIVE" and reached: run.inconclusive += 1
            run.executed += 1

            maxrisk = max(req["risk_score"], resp["risk_score"])
            ex = TestExecution(
                test_run_id=run.id, attack_pattern_id=a.id, session_id=f"run-{run_id}-{seq}", sequence_number=seq,
                request_text=prompt, request_risk_score=req["risk_score"], request_action=req["action"], request_evidence=req["evidence"],
                reached_target=reached, response_text=response, response_risk_score=resp["risk_score"], response_action=resp["action"],
                response_evidence={**resp["evidence"], "leakage_type": resp.get("leakage_type")}, outcome=outcome, source_severity=a.source_severity,
                derived_severity=severity_from_score(maxrisk), confidence=max(req["confidence"], resp["confidence"]),
                latency_ms=(datetime.utcnow() - started).total_seconds() * 1000
            )
            db.add(ex); db.commit()

        run.status, run.finished_at = "completed", datetime.utcnow()
        db.commit()
    finally:
        db.close()


@router.post("/tests", status_code=202)
def start_test(body: TestCreate, tasks: BackgroundTasks, db: Session = Depends(get_db)):
    if not db.get(Target, body.target_id): raise HTTPException(404, "target not found")
    run = TestRun(target_id=body.target_id, config=body.model_dump(exclude={"target_id"}))
    db.add(run); db.commit()
    tasks.add_task(execute_run, run.id)
    return {"test_run_id": run.id, "status": "queued"}


@router.get("/tests/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    r = db.get(TestRun, run_id)
    if not r: raise HTTPException(404, "run not found")
    return {c: getattr(r, c) for c in ["id", "target_id", "mode", "status", "total", "executed", "resisted", "successful", "inconclusive", "skipped", "errors", "started_at", "finished_at"]}


@router.get("/tests/{run_id}/executions")
def get_executions(run_id: int, db: Session = Depends(get_db)):
    return [
        {c: getattr(e, c) for c in ["id", "attack_pattern_id", "sequence_number", "request_text", "request_risk_score", "request_action", "request_evidence", "reached_target", "response_text", "response_risk_score", "response_action", "response_evidence", "outcome", "source_severity", "derived_severity", "confidence", "latency_ms"]}
        for e in db.query(TestExecution).filter_by(test_run_id=run_id).order_by(TestExecution.sequence_number)
    ]
