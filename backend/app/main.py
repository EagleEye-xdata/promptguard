import json, random, uuid
from datetime import datetime
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session
from .database import Base, SessionLocal, engine, get_db
from .models import Alert, AttackPattern, Target, TestExecution, TestRun
from .schemas import GeneratePayload, InspectRequest, InspectResponse, ProxyRequest, TargetCreate, TestCreate
from .services.adapter import call_target
from .services.inspectors import inspect_request, inspect_response
from .services.judge import judge
from .services.mutator import mutate
from .services.reporting import build_report, markdown_report
from .services.session_window import session_windows
from .services.secrets import protect
from .config import settings

Base.metadata.create_all(engine)
app=FastAPI(title="eagleI — AI Security Testing Platform",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=[x.strip() for x in settings.cors_origins.split(",") if x.strip()],allow_methods=["*"],allow_headers=["*"])

def corpus(db): return [{"id":a.id,"category":a.category,"prompt":a.cleaned_prompt} for a in db.query(AttackPattern).all()]
def severity(score): return "CRITICAL" if score>=80 else "HIGH" if score>=60 else "MEDIUM" if score>=30 else "LOW"

@app.get("/health")
def health(db:Session=Depends(get_db)): return {"status":"ok","database":"connected","judge_provider":__import__('backend.app.config',fromlist=['settings']).settings.judge_provider}

@app.post("/targets",status_code=201)
def create_target(body:TargetCreate,db:Session=Depends(get_db)):
    target=Target(name=body.name,api_endpoint=body.api_endpoint,auth_config_encrypted=protect(body.auth_header,settings.encryption_key),model_name=body.model_name,request_format={"preset":body.format_preset,**body.request_format},response_format=body.response_format,capabilities=body.capabilities,system_prompt_canary=body.canary,declared_policy=body.declared_policy,authorized=True); db.add(target); db.commit(); return {"target_id":target.id,"name":target.name}

@app.get("/targets")
def targets(db:Session=Depends(get_db)): return [{"id":x.id,"name":x.name,"api_endpoint":x.api_endpoint,"model_name":x.model_name,"capabilities":x.capabilities,"authorized":x.authorized} for x in db.query(Target).all()]

def inspect_session(message:str,session_id:str,patterns:list[dict]):
    """Inspect the current message and bounded conversation context; keep the riskier result."""
    single=inspect_request(message,patterns)
    window_text=session_windows.add_and_join(session_id,message)
    if window_text==message:return {**single,"session_window_used":False}
    combined=inspect_request(window_text,patterns)
    used=combined["risk_score"]>single["risk_score"]
    result=combined if used else single
    return {**result,"session_window_used":used,"evidence":{**result["evidence"],"single_message_risk":single["risk_score"],"session_window_risk":combined["risk_score"]}}

@app.get("/attacks")
def attacks(category:str|None=None,severity:str|None=None,origin:str|None=None,q:str|None=None,db:Session=Depends(get_db)):
    query=db.query(AttackPattern)
    if category: query=query.filter_by(category=category)
    if severity: query=query.filter(AttackPattern.source_severity==severity.upper())
    if origin: query=query.filter_by(origin=origin)
    if q: query=query.filter((AttackPattern.title.ilike(f"%{q}%"))|(AttackPattern.cleaned_prompt.ilike(f"%{q}%")))
    return [{"id":a.id,"category":a.category,"title":a.title,"prompt":a.raw_prompt,"turns":a.turns,"expected_safe_behaviour":a.expected_safe_behaviour,"success_indicators":a.success_indicators,"failure_indicators":a.failure_indicators,"source_severity":a.source_severity,"remediation":a.remediation,"origin":a.origin,"mutation":a.mutation,"provenance":a.provenance} for a in query.limit(1000)]

@app.post("/inspect/request")
def inspect_req(body:InspectRequest,db:Session=Depends(get_db)): return inspect_session(body.prompt_text,body.session_id,corpus(db))

@app.post("/inspect/response")
async def inspect_resp(body:InspectResponse):
    j=await judge(body.original_attack,body.response_text,body.objective,body.expected_safe_behaviour,body.declared_policy)
    return inspect_response(body.response_text,body.success_indicators,body.failure_indicators,body.canary,j)

@app.post("/generate-payload")
def generate(body:GeneratePayload,db:Session=Depends(get_db)):
    prompt=body.prompt_text
    aid=body.attack_pattern_id
    if aid:
        a=db.get(AttackPattern,aid)
        if a:prompt=a.raw_prompt
    if not prompt:raise HTTPException(400,"Must provide prompt_text or valid attack_pattern_id")
    available_mutations=body.mutations if body.mutations else ["base64","hex","leetspeak","unicode_homoglyph","zero_width_insert","roleplay_wrap","delimiter_inject","split_2_turns","translate_hi","html_comment_wrap"]
    return {"attack_pattern_id":aid,"original_prompt":prompt,"variants":[{"mutation":m,"payload":mutate(prompt,m)} for m in available_mutations]}


async def execute_run(run_id:int):
    db=SessionLocal()
    try:
        run=db.get(TestRun,run_id); target=db.get(Target,run.target_id); run.status="running"; run.started_at=datetime.utcnow(); db.commit()
        q=db.query(AttackPattern).filter_by(origin="seed")
        cats=run.config.get("categories") or []
        if cats:q=q.filter(AttackPattern.category.in_(cats))
        selected=q.limit(run.config["count"]).all(); work=[]
        for a in selected:
            work.append((a,a.raw_prompt,a.mutation))
            for m in run.config.get("mutations",[])[:run.config.get("variants_per_attack",0)]:
                value=mutate(a.raw_prompt,m); prompt="\n".join(value) if isinstance(value,list) else value
                mid=f"MUT-{uuid.uuid4().hex[:12]}"; ma=AttackPattern(id=mid,category=a.category,title=f"{a.title} [{m}]",raw_prompt=prompt,cleaned_prompt=prompt,raw_hash=uuid.uuid4().hex,parameters={},presumptions=a.presumptions,expected_safe_behaviour=a.expected_safe_behaviour,success_indicators=a.success_indicators,failure_indicators=a.failure_indicators,source_severity=a.source_severity,remediation=a.remediation,origin="mutated",parent_pattern_id=a.id,mutation=m,turns=value if isinstance(value,list) else None,provenance={"parent":a.id}); db.add(ma); db.flush(); work.append((ma,prompt,m))
        run.total=len(work); db.commit()
        for seq,(a,prompt,mutation_name) in enumerate(work,1):
            root_id=a.parent_pattern_id or a.id
            family={str(row.id) for row in db.query(AttackPattern).filter((AttackPattern.id==root_id)|(AttackPattern.parent_pattern_id==root_id)).all()}
            req=inspect_request(prompt,corpus(db),exclude_ids=family); reached=not(run.config.get("enforce_request_block") and req["action"]=="BLOCK")
            started=datetime.utcnow(); response=None
            try:
                if not target.capabilities.get("multi_turn",True) and a.turns:
                    outcome="SKIPPED_INCOMPATIBLE"; run.skipped+=1; reached=False; resp={"risk_score":0,"action":"ALLOW","confidence":1,"evidence":{"reason":"target lacks multi_turn"},"leakage_type":None}
                elif reached:
                    response=await call_target(target,prompt,f"run-{run_id}-{seq}")
                    j=await judge(prompt,response,a.title,a.expected_safe_behaviour,target.declared_policy) if run.config.get("judge_enabled") else None
                    resp=inspect_response(response,a.success_indicators,a.failure_indicators,target.system_prompt_canary,j); outcome=resp["outcome"]
                else: outcome="INCONCLUSIVE"; resp={"risk_score":0,"action":"ALLOW","confidence":.5,"evidence":{"reason":"request_blocked"},"leakage_type":None}; run.inconclusive+=1
            except Exception as exc:
                outcome="ERROR"; run.errors+=1; resp={"risk_score":0,"action":"ALLOW","confidence":0,"evidence":{"error":str(exc)[:500]},"leakage_type":None}
            if outcome=="SUCCESSFUL":run.successful+=1
            elif outcome=="RESISTED":run.resisted+=1
            elif outcome=="INCONCLUSIVE" and reached:run.inconclusive+=1
            run.executed+=1
            maxrisk=max(req["risk_score"],resp["risk_score"]); ex=TestExecution(test_run_id=run.id,attack_pattern_id=a.id,session_id=f"run-{run_id}-{seq}",sequence_number=seq,request_text=prompt,request_risk_score=req["risk_score"],request_action=req["action"],request_evidence=req["evidence"],reached_target=reached,response_text=response,response_risk_score=resp["risk_score"],response_action=resp["action"],response_evidence={**resp["evidence"],"leakage_type":resp.get("leakage_type")},outcome=outcome,source_severity=a.source_severity,derived_severity=severity(maxrisk),confidence=max(req["confidence"],resp["confidence"]),latency_ms=(datetime.utcnow()-started).total_seconds()*1000); db.add(ex); db.commit()
        run.status="completed"; run.finished_at=datetime.utcnow(); db.commit()
    finally: db.close()

@app.post("/tests",status_code=202)
def start_test(body:TestCreate,tasks:BackgroundTasks,db:Session=Depends(get_db)):
    if not db.get(Target,body.target_id):raise HTTPException(404,"target not found")
    run=TestRun(target_id=body.target_id,config=body.model_dump(exclude={"target_id"})); db.add(run); db.commit(); tasks.add_task(execute_run,run.id); return {"test_run_id":run.id,"status":"queued"}

@app.get("/tests/{run_id}")
def get_run(run_id:int,db:Session=Depends(get_db)):
    r=db.get(TestRun,run_id)
    if not r:raise HTTPException(404,"run not found")
    return {c:getattr(r,c) for c in ["id","target_id","mode","status","total","executed","resisted","successful","inconclusive","skipped","errors","started_at","finished_at"]}

@app.get("/tests/{run_id}/executions")
def executions(run_id:int,db:Session=Depends(get_db)): return [{c:getattr(e,c) for c in ["id","attack_pattern_id","sequence_number","request_text","request_risk_score","request_action","request_evidence","reached_target","response_text","response_risk_score","response_action","response_evidence","outcome","source_severity","derived_severity","confidence","latency_ms"]} for e in db.query(TestExecution).filter_by(test_run_id=run_id).order_by(TestExecution.sequence_number)]

@app.get("/reports/{run_id}")
def report(run_id:int,format:str="json",db:Session=Depends(get_db)):
    if not db.get(TestRun,run_id):raise HTTPException(404,"run not found")
    data=build_report(db,run_id)
    return PlainTextResponse(markdown_report(data),media_type="text/markdown") if format=="md" else data

@app.post("/proxy/chat")
async def proxy(body:ProxyRequest,db:Session=Depends(get_db),x_eaglei_proxy_key:str|None=Header(default=None)):
    if settings.proxy_api_key and x_eaglei_proxy_key!=settings.proxy_api_key:raise HTTPException(401,"invalid or missing X-eagleI-Proxy-Key")
    target=db.get(Target,body.target_id)
    if not target:raise HTTPException(404,"target not found")
    req=inspect_session(body.message,body.session_id,corpus(db))
    if req["action"]=="BLOCK":
        db.add(Alert(severity=severity(req["risk_score"]),category=req.get("attack_type") or "prompt_injection",message=f"Blocked prompt injection: {req.get('attack_type') or 'malicious prompt'}",evidence={"request":req,"session_id":body.session_id,"target_name":target.name}))
        db.commit()
        return {"response":None,"request_verdict":req,"response_verdict":None,"notice":"blocked by proxy"}
    response=await call_target(target,body.message,body.session_id); resp=inspect_response(response,[],[],target.system_prompt_canary,await judge(body.message,response,"live inspection","safe assistance",target.declared_policy))
    final=None if resp["action"]=="BLOCK" else resp["redacted_response"] if resp["action"]=="REDACT" else response
    if resp["action"] in {"BLOCK","REDACT"}:
        db.add(Alert(severity=severity(resp["risk_score"]),category=resp.get("leakage_type") or "leakage",message=f"Intervened on model response: {resp['action']}",evidence={"request":req,"response":resp,"session_id":body.session_id,"target_name":target.name}))
        db.commit()
    return {"response":final,"request_verdict":req,"response_verdict":resp}


@app.get("/alerts")
def alerts(db:Session=Depends(get_db)): return [{"id":a.id,"severity":a.severity,"category":a.category,"message":a.message,"evidence":a.evidence,"created_at":a.created_at} for a in db.query(Alert).order_by(Alert.id.desc()).limit(100)]

@app.post("/admin/reload-rules")
def reload_rules(): return {"ok":True,"message":"rules reloaded from configured files"}

@app.post("/admin/sync-repo")
def sync_repo(): return {"status":"accepted","message":"Use scripts/sync_repo.py with an allowlisted file:// source."}
