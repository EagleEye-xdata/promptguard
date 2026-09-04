from collections import Counter, defaultdict
from sqlalchemy.orm import Session
from ..models import AttackPattern, Report, Target, TestExecution, TestRun

def build_report(db:Session,run_id:int)->dict:
    run=db.get(TestRun,run_id); target=db.get(Target,run.target_id); rows=db.query(TestExecution).filter_by(test_run_id=run_id).all()
    categories=defaultdict(lambda:{"executed":0,"successful":0,"resisted":0}) ; severities=Counter(); findings=[]
    for e in rows:
        a=db.get(AttackPattern,e.attack_pattern_id) if e.attack_pattern_id else None; cat=a.category if a else "live"
        categories[cat]["executed"]+=1; categories[cat][e.outcome.lower()]=categories[cat].get(e.outcome.lower(),0)+1; severities[e.derived_severity.lower()]+=1
        findings.append({"execution_id":e.id,"attack_id":e.attack_pattern_id,"category":cat,"title":a.title if a else "Live message","mutation":a.mutation if a else None,"payload_used":e.request_text,"request_verdict":e.request_action,"request_evidence":e.request_evidence,"reached_target":e.reached_target,"outcome":e.outcome,"response_excerpt":(e.response_text or "")[:800],"leakage_type":e.response_evidence.get("leakage_type"),"response_evidence":e.response_evidence,"source_severity":e.source_severity,"derived_severity":e.derived_severity,"confidence":e.confidence,"remediation":a.remediation if a else "Harden instruction boundaries and validate model output."})
    findings.sort(key=lambda x:(x["outcome"]!="SUCCESSFUL",-x["confidence"]))
    risk=round(sum(max(e.request_risk_score,e.response_risk_score) for e in rows)/len(rows),2) if rows else 0
    return {"run_id":run.id,"target_name":target.name,"run_mode":run.mode,"status":run.status,"totals":{"executed":run.executed,"resisted":run.resisted,"successful":run.successful,"inconclusive":run.inconclusive,"skipped_incompatible":run.skipped,"errors":run.errors},"risk_score_overall":risk,"severity_breakdown":dict(severities),"by_category":[{"category":k,**v} for k,v in categories.items()],"findings":findings}

def markdown_report(report:dict)->str:
    t=report["totals"]
    out=[f"# Prompt Injection Security Report — {report['target_name']}","",f"Overall risk score: **{report['risk_score_overall']}/100**",f"Executed: {t['executed']} · Successful: {t['successful']} · Resisted: {t['resisted']} · Inconclusive: {t['inconclusive']} · Skipped: {t['skipped_incompatible']} · Errors: {t['errors']}","","## Findings",""]
    for f in report["findings"]:
        out += [f"### {f['outcome']} — {f['title']}","",f"- Category: {f['category']}; source severity: {f['source_severity']}; derived severity: {f['derived_severity']}.",f"- Request verdict: {f['request_verdict']}; reached target: {f['reached_target']}; confidence: {f['confidence']}.",f"- Payload: `{f['payload_used'][:300]}`",f"- Response: `{f['response_excerpt'][:300]}`",f"- Fix: {f['remediation']}",""]
    return "\n".join(out)
