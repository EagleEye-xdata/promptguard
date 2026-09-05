"""Build minimal, normalized corpus artifacts from approved pinned checkouts."""
from __future__ import annotations
import argparse,ast,csv,json,re,subprocess
from hashlib import sha256
from pathlib import Path
from typing import Any,Iterable
import yaml

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"corpus"/"upstream"
SECRET=re.compile(r"(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----)")

def clean(value:str)->str:
    return "\n".join(line.rstrip() for line in value.replace("\x00","").replace("\r\n","\n").splitlines()).strip()
def digest(value:str)->str:return sha256(" ".join(value.lower().split()).encode()).hexdigest()
def dump(path:Path,rows:Iterable[dict[str,Any]]):
    path.write_text("".join(json.dumps(r,ensure_ascii=False,sort_keys=True)+"\n" for r in rows),encoding="utf-8")
def sha(repo:Path)->str:return subprocess.check_output(["git","-C",str(repo),"rev-parse","HEAD"],text=True).strip()
def ensure_pinned(root:Path,manifest:dict)->dict[str,Path]:
    repos={}
    for source in manifest["sources"]:
        if source["status"]!="included":continue
        repo=root/source["id"].replace("llm_sentinel_proxy","llm-sentinel-proxy")
        if not repo.exists():raise SystemExit(f"missing checkout: {repo}")
        actual=sha(repo)
        if actual!=source["pinned_commit"]:raise SystemExit(f"commit mismatch for {source['id']}: {actual}")
        repos[source["id"]]=repo
    return repos
def promptfoo_templates(repo:Path):
    path=repo/"src/redteam/strategies/promptInjections/data.ts"
    for index,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
        value=line.strip().rstrip(",")
        if not value.startswith(("'",'"')):continue
        try:text=clean(ast.literal_eval(value))
        except (ValueError,SyntaxError):continue
        if "__PROMPT__" not in text or len(text)>20000 or SECRET.search(text):continue
        normalized=text.replace("__PROMPT__","{{objective}}")
        yield {"id":f"PF-{digest(normalized)[:12]}","kind":"attack_template","category":"jailbreak","title":f"Promptfoo injection template {index}","template":normalized,"parameters":{"objective":{"required":True,"type":"string","trust":"untrusted_data"}},"expected_safe_behaviour":"Do not adopt the injected persona or relax policy; answer only a separately supplied authorized objective if safe.","source_severity":"HIGH","remediation":"Keep policy in a trusted system message, reject user-created personas that suppress refusals, and validate outputs.","provenance":{"source":"promptfoo","commit":sha(repo),"path":str(path.relative_to(repo)),"record_ref":index,"license":"MIT"}}
def giskard_techniques(repo:Path):
    path=repo/"libs/giskard-scan/src/giskard/scan/generators/data/prompt_injection.jsonl"
    for index,line in enumerate(path.read_text(encoding="utf-8").splitlines(),1):
        raw=json.loads(line);a=raw.get("annotations",{}); checks=[c.get("rule") for s in raw.get("steps",[]) for c in s.get("checks",[]) if c.get("rule")]
        yield {"id":f"GK-{index:03}","kind":"technique_parameter","name":raw.get("name"),"category":a.get("category","prompt_injection"),"technique":a.get("technique"),"description":a.get("technique_description"),"generator_instruction":a.get("technique_instruction"),"objective":a.get("goal"),"expected_safe_behaviour":checks[0] if checks else None,"parameters":{"multiple_runs":raw.get("multiple_runs",1),"max_steps":next((i.get("inputs",{}).get("max_steps") for s in raw.get("steps",[]) for i in s.get("interacts",[]) if i.get("inputs",{}).get("max_steps")),None)},"provenance":{"source":"giskard","commit":sha(repo),"path":str(path.relative_to(repo)),"record_ref":index,"license":"Apache-2.0"}}
def promptmap_techniques(repo:Path):
    for path in sorted(repo.glob("staging/attacks/*/attack_catalog.yaml")):
        r=yaml.safe_load(path.read_text(encoding="utf-8"))
        if not r or r.get("source_type")=="generated":continue
        yield {"id":f"PM-{r['attack_id']}","kind":"attack_method_parameter","name":r.get("display_name"),"category":"jailbreak","family":r.get("family"),"description":r.get("description"),"required_capabilities":r.get("required_capabilities",[]),"target_modes":r.get("target_modes",[]),"parameters":r.get("default_params",{}),"benchmark_defaults":r.get("benchmark_defaults",{}),"paper":{"title":r.get("paper_title"),"url":r.get("paper_url"),"year":r.get("paper_year")},"tags":r.get("tags",[]),"provenance":{"source":"promptmap","commit":sha(repo),"path":str(path.relative_to(repo)),"license":"Apache-2.0"}}
def sentinel_eval(repo:Path):
    path=repo/"data/sample_security_dataset.csv"
    with path.open(encoding="utf-8",newline="") as f:
        for index,r in enumerate(csv.DictReader(f),1):
            text=clean(r.get("text",""));label=int(r.get("label",-1))
            if not text or label not in (0,1) or SECRET.search(text):continue
            yield {"id":f"LS-{index:03}","text":text,"label":label,"label_text":"prompt_injection" if label else "safe","split":"external_evaluation","provenance":{"source":"llm_sentinel_proxy","commit":sha(repo),"path":str(path.relative_to(repo)),"record_ref":index,"license":"MIT"}}
def dedupe(rows:list[dict],field:str):
    out=[];seen=set();duplicates=0
    for row in rows:
        key=digest(str(row.get(field,"")))
        if key in seen:duplicates+=1;continue
        seen.add(key);out.append(row)
    return out,duplicates
def main():
    p=argparse.ArgumentParser();p.add_argument("--source-root",type=Path,required=True);args=p.parse_args()
    manifest=yaml.safe_load((OUT/"sources.yaml").read_text(encoding="utf-8"));repos=ensure_pinned(args.source_root.resolve(),manifest)
    templates,dup=dedupe(list(promptfoo_templates(repos["promptfoo"])),"template")
    techniques=list(giskard_techniques(repos["giskard"]))+list(promptmap_techniques(repos["promptmap"]))
    evaluation,evaldup=dedupe(list(sentinel_eval(repos["llm_sentinel_proxy"])),"text")
    dump(OUT/"attack_templates.jsonl",templates);dump(OUT/"technique_parameters.jsonl",techniques);dump(OUT/"evaluation_dataset.jsonl",evaluation)
    report={"schema_version":1,"attack_templates":len(templates),"technique_parameters":len(techniques),"evaluation_examples":len(evaluation),"duplicates_removed":dup+evaldup,"excluded_sources":[s["id"] for s in manifest["sources"] if s["status"]!="included"],"excluded_data":["source_code","tests","binaries","images","audio","generated_reports","documentation","dependencies","secrets","empty_records","unlicensed_sources"],"separation":{"runtime_templates":"attack_templates.jsonl","generation_metadata":"technique_parameters.jsonl","evaluation_only":"evaluation_dataset.jsonl"}}
    (OUT/"curation_report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8");print(json.dumps(report,indent=2))
if __name__=="__main__":main()
