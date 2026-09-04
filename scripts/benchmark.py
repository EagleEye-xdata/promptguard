"""Reproducible checker benchmark; prints metrics and does not change data."""
from pathlib import Path
import sys,yaml
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from backend.app.services.inspectors import inspect_request
from backend.app.services.mutator import MUTATIONS,mutate

seed=yaml.safe_load((ROOT/"corpus/seed/attacks.yaml").read_text(encoding="utf-8"))["attacks"]
cases=yaml.safe_load((ROOT/"evaluation/request_benchmark.yaml").read_text(encoding="utf-8"))
corpus=[{"id":a["id"],"category":a["category"],"prompt":a["prompt"]} for a in seed]
def detected(text):return inspect_request(text,corpus)["action"]!="ALLOW"
def metrics(positive,negative):
    tp=sum(detected(x) for x in positive);fn=len(positive)-tp;fp=sum(detected(x) for x in negative);tn=len(negative)-fp
    return {"samples":len(positive)+len(negative),"tp":tp,"fn":fn,"fp":fp,"tn":tn,"accuracy":round((tp+tn)/(len(positive)+len(negative)),4),"precision":round(tp/(tp+fp),4) if tp+fp else 0,"recall":round(tp/len(positive),4),"specificity":round(tn/len(negative),4)}
mutated=[]
for a in seed:
    for kind in MUTATIONS:
        value=mutate(a["prompt"],kind);mutated.append(" ".join(value) if isinstance(value,list) else value)
print("heldout",metrics(cases["malicious_holdout"],cases["benign"]))
print("seed_regression",metrics([a["prompt"] for a in seed],cases["benign"]))
print("mutation_coverage",{"samples":len(mutated),"detected":sum(detected(x) for x in mutated),"rate":round(sum(detected(x) for x in mutated)/len(mutated),4)})
