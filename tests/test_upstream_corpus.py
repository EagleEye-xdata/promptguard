import json
from pathlib import Path
import yaml

ROOT=Path(__file__).resolve().parents[1]
def rows(name):return [json.loads(x) for x in (ROOT/"corpus"/"upstream"/name).read_text(encoding="utf-8").splitlines()]
def test_manifest_is_commit_pinned_and_licensed_sources_only_included():
    sources=yaml.safe_load((ROOT/"corpus"/"upstream"/"sources.yaml").read_text(encoding="utf-8"))["sources"]
    assert all(len(s["pinned_commit"])==40 for s in sources)
    assert all(s["license"]!="unknown" for s in sources if s["status"]=="included")
def test_curated_artifacts_are_separated_and_have_provenance():
    templates=rows("attack_templates.jsonl");techniques=rows("technique_parameters.jsonl");evaluation=rows("evaluation_dataset.jsonl")
    assert len(templates)>=70 and len(techniques)>=15 and len(evaluation)>=20
    assert all("provenance" in x and "commit" in x["provenance"] for x in templates+techniques+evaluation)
    assert all("label" not in x for x in templates)
    assert all(x["split"]=="external_evaluation" for x in evaluation)
def test_no_duplicate_runtime_templates():
    templates=rows("attack_templates.jsonl")
    normalized=[" ".join(x["template"].lower().split()) for x in templates]
    assert len(normalized)==len(set(normalized))
