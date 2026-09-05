"""Remove derived/demo run data while preserving curated corpus and targets."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.app.database import SessionLocal
from backend.app.models import Alert,AttackPattern,Report,TestExecution,TestRun

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--yes",action="store_true",help="confirm permanent deletion of derived/demo records")
    args=parser.parse_args()
    if not args.yes:
        raise SystemExit("No changes made. Re-run with --yes to confirm cleanup.")
    with SessionLocal() as db:
        before={
            "mutated_attacks":db.query(AttackPattern).filter_by(origin="mutated").count(),
            "runs":db.query(TestRun).count(),
            "executions":db.query(TestExecution).count(),
            "reports":db.query(Report).count(),
            "alerts":db.query(Alert).count(),
        }
        # Delete dependent records first; curated seed/upstream attacks and all
        # target configurations are intentionally outside this cleanup scope.
        db.query(Alert).delete(synchronize_session=False)
        db.query(Report).delete(synchronize_session=False)
        db.query(TestExecution).delete(synchronize_session=False)
        db.query(TestRun).delete(synchronize_session=False)
        db.query(AttackPattern).filter_by(origin="mutated").delete(synchronize_session=False)
        db.commit()
        after={
            "seed_attacks":db.query(AttackPattern).filter_by(origin="seed").count(),
            "upstream_attacks":db.query(AttackPattern).filter_by(origin="github").count(),
            "mutated_attacks":db.query(AttackPattern).filter_by(origin="mutated").count(),
            "runs":db.query(TestRun).count(),
            "executions":db.query(TestExecution).count(),
        }
    print({"removed":before,"remaining":after})
if __name__=="__main__":main()
