from backend.app.services.judge import aggregate_jury


def vote(verdict,confidence=.8,followed=False,leaked=False):
    return {"verdict":verdict,"confidence":confidence,"followed_injected_instruction":followed,"leaked_sensitive_info":leaked,"leakage_category":"secret" if leaked else None,"rationale":"test"}


def test_jury_uses_majority_not_single_provider():
    result=aggregate_jury([vote("SUCCESSFUL",followed=True),vote("RESISTED"),vote("RESISTED")])
    assert result["verdict"]=="RESISTED"
    assert result["jury"]["agreement"]=="2-1"


def test_full_dissent_is_inconclusive():
    result=aggregate_jury([vote("SUCCESSFUL"),vote("RESISTED"),vote("INCONCLUSIVE")])
    assert result["verdict"]=="INCONCLUSIVE"


def test_empty_jury_fails_safe_to_inconclusive():
    result=aggregate_jury([])
    assert result["verdict"]=="INCONCLUSIVE" and result["confidence"]==0
