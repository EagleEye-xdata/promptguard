import base64, binascii, math, re, time, unicodedata
from collections import Counter
from typing import Any
from .session_window import session_windows
from ..models import AttackPattern

RULES = [
    ("ignore-instructions", "instruction_override", re.compile(r"ignore (all |any )?(previous|prior|above) instructions?", re.I), 70),
    ("role-change", "role_manipulation", re.compile(r"you are now|pretend (?:you are|to be)|developer mode|\bDAN\b|act as (?:an? )?(?:system|backend|unrestricted|developer|administrator|auditor|debugger)", re.I), 58),
    ("prompt-extraction", "system_prompt_extraction", re.compile(r"system prompt|repeat (?:your|the) instructions|what were you told|hidden instructions", re.I), 62),
    ("delimiter", "delimiter_manipulation", re.compile(r"```\s*(system|developer)|###\s*(system|developer)|<system>", re.I), 65),
    ("hierarchy", "instruction_hierarchy", re.compile(r"higher priority|supersede|most important instruction|developer message", re.I), 58),
    ("secret-request", "system_prompt_extraction", re.compile(r"reveal|print|output|exfiltrate", re.I), 28),
    ("override-synonym", "instruction_override", re.compile(r"set aside|disregard|replace (?:the|your|current)|obsolete|suspend|bypass|supersede|outranks?|restrictions? (?:do|does) not apply", re.I), 55),
    ("protected-object", "system_prompt_extraction", re.compile(r"private|protected|confidential|internal|hidden|system (?:message|instructions?)|operating rules?|initiali[sz]ed your behavior|setup text", re.I), 42),
    ("disclosure-intent", "system_prompt_extraction", re.compile(r"disclos(?:e|ure)|dump|emit|expose|reconstruct|reproduce|return the exact|numbered checklist", re.I), 45),
    ("authority-claim", "instruction_hierarchy", re.compile(r"administrator|operator|authority update|granted permission|backend diagnostic|developer>", re.I), 38),
    ("indirect-command", "indirect_injection", re.compile(r"retrieved (?:web)?page says|document says|execute the phrase|instruction (?:inside|in) (?:the )?(?:document|page|email)", re.I), 48),
    ("payload-variables", "payload_splitting", re.compile(r"(?:part|fragment|variable)\s*[1-9a-z]\s*=|concatenate|join (?:the )?(?:parts|fragments|variables)|execute .{0,20}(?:a\+b|stored instruction|combined)", re.I), 58),
    ("fake-history", "context_manipulation", re.compile(r"(?:conversation|chat) (?:history|recap)|(?:user|assistant)\s*:.{0,160}(?:user|assistant)\s*:|previously (?:approved|agreed|authorized)", re.I | re.S), 86),
    ("prefix-coercion", "instruction_override", re.compile(r"(?:begin|start|prefix) (?:your|the) (?:answer|response|reply).{0,60}(?:with|by saying)|respond only with|must first say", re.I), 52),
    ("refusal-suppression", "jailbreak", re.compile(r"(?:do not|don't|never|must not) (?:say|use|include|mention).{0,80}(?:sorry|cannot|can't|unable|refus|warning|policy|safety)|without (?:a |any )?(?:warning|refusal|disclaimer)", re.I), 62),
    ("nested-instruction", "indirect_injection", re.compile(r"(?:todo|note|instruction|comment)\s*:.{0,120}(?:ignore|reveal|override|bypass)|<(?:document|retrieved|context)>.*(?:ignore|reveal|override)", re.I | re.S), 56),
    ("known-jailbreak-persona", "jailbreak", re.compile(r"\b(?:DAN|STAN|DUDE|AIM|AntiGPT|Developer Mode|Anarchy Mode|unfiltered (?:AI|model)|no restrictions? (?:AI|model))\b", re.I), 64),
    ("fictional-policy-bypass", "jailbreak", re.compile(r"(?:fictional|hypothetical|roleplay|simulate).{0,100}(?:no (?:rules|restrictions|filters)|unfiltered|policy does not apply|always (?:comply|obey|answer))", re.I | re.S), 55),
    ("policy-bypass-command", "instruction_override", re.compile(r"forget (?:everything|all).{0,50}(?:told|rules|instructions)|override (?:(?:all|your)\s+){0,2}(?:safety |ethical )?(?:guidelines|instructions|rules)|ignore (?:all )?(?:your )?(?:training|safety protocols?|safeguards)|(?:start fresh|act as if).{0,50}(?:without (?:rules|restrictions)|jailbroken|no ethical constraints)|must comply.{0,60}(?:regardless|programming)|without (?:limitations|restrictions)", re.I | re.S), 82),
]

TECHNIQUE_SOURCES = {
    "payload-variables": "GK-002", "delimiter": "GK-003", "prefix-coercion": "GK-004",
    "fake-history": "GK-005", "nested-instruction": "GK-006", "refusal-suppression": "GK-007",
    "known-jailbreak-persona": "GK-011..GK-018", "fictional-policy-bypass": "GK-017",
    "policy-bypass-command": "GK-007/GK-017",
}

HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
    "ν": "v", "ρ": "p", "τ": "t", "к": "k", "м": "m", "т": "t", "н": "h", "А": "A", "В": "B", "Е": "E", "К": "K",
    "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X"
})

HIDDEN_MARKUP = re.compile(r"<!--(.*?)-->|```[a-z]*\n?(.*?)```|\[\^\d+\]:\s*([^\n]+)", re.S | re.I)


def _tokens(s: str) -> Counter:
    return Counter(re.findall(r"[a-z0-9]+", s.lower()))


def lexical_similarity(a: str, b: str) -> float:
    x, y = _tokens(a), _tokens(b)
    dot = sum(x[k] * y[k] for k in x)
    den = math.sqrt(sum(v * v for v in x.values()) * sum(v * v for v in y.values()))
    return dot / den if den else 0.0


def _printable(value: str) -> bool:
    return len(value) > 8 and sum(c.isprintable() or c.isspace() for c in value) / len(value) > 0.9


def normalize(text: str) -> tuple[str, list[dict[str, Any]]]:
    evidence = []
    norm = unicodedata.normalize("NFKC", text)
    norm = "".join(c for c in norm if unicodedata.category(c) != "Cf")
    if norm != text:
        evidence.append({"type": "unicode_normalization", "decoded": norm[:1000]})

    hidden = [m.group(1) or m.group(2) or m.group(3) for m in HIDDEN_MARKUP.finditer(norm) if any(m.groups())]
    if hidden:
        revealed = " ".join(h.strip() for h in hidden if h and h.strip())
        norm = f"{norm}\n{revealed}"
        evidence.append({"type": "hidden_markup", "decoded": revealed[:1000]})

    for _ in range(2):
        changed = False
        compact = re.sub(r"\s+", "", norm)
        for kind in ("base64", "hex"):
            try:
                dec = base64.b64decode(compact, validate=True).decode() if kind == "base64" else bytes.fromhex(compact.removeprefix("0x")).decode()
                if _printable(dec):
                    norm = dec; evidence.append({"type": kind, "decoded": dec[:1000]}); changed = True; break
            except (ValueError, UnicodeError, binascii.Error):
                pass
        if changed:
            continue
        for kind, rx in (("embedded_base64", r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])"), ("embedded_hex", r"\b(?:[0-9a-fA-F]{2}){12,}\b")):
            for token in re.findall(rx, norm):
                try:
                    dec = base64.b64decode(token, validate=True).decode() if kind.endswith("base64") else bytes.fromhex(token).decode()
                    if _printable(dec):
                        norm = norm.replace(token, dec); evidence.append({"type": kind, "decoded": dec[:1000]}); changed = True
                except (ValueError, UnicodeError, binascii.Error):
                    pass
        if not changed:
            break

    dehom = norm.translate(HOMOGLYPHS)
    if dehom != norm:
        evidence.append({"type": "homoglyph", "decoded": dehom[:1000]}); norm = dehom

    leet_hits = sum(norm.lower().count(c) for c in "431057")
    deleet = norm.lower().translate(str.maketrans("431057", "aeiost"))
    if leet_hits >= 3:
        evidence.append({"type": "leetspeak", "decoded": deleet[:1000]}); norm = deleet

    return norm, evidence


def inspect_request(text: str, corpus: list[dict[str, Any]], judge_score: float | None = None, exclude_ids: set[str] | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    norm, decoded = normalize(text)
    matched = [{"name": n, "category": c, "weight": w, "match": m.group(0)[:240], "technique_source": TECHNIQUE_SOURCES.get(n)} for n, c, r, w in RULES if (m := r.search(norm))]
    rule_score = min(100, sum(x["weight"] for x in matched))
    best = {"id": None, "score": 0.0, "category": None}
    norm_lower = " ".join(norm.lower().split())
    excluded = 0

    for item in corpus:
        if exclude_ids and str(item["id"]) in exclude_ids:
            excluded += 1; continue
        pat = " ".join(item["prompt"].lower().split())
        score = 1.0 if len(pat) > 20 and pat in norm_lower else lexical_similarity(norm, item["prompt"])
        if score > best["score"]:
            best = {"id": item["id"], "score": round(score, 4), "category": item["category"]}

    sim_score = 100 if best["score"] >= 0.85 else (best["score"] / 0.85) * 100
    base = 0.35 * rule_score + 0.30 * sim_score + 0.10 * (100 if decoded else 0)

    discussion = bool(re.search(r"^\s*(explain|discuss|describe|define|write (?:an?|the) (?:article|guide)|how (?:can|do|should) (?:i|we) (?:detect|prevent|protect)|what (?:is|are|does))\b", norm, re.I))
    discussion = discussion or bool(re.search(r"^\s*how do i .*(?:in|for) (?:a |my )?(?:config|configuration|code|application|document|article)\b", norm, re.I))

    if discussion and not decoded:
        base *= 0.45

    judge_used = judge_score is not None and 30 <= base <= 70
    risk = min(100, base + (0.25 * judge_score if judge_used else 0))
    signals = sum([bool(matched), best["score"] >= 0.85, bool(decoded), judge_used and judge_score >= 60])
    confidence = min(0.98, 0.35 + 0.18 * signals)
    action = "BLOCK" if risk >= 70 and confidence >= 0.6 and signals >= 2 else "REVIEW" if risk >= 30 else "ALLOW"
    category = (matched[0]["category"] if matched else best["category"])

    return {
        "attack_detected": action != "ALLOW",
        "attack_type": category,
        "risk_score": round(risk, 2),
        "confidence": round(confidence, 2),
        "action": action,
        "evidence": {
            "matched_rules": matched,
            "matched_techniques": [{"rule": x["name"], "source": x["technique_source"]} for x in matched if x["technique_source"]],
            "top_similarity": {**best, "excluded_family_patterns": excluded},
            "decoded_obfuscation": decoded,
            "benign_discussion_context": discussion,
            "judge": {"used": judge_used, "score": judge_score},
            "timings": {"total_ms": round((time.perf_counter() - started) * 1000, 3)}
        }
    }


def get_corpus(db) -> list[dict]:
    return [{"id": a.id, "category": a.category, "prompt": a.cleaned_prompt} for a in db.query(AttackPattern).all()]


def inspect_session(message: str, session_id: str, patterns: list[dict]):
    single = inspect_request(message, patterns)
    window_text = session_windows.add_and_join(session_id, message)
    if window_text == message:
        return {**single, "session_window_used": False}
    combined = inspect_request(window_text, patterns)
    used = combined["risk_score"] > single["risk_score"]
    res = combined if used else single
    return {**res, "session_window_used": used, "evidence": {**res["evidence"], "single_message_risk": single["risk_score"], "session_window_risk": combined["risk_score"]}}
