"""
Inspectors module re-exporting request, response, and analyzer routines.
"""
from typing import Any
from .request_inspector import (
    RULES,
    TECHNIQUE_SOURCES,
    HOMOGLYPHS,
    HIDDEN_MARKUP,
    lexical_similarity,
    normalize,
    inspect_request
)
from .response_inspector import (
    LEAKS,
    inspect_response
)
from .analyzer import (
    severity_from_score,
    generate_finding_and_remediation
)

__all__ = [
    "RULES",
    "TECHNIQUE_SOURCES",
    "HOMOGLYPHS",
    "HIDDEN_MARKUP",
    "lexical_similarity",
    "normalize",
    "inspect_request",
    "LEAKS",
    "inspect_response",
    "severity_from_score",
    "generate_finding_and_remediation",
]
