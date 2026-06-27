"""
Analyzer 5: Dynamic Code Execution & Obfuscation Detection

v1.3 false-positive fixes:
  - Strip string literal CONTENT before matching, so patterns inside
    quoted strings ("dF4sA", key names, etc.) don't trigger
  - atob() alone REMOVED — it's a standard browser API. Only flagged
    when combined with eval() or new Function()
  - btoa() alone REMOVED — encoding data is not inherently suspicious
  - Hex escapes \\x.. only flagged at HIGH density (5+ per line)
  - Unicode escapes \\u.... only flagged at moderate density (3+ per line)
  - String.fromCharCode() only flagged when called with numeric args
  - Snippet now shows context AROUND the match, not just first 120 chars
"""
import re
import math
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class DynExecFinding:
    technique: str
    file: str
    line_number: int
    line_snippet: str   # context around the actual match
    risk_score: int
    reason: str


@dataclass
class DynExecResult:
    findings: List[DynExecFinding] = field(default_factory=list)
    total_score: int = 0
    obfuscation_score: float = 0.0
    obfuscation_verdict: str = "Clean"


# ── String literal stripping ──────────────────────────────────────────────────

def _strip_strings(line: str) -> str:
    """
    Replace the CONTENT inside string literals with a placeholder so
    patterns inside quoted strings don't generate false matches.
    e.g.  {"50b64a551f51b337":"dF4sA"}  →  {"__S__":"__S__"}
    """
    # Double-quoted strings (handles \" escapes)
    result = re.sub(r'"(?:[^"\\]|\\.)*"', '"__S__"', line)
    # Single-quoted strings (handles \' escapes)
    result = re.sub(r"'(?:[^'\\]|\\.)*'", "'__S__'", result)
    # Template literals (basic, no nested ${})
    result = re.sub(r'`[^`]*`', '`__S__`', result)
    return result


def _get_snippet(line: str, pattern: str, flags: int = 0, width: int = 110) -> str:
    """
    Return a snippet of `line` centered around where `pattern` matches.
    Falls back to first `width` chars if no match found.
    """
    stripped = line.strip()
    if len(stripped) <= width:
        return stripped

    m = re.search(pattern, stripped, flags)
    if m:
        center = (m.start() + m.end()) // 2
        half   = width // 2
        start  = max(0, center - half)
        end    = min(len(stripped), start + width)
        # adjust if we hit the end
        if end == len(stripped):
            start = max(0, end - width)
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(stripped) else ""
        return prefix + stripped[start:end] + suffix

    return stripped[:width]


# ── Dynamic execution patterns (high confidence, run on RAW line) ─────────────
# These are dangerous regardless of string context, so we match the raw line.
# Each: (regex, score, technique_label, reason)

EXEC_PATTERNS = [
    # eval combinations — highest confidence
    (r"\beval\s*\(\s*atob\s*\(",         10, "eval(atob())",
     "Executes base64-decoded payload — clear obfuscation to hide code"),

    (r"\beval\s*\(\s*unescape\s*\(",      9, "eval(unescape())",
     "Executes URL-decoded string as code — obfuscated payload"),

    (r"new\s+Function\s*\(.*?atob\s*\(", 10, "new Function(atob())",
     "Creates function from base64-decoded string — obfuscated execution"),

    (r"new\s+Function\s*\(.*?unescape\s*\(", 9, "new Function(unescape())",
     "Creates function from URL-decoded string"),

    # standalone eval — confirmed dangerous only when not in a comment
    (r"(?<![/\*#])\beval\s*\(\s*(?!function|null|undefined|''\s*\)|\"\")",
     8, "eval(variable)",
     "eval() called on a variable/expression — dynamic code execution"),

    # new Function() on a variable
    (r"new\s+Function\s*\(\s*[a-zA-Z_$]",  7, "new Function(variable)",
     "Creates function from a variable string — same power as eval"),

    # setTimeout/setInterval with a STRING (not a function reference)
    (r"setTimeout\s*\(\s*['\"]",            6, "setTimeout(string)",
     "Executes string as code after delay — legacy eval equivalent"),

    (r"setInterval\s*\(\s*['\"]",           6, "setInterval(string)",
     "Executes string as code on interval — legacy eval equivalent"),

    # innerHTML assigned from a dynamic/fetched value
    (r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])[^;]{0,30}"
     r"(fetch|XMLHttp|atob|eval|decode)",
     7, "innerHTML=dynamic()",
     "innerHTML set from dynamic/fetched content — DOM injection risk"),

    # window['method']() — obfuscated API call
    (r"window\s*\[\s*[^'\"\]]{0,40}\]\s*\(",  6, "window[var]()",
     "Calls window method via bracket notation — obfuscates function name"),

    # Function.prototype.constructor — rare, almost always obfuscation
    (r"Function\s*\.\s*prototype\s*\.\s*constructor",  8,
     "Function.prototype.constructor",
     "Indirect eval via constructor — used to bypass eval detection"),

    # document.write with dynamic content
    (r"document\s*\.\s*write\s*\(\s*(?!['\"]\s*['\"])",  5,
     "document.write(dynamic)",
     "Writes dynamic content to DOM — can inject scripts"),
]


# ── Obfuscation patterns (run on STRIPPED line — string content removed) ──────
# These patterns are only meaningful if found in actual code, not inside strings.
# Each: (regex, score, technique_label, reason, min_count)
#   min_count = minimum occurrences in the line required to flag (None = 1)

OBFUSCATION_PATTERNS = [
    # Hex variable names like _0x1a2b — strong signal of automated obfuscator
    (r"_0x[0-9a-fA-F]{4,}\b",       8, "_0x hex variables",
     "Hex variable names — signature of JS obfuscators (obfuscator.io, etc.)",
     3),   # require 3+ on a line to flag

    # Mangled names like $$aAbBcC — less common but clear
    (r"\$\$[a-zA-Z0-9_]{8,}\b",     6, "$$-mangled variables",
     "Double-dollar mangled names — automated obfuscator output",
     2),

    # String.fromCharCode with actual numbers
    (r"String\s*\.\s*fromCharCode\s*\(\s*\d+",  6,
     "String.fromCharCode(numbers)",
     "Builds string from char codes with numeric args — classic obfuscation",
     None),

    # XOR cipher: x = a ^ b where variables are single chars (tight pattern)
    (r"\b[a-z_$]\s*=\s*[a-z_$]\s*\^\s*[a-z_$]\b",  5, "XOR char operations",
     "XOR operations on single-char variables — string encryption technique",
     None),

    # parseInt + toString with a radix — number base conversion obfuscation
    (r"parseInt\s*\(.*?\bttoString\s*\(\s*\d{2}",  5,
     "parseInt/toString radix",
     "Number base conversion trick — encodes strings as different-base numbers",
     None),

    # split + reverse + join chain — string reversal
    (r"split\s*\(\s*['\"]['\"]?\s*\).*reverse\s*\(\s*\).*join\s*\(",  5,
     "split/reverse/join",
     "String reversal chain — hides string content by reversing it",
     None),

    # Long base64 blob (20+ groups of 4 chars) in actual code
    # min_count=None but requires 80+ char b64 string
    (r"(?:[A-Za-z0-9+/]{4}){20,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
     5, "Long base64 blob",
     "Embedded base64 blob (80+ chars) — may contain hidden payload",
     None),
]

# ── Density-based patterns (require multiple occurrences per line) ────────────
# These are common in normal code; only suspicious at high density.

DENSITY_PATTERNS = [
    # \xNN hex escapes — normal in minified code but suspicious at HIGH density
    (r"\\x[0-9a-fA-F]{2}", 5, "Dense hex escapes",
     "High density of \\x hex escapes — suggests character-level obfuscation",
     5),   # require 5+ per line

    # \uNNNN unicode escapes — occasional ones are fine, many = obfuscation
    (r"\\u[0-9a-fA-F]{4}", 4, "Dense unicode escapes",
     "High density of \\u unicode escapes — suggests string obfuscation",
     4),   # require 4+ per line
]


def analyze(js_files: Dict[str, str]) -> DynExecResult:
    result = DynExecResult()
    seen: Dict[str, int] = {}  # technique → max_score (deduplicate across files)

    for filename, source in js_files.items():
        lines = source.splitlines()

        for line_num, line in enumerate(lines, 1):
            stripped_line = _strip_strings(line)  # used for obfuscation checks

            # ── Exec patterns: match on RAW line ──────────────────────────────
            for pattern, score, technique, reason in EXEC_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE | re.DOTALL):
                    snippet = _get_snippet(line, pattern, re.IGNORECASE | re.DOTALL)
                    result.findings.append(DynExecFinding(
                        technique=technique, file=filename,
                        line_number=line_num, line_snippet=snippet,
                        risk_score=score, reason=reason,
                    ))
                    if seen.get(technique, 0) < score:
                        seen[technique] = score

            # ── Obfuscation patterns: match on STRING-STRIPPED line ────────────
            for pattern, score, technique, reason, min_count in OBFUSCATION_PATTERNS:
                matches = re.findall(pattern, stripped_line)
                threshold = min_count if min_count is not None else 1
                if len(matches) >= threshold:
                    snippet = _get_snippet(line, pattern)
                    result.findings.append(DynExecFinding(
                        technique=technique, file=filename,
                        line_number=line_num, line_snippet=snippet,
                        risk_score=score, reason=reason,
                    ))
                    if seen.get(technique, 0) < score:
                        seen[technique] = score

            # ── Density patterns: count occurrences, only flag if >= threshold ─
            for pattern, score, technique, reason, min_count in DENSITY_PATTERNS:
                matches = re.findall(pattern, stripped_line)
                if len(matches) >= min_count:
                    snippet = _get_snippet(line, pattern)
                    result.findings.append(DynExecFinding(
                        technique=technique, file=filename,
                        line_number=line_num, line_snippet=snippet,
                        risk_score=score, reason=reason,
                    ))
                    if seen.get(technique, 0) < score:
                        seen[technique] = score

        # ── File-level entropy + structural obfuscation ────────────────────────
        entropy       = _calculate_entropy(source)
        avg_line_len  = _avg_line_length(source)
        hex_var_ratio = _hex_variable_density(source)

        obf_score = 0.0
        if entropy > 5.5:
            obf_score += (entropy - 5.5) * 20
        if avg_line_len > 500:
            obf_score += min(30, (avg_line_len - 500) / 100)
        if hex_var_ratio > 0.1:
            obf_score += hex_var_ratio * 50

        if obf_score > result.obfuscation_score:
            result.obfuscation_score = obf_score

    # Verdict
    if result.obfuscation_score > 70:
        result.obfuscation_verdict = "HEAVILY OBFUSCATED"
        if seen.get("file_obfuscation", 0) < 9:
            seen["file_obfuscation"] = 9
    elif result.obfuscation_score > 40:
        result.obfuscation_verdict = "Likely Obfuscated"
        if seen.get("file_obfuscation", 0) < 6:
            seen["file_obfuscation"] = 6
    elif result.obfuscation_score > 20:
        result.obfuscation_verdict = "Possibly Obfuscated"
        if seen.get("file_obfuscation", 0) < 3:
            seen["file_obfuscation"] = 3
    else:
        result.obfuscation_verdict = "Clean"

    result.total_score = sum(seen.values())
    return result


# ── Helpers ───────────────────────────────────────────────────────────────────

def _calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _avg_line_length(source: str) -> float:
    lines = [l for l in source.splitlines() if l.strip()]
    if not lines:
        return 0.0
    return sum(len(l) for l in lines) / len(lines)


def _hex_variable_density(source: str) -> float:
    tokens  = len(re.findall(r'\b\w+\b', source))
    hex_vars = len(re.findall(r'\b_0x[0-9a-fA-F]{4,}\b', source))
    return hex_vars / tokens if tokens else 0.0
