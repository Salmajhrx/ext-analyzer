"""
Analyzer 4: Remote Configuration Detection
Detects when extensions fetch code/config from remote servers at runtime.
This is the "sleeper agent" pattern — looks benign at install, activates later.
"""
import re
from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class RemoteConfigFinding:
    pattern_name: str
    file: str
    line_number: int
    line_snippet: str
    risk_score: int
    reason: str


@dataclass
class RemoteConfigResult:
    findings: List[RemoteConfigFinding] = field(default_factory=list)
    total_score: int = 0


# Patterns that indicate fetching remote instructions/config
REMOTE_CONFIG_PATTERNS = [
    # Fetch + use response as code
    (
        r"fetch\(['\"][^'\"]+['\"].*\)\s*\.then.*eval",
        9,
        "FETCH+EVAL CHAIN: Downloads remote content and executes it as code"
    ),
    (
        r"fetch\(['\"][^'\"]+config[^'\"]*['\"]",
        7,
        "Fetches remote configuration file"
    ),
    (
        r"fetch\(['\"][^'\"]+\.json['\"]",
        5,
        "Fetches remote JSON — may contain behavioral instructions"
    ),
    (
        r"chrome\.storage\.sync\.set.*fetch|fetch.*chrome\.storage\.sync\.set",
        7,
        "Fetches remote data and stores in sync storage — persisted remote config"
    ),

    # XMLHttpRequest for config
    (
        r"XMLHttpRequest.*responseText.*eval",
        9,
        "XHR response evaluated as code"
    ),
    (
        r"new\s+XMLHttpRequest.*config",
        6,
        "XHR request for configuration"
    ),

    # Script injection from remote
    (
        r"document\.createElement\(['\"]script['\"].*src\s*=",
        8,
        "Dynamically creates script tag with remote src — loads remote code"
    ),
    (
        r"\.src\s*=\s*['\"]https?://",
        7,
        "Sets script/iframe src to remote URL — executes external code"
    ),

    # importScripts in service workers
    (
        r"importScripts\(['\"]https?://",
        9,
        "Service worker imports scripts from remote URL"
    ),

    # WebSocket for live C2
    (
        r"new\s+WebSocket\(",
        8,
        "WebSocket connection — enables real-time command-and-control channel"
    ),
    (
        r"ws\.onmessage.*eval|WebSocket.*onmessage.*eval",
        10,
        "LIVE C2: Evaluates WebSocket messages as code"
    ),
    (
        r"ws\.onmessage.*Function\(|WebSocket.*Function\(",
        10,
        "LIVE C2: Executes WebSocket messages via new Function()"
    ),

    # Polling patterns
    (
        r"setInterval.*fetch|setTimeout.*fetch",
        6,
        "Periodic remote fetch — polls for updated instructions"
    ),
    (
        r"chrome\.alarms.*fetch|fetch.*chrome\.alarms",
        6,
        "Uses Chrome alarms to periodically fetch remote data"
    ),

    # Remote update checks
    (
        r"fetch.*version|fetch.*update",
        5,
        "Fetches remote version/update info — may trigger code replacement"
    ),
    (
        r"chrome\.runtime\.requestUpdateCheck",
        4,
        "Requests extension update check"
    ),

    # Config key patterns in fetched JSON
    (
        r"['\"]payload['\"]",
        7,
        "References 'payload' key — common in remote config for code delivery"
    ),
    (
        r"['\"]script['\"].*fetch|fetch.*['\"]script['\"]",
        8,
        "Fetches remote 'script' payload"
    ),
    (
        r"['\"]command['\"].*onmessage|onmessage.*['\"]command['\"]",
        8,
        "Processes 'command' field from remote messages — C2 protocol"
    ),
]

# Multi-line / contextual patterns (check surrounding context)
CONTEXT_PATTERNS = [
    (
        r"onInstalled.*fetch|onStartup.*fetch",
        8,
        "Fetches remote content on install/startup — initialization C2 check-in"
    ),
    (
        r"fetch.*then.*JSON\.parse.*then",
        5,
        "Fetch → parse JSON → act chain — remote instructions pattern"
    ),
]


def analyze(js_files: Dict[str, str]) -> RemoteConfigResult:
    result = RemoteConfigResult()
    seen_patterns: Dict[str, int] = {}

    for filename, source in js_files.items():
        lines = source.splitlines()
        # Also check multi-line contexts (join sliding windows)
        windows = []
        for i in range(len(lines)):
            window = " ".join(lines[max(0, i-2):i+3]).replace("\n", " ")
            windows.append((i + 1, window))

        for line_num, line in enumerate(lines, 1):
            for pattern, score, reason in REMOTE_CONFIG_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.findings.append(RemoteConfigFinding(
                        pattern_name=_clean_pattern(pattern),
                        file=filename,
                        line_number=line_num,
                        line_snippet=line.strip()[:120],
                        risk_score=score,
                        reason=reason
                    ))
                    key = _clean_pattern(pattern)
                    if key not in seen_patterns or seen_patterns[key] < score:
                        seen_patterns[key] = score

        for line_num, window in windows:
            for pattern, score, reason in CONTEXT_PATTERNS:
                if re.search(pattern, window, re.IGNORECASE | re.DOTALL):
                    result.findings.append(RemoteConfigFinding(
                        pattern_name=_clean_pattern(pattern),
                        file=filename,
                        line_number=line_num,
                        line_snippet=window[:120],
                        risk_score=score,
                        reason=reason
                    ))
                    key = _clean_pattern(pattern)
                    if key not in seen_patterns or seen_patterns[key] < score:
                        seen_patterns[key] = score

    result.total_score = sum(seen_patterns.values())
    return result


def _clean_pattern(pattern: str) -> str:
    return re.sub(r'[\\()\[\].*+?^${}|]', '', pattern)[:40]
