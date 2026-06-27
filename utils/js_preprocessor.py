"""
utils/js_preprocessor.py
────────────────────────
Pre-pass that runs BEFORE any analyzer touches js_files.

What it does
============
1.  Detects whether a JS file is minified / one-liner code.
2.  If yes  → sends it through Node.js (recast / acorn) to pretty-print it
              back to readable multi-line JS, then replaces the in-memory
              content so every downstream analyzer sees clean code.
3.  If no   → file passes through unchanged.
4.  Returns a PreprocessResult you can print/log and include in the report.

Detection heuristics
====================
A file is considered minified / inline if ANY of these are true:
  • avg_line_length  > THRESHOLD_AVG_LINE  (default 200 chars)
  • max_line_length  > THRESHOLD_MAX_LINE  (default 500 chars)
  • single_line_ratio > THRESHOLD_RATIO   (default 0.85 — 85 % of code on
                                           one line)
  • file has ≥ MIN_TOKENS tokens but only 1–2 lines

Node pretty-printer
===================
Uses a tiny inline Node script (written to a temp file on demand) that:
  • parses with acorn (tolerant mode)
  • walks + reprints with escodegen
  • falls back to the original text if parsing fails
  • writes the result to stdout so Python captures it

Requires:  node  +  acorn@8.14.1  +  escodegen@2.1.0  (installed via npm)
NODE_PATH is resolved dynamically from `npm root -g` so global installs
are found regardless of where the Node script is written at runtime.
If node/acorn/escodegen are unavailable the file is returned unchanged;
the FilePreprocessResult.error field records the reason.
"""

from __future__ import annotations

import os
import re
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import sys 

# ── npm global node_modules path (resolved once, cached) ─────────────────────
_NPM_NODE_PATH: Optional[str] = None
_NPM_NODE_PATH_RESOLVED = False   # distinguish "not yet tried" from "tried, got None"

def _get_npm_node_path() -> str:
    global _NPM_NODE_PATH, _NPM_NODE_PATH_RESOLVED
    if _NPM_NODE_PATH_RESOLVED:
        return _NPM_NODE_PATH or ""
    _NPM_NODE_PATH_RESOLVED = True

    # Windows needs npm.cmd, not npm
    npm_cmd = "npm.cmd" if sys.platform == "win32" else "npm"
    
    # Check local node_modules first (project-level install takes priority)
    local = Path(__file__).parent.parent / "node_modules"
    if local.is_dir():
        _NPM_NODE_PATH = str(local)
        return _NPM_NODE_PATH

    # Fall back to global
    try:
        res = subprocess.run(
            [npm_cmd, "root", "-g"],
            capture_output=True,
            timeout=10,
        )
        if res.returncode == 0:
            path = res.stdout.decode().strip()
            if path and os.path.isdir(path):
                _NPM_NODE_PATH = path
    except (OSError, subprocess.TimeoutExpired):
        pass
    return _NPM_NODE_PATH or ""



# ── Tunable thresholds ────────────────────────────────────────────────────────
THRESHOLD_AVG_LINE  = 200   # chars — average line length
THRESHOLD_MAX_LINE  = 500   # chars — longest single line
THRESHOLD_RATIO     = 0.85  # fraction of non-blank content on one line
MIN_CONTENT_CHARS   = 300   # ignore tiny files (< 300 chars)

# ── Node pretty-printer script (written to /tmp once per process) ─────────────
_NODE_SCRIPT = r"""
'use strict';
const fs      = require('fs');
const acorn   = require('acorn');
const astring = require('astring');

const src = fs.readFileSync(process.argv[2], 'utf8');

let ast;
try {
    ast = acorn.parse(src, {
        ecmaVersion              : 'latest',
        sourceType               : 'module',
        allowHashBang            : true,
        allowAwaitOutsideFunction: true,
    });
} catch (_) {
    try {
        ast = acorn.parse(src, {
            ecmaVersion  : 'latest',
            sourceType   : 'script',
            allowHashBang: true,
        });
    } catch (e2) {
        process.stdout.write(src);
        process.exit(0);
    }
}

const pretty = astring.generate(ast, {
    indent : '  ',
    lineEnd: '\n',
});
process.stdout.write(pretty);
"""


_NODE_SCRIPT_PATH: Optional[str] = None   # set on first use


def _ensure_node_script() -> str:
    """Write the Node pretty-printer script to /tmp once and cache its path."""
    global _NODE_SCRIPT_PATH
    if _NODE_SCRIPT_PATH and os.path.exists(_NODE_SCRIPT_PATH):
        return _NODE_SCRIPT_PATH
    fd, path = tempfile.mkstemp(suffix=".js", prefix="cxtscan_pp_")
    os.write(fd, _NODE_SCRIPT.encode())
    os.close(fd)
    _NODE_SCRIPT_PATH = path
    return path


# ── Detection ─────────────────────────────────────────────────────────────────

def _is_minified(content: str) -> tuple[bool, dict]:
    """
    Returns (is_minified, metrics_dict).
    metrics_dict is always populated so callers can log it.
    """
    if len(content) < MIN_CONTENT_CHARS:
        return False, {"reason": "file_too_small"}

    lines = content.splitlines()
    non_blank = [l for l in lines if l.strip()]

    if not non_blank:
        return False, {"reason": "empty"}

    lengths       = [len(l) for l in non_blank]
    avg_len       = sum(lengths) / len(lengths)
    max_len       = max(lengths)
    total_chars   = sum(lengths)
    longest_chars = lengths[0] if lengths else 0
    ratio         = longest_chars / total_chars if total_chars else 0

    metrics = {
        "total_lines"  : len(lines),
        "non_blank"    : len(non_blank),
        "avg_line_len" : round(avg_len, 1),
        "max_line_len" : max_len,
        "top_line_ratio": round(ratio, 3),
    }

    flags = []
    if avg_len > THRESHOLD_AVG_LINE:
        flags.append(f"avg_line_len={avg_len:.0f}>{THRESHOLD_AVG_LINE}")
    if max_len > THRESHOLD_MAX_LINE:
        flags.append(f"max_line_len={max_len}>{THRESHOLD_MAX_LINE}")
    if ratio > THRESHOLD_RATIO and len(non_blank) <= 5:
        flags.append(f"top_line_ratio={ratio:.2f}>{THRESHOLD_RATIO}")
    if len(non_blank) <= 2 and len(content) > 1000:
        flags.append("single_or_two_line_large_file")

    metrics["flags"] = flags
    return bool(flags), metrics


# ── Node-based pretty-printer ─────────────────────────────────────────────────

def _node_available() -> bool:
    return shutil.which("node") is not None


def _pretty_print_via_node(content: str) -> tuple[str, bool]:
    """
    Returns (pretty_content, success).
    If Node / acorn / escodegen are unavailable, returns (original, False).
    """
    if not _node_available():
        return content, False

    script = _ensure_node_script()

    # Resolve npm global node_modules so require('acorn') works
    # regardless of where the temp script is written
    node_path = _get_npm_node_path()
    print(f"\n  [DEBUG] NODE_PATH resolved to: {repr(node_path)}")  # ← add this


    # Write source to a temp file
    fd, src_path = tempfile.mkstemp(suffix=".js", prefix="cxtscan_src_")
    try:
        os.write(fd, content.encode("utf-8", errors="replace"))
        os.close(fd)

        env = {**os.environ, "NODE_PATH": node_path} if node_path else os.environ

        result = subprocess.run(
            ["node", script, src_path],
            capture_output=True,
            timeout=30,
            env=env,
        )

        #← add these four lines
        print(f"  [DEBUG] returncode: {result.returncode}")
        print(f"  [DEBUG] stdout length: {len(result.stdout)}")
        print(f"  [DEBUG] stderr: {result.stderr.decode('utf-8', errors='replace').strip()[:300]}")
        print(f"  [DEBUG] script path: {script}")


        if result.returncode == 0 and result.stdout:
            pretty = result.stdout.decode("utf-8", errors="replace")
            # Check line count instead of size — acorn fallback echoes the
            # original (same size) but line count stays the same; a real
            # pretty-print always produces significantly more lines.
            original_lines = content.count("\n")
            pretty_lines   = pretty.count("\n")
            print(f"  [DEBUG] original_lines={original_lines} pretty_lines={pretty_lines}")  # ← add 
            if pretty_lines > max(original_lines * 2, original_lines + 10):
                return pretty, True

        # Capture stderr for diagnosis if something went wrong
        stderr = result.stderr.decode("utf-8", errors="replace").strip() if result.stderr else ""
        return content, False

    except (subprocess.TimeoutExpired, OSError):
        return content, False
    finally:
        try:
            os.unlink(src_path)
        except OSError:
            pass


# ── Public result types ───────────────────────────────────────────────────────

@dataclass
class FilePreprocessResult:
    filename      : str
    was_minified  : bool
    was_expanded  : bool          # True if pretty-printer ran successfully
    original_size : int
    expanded_size : int
    metrics       : dict
    error         : Optional[str] = None


@dataclass
class PreprocessResult:
    file_results  : list[FilePreprocessResult] = field(default_factory=list)

    @property
    def total_minified(self) -> int:
        return sum(1 for r in self.file_results if r.was_minified)

    @property
    def total_expanded(self) -> int:
        return sum(1 for r in self.file_results if r.was_expanded)

    @property
    def summary(self) -> str:
        return (f"{self.total_minified} minified/inline file(s) detected, "
                f"{self.total_expanded} expanded via AST pretty-printer")


# ── Main entry point ──────────────────────────────────────────────────────────

def preprocess(js_files: dict[str, str]) -> tuple[dict[str, str], PreprocessResult]:
    """
    Parameters
    ----------
    js_files : dict mapping  filename → JS source string
               (same format returned by utils/loader.py)

    Returns
    -------
    (updated_js_files, PreprocessResult)

    updated_js_files has the same keys; values are replaced with pretty-printed
    source where minification was detected and expansion succeeded.
    """
    result      = PreprocessResult()
    updated     = {}

    node_ok = _node_available()

    for filename, content in js_files.items():
        is_min, metrics = _is_minified(content)

        if not is_min:
            updated[filename] = content
            result.file_results.append(FilePreprocessResult(
                filename      = filename,
                was_minified  = False,
                was_expanded  = False,
                original_size = len(content),
                expanded_size = len(content),
                metrics       = metrics,
            ))
            continue

        # Minified — attempt pretty-print
        if not node_ok:
            updated[filename] = content
            result.file_results.append(FilePreprocessResult(
                filename      = filename,
                was_minified  = True,
                was_expanded  = False,
                original_size = len(content),
                expanded_size = len(content),
                metrics       = metrics,
                error         = "node not available; file passed through unchanged",
            ))
            continue

        pretty, success = _pretty_print_via_node(content)
        updated[filename] = pretty

        result.file_results.append(FilePreprocessResult(
            filename      = filename,
            was_minified  = True,
            was_expanded  = success,
            original_size = len(content),
            expanded_size = len(pretty),
            metrics       = metrics,
            error         = None if success else "pretty-printer returned unusable output",
        ))

    return updated, result
