"""
Extension Loader
Handles unpacking .crx / .zip / directory extensions.
CRX3 format: 4-byte magic + 4-byte version + 4-byte header_size + header + zip_data

v1.4 changes:
  - load_extension() now accepts Chrome Web Store URLs and bare extension IDs
  - Downloads .crx directly from Google's update servers
  - Caches downloaded .crx in SAMPLES_BASE/<ext_id>/ to avoid re-downloading

v1.3 changes:
  - Step 3: Unpacked files stored persistently under
            EXT-ANALYZER/samples/<ext_id>/unpacked/  (not deleted after scan)
  - Step 3: Zip-slip protection on all unpack paths
  - Samples base dir: env var CXT_SAMPLES_DIR or ~/EXT-ANALYZER/samples
"""
import os
import re
import json
import struct
import zipfile
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Optional, Tuple

# Persistent samples directory — project-relative by default.
# Override with env var:  set CXT_SAMPLES_DIR=E:\your\path  (Windows)
#                         export CXT_SAMPLES_DIR=/your/path   (Mac/Linux)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_BASE = os.environ.get(
    "CXT_SAMPLES_DIR",
    os.path.join(_PROJECT_ROOT, "samples"),
)

# Google's CRX download endpoint (same URL the browser uses for updates)
_CRX_DOWNLOAD_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect"
    "&acceptformat=crx3,crx2"
    "&prodversion=120.0.0.0"
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


class ExtensionLoadError(Exception):
    pass


# ── Public entry point ────────────────────────────────────────────────────────

def load_extension(source: str) -> Tuple[dict, Dict[str, str], str]:
    """
    Returns: (manifest_dict, {filename: source_code}, unpacked_dir_path)

    Accepted inputs:
      - Chrome Web Store URL  (https://chromewebstore.google.com/detail/…/<id>)
      - Raw extension ID      (32 lowercase letters)
      - Local .crx file
      - Local .zip file
      - Local unpacked directory
    """
    source = source.strip()

    # ── 1. Chrome Web Store URL or bare extension ID ──────────────────────
    ext_id = parse_extension_id(source)
    if ext_id:
        return _load_from_id(ext_id)

    # ── 2. Local path ─────────────────────────────────────────────────────
    path = Path(source)

    if not path.exists():
        # Give a helpful error if it looks like they meant a URL
        if source.startswith("http"):
            raise ExtensionLoadError(
                f"Could not parse extension ID from URL: {source}\n"
                "Expected format: https://chromewebstore.google.com/detail/<name>/<32-char-id>"
            )
        raise ExtensionLoadError(f"Path not found: {source}")

    if path.is_dir():
        return _load_from_directory(str(path)), _read_js_files(str(path)), str(path)

    if path.suffix.lower() in (".crx", ".zip"):
        stem   = path.stem
        ext_id = stem if (len(stem) == 32 and stem.isalpha() and stem.islower()) else stem
        return _load_from_file(str(path), ext_id)

    raise ExtensionLoadError(
        f"Unsupported format: {path.suffix}. "
        "Use a Chrome Web Store URL, extension ID, .crx, .zip, or a directory."
    )


# ── ID-based loader (download from CWS) ──────────────────────────────────────

def _load_from_id(ext_id: str) -> Tuple[dict, Dict[str, str], str]:
    """Download CRX from Google, cache it, then unpack."""
    ext_dir    = os.path.join(SAMPLES_BASE, ext_id)
    crx_path   = os.path.join(ext_dir, f"{ext_id}.crx")
    unpack_dir = os.path.join(ext_dir, "unpacked")

    os.makedirs(ext_dir,    exist_ok=True)
    os.makedirs(unpack_dir, exist_ok=True)

    # Use cached CRX if already downloaded
    if not os.path.exists(crx_path):
        print(f"  ↓  Downloading extension {ext_id} from Chrome Web Store...")
        _download_crx(ext_id, crx_path)
        print(f"  ✓  Downloaded → {crx_path}")
    else:
        print(f"  ✓  Using cached CRX → {crx_path}")

    try:
        _unpack(crx_path, unpack_dir)
        root = _find_manifest_root(unpack_dir)
        return _load_from_directory(root), _read_js_files(root), root
    except Exception as e:
        raise ExtensionLoadError(f"Failed to unpack {ext_id}: {e}")


def _download_crx(ext_id: str, dest_path: str):
    """
    Download a .crx from Google's update servers.
    Follows redirects (urllib does this automatically).
    """
    url = _CRX_DOWNLOAD_URL.format(ext_id=ext_id)
    req = urllib.request.Request(url, headers={"User-Agent": _CHROME_UA})

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except urllib.error.HTTPError as e:
        if e.code == 204:
            raise ExtensionLoadError(
                f"Extension '{ext_id}' not found on the Chrome Web Store "
                "(HTTP 204 — ID may be wrong or extension removed)."
            )
        raise ExtensionLoadError(
            f"Download failed (HTTP {e.code}): {e.reason}\n"
            f"URL: {url}"
        )
    except urllib.error.URLError as e:
        raise ExtensionLoadError(
            f"Network error downloading extension: {e.reason}\n"
            "Check your internet connection."
        )

    if len(data) < 16:
        raise ExtensionLoadError(
            f"Download returned {len(data)} bytes — extension may not exist "
            "or the ID is incorrect."
        )

    with open(dest_path, "wb") as f:
        f.write(data)


def _load_from_file(file_path: str, ext_id: str) -> Tuple[dict, Dict[str, str], str]:
    unpack_dir = os.path.join(SAMPLES_BASE, ext_id, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)
    try:
        _unpack(file_path, unpack_dir)
        root = _find_manifest_root(unpack_dir)
        return _load_from_directory(root), _read_js_files(root), root
    except Exception as e:
        raise ExtensionLoadError(f"Failed to unpack: {e}")


# ── Unpack helpers ────────────────────────────────────────────────────────────

def _unpack(src: str, dest: str):
    """Handle both CRX3 and plain ZIP."""
    with open(src, "rb") as f:
        magic = f.read(4)

    if magic == b"Cr24":
        _unpack_crx(src, dest)
    else:
        _safe_unzip(src, dest)


def _unpack_crx(crx_path: str, dest: str):
    """Unpack CRX3 format."""
    with open(crx_path, "rb") as f:
        magic = f.read(4)
        if magic != b"Cr24":
            raise ExtensionLoadError("Not a valid CRX file")

        version = struct.unpack("<I", f.read(4))[0]
        if version not in (2, 3):
            raise ExtensionLoadError(f"Unsupported CRX version: {version}")

        header_size = struct.unpack("<I", f.read(4))[0]
        f.seek(header_size, 1)
        zip_data = f.read()

    zip_path = os.path.join(dest, "_ext.zip")
    with open(zip_path, "wb") as f:
        f.write(zip_data)

    _safe_unzip(zip_path, dest)
    os.remove(zip_path)


def _safe_unzip(zip_path: str, dest: str):
    """Unzip with zip-slip protection."""
    real_dest = os.path.realpath(dest)
    with zipfile.ZipFile(zip_path, "r") as z:
        for member in z.namelist():
            target = os.path.realpath(os.path.join(real_dest, member))
            if not target.startswith(real_dest + os.sep) and target != real_dest:
                raise ExtensionLoadError(f"Zip slip blocked: {member}")
            z.extract(member, real_dest)


def _find_manifest_root(directory: str) -> str:
    """Find the directory containing manifest.json."""
    for root, dirs, files in os.walk(directory):
        if "manifest.json" in files:
            return root
    return directory


def _load_from_directory(directory: str) -> dict:
    manifest_path = os.path.join(directory, "manifest.json")
    if not os.path.exists(manifest_path):
        raise ExtensionLoadError(f"manifest.json not found in {directory}")
    with open(manifest_path, "r", encoding="utf-8", errors="replace") as f:
        return json.load(f)


def _read_js_files(directory: str) -> Dict[str, str]:
    """Read all JavaScript files from the extension directory."""
    js_files = {}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git", "vendor", "lib")]
        for filename in files:
            if filename.endswith((".js", ".mjs")):
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, directory)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    if len(content) <= 5 * 1024 * 1024:
                        js_files[rel_path] = content
                except Exception:
                    pass
    return js_files


# ── ID parser (unchanged) ─────────────────────────────────────────────────────

def parse_extension_id(input_str: str) -> Optional[str]:
    """Extract extension ID from URL or raw ID string."""
    input_str = input_str.strip()
    # Raw 32-char ID
    if len(input_str) == 32 and input_str.isalpha() and input_str.islower():
        return input_str
    # ID embedded in any URL path segment
    match = re.search(r'/([a-z]{32})(?:[/?]|$)', input_str)
    if match:
        return match.group(1)
    return None