"""
box-js Sandbox Client
─────────────────────
Drop-in client for ext-analyzer to submit JS/JSE/HTA/WSF samples
to the box-js REST API and retrieve structured results.

Usage (standalone):
    python boxjs_client.py /path/to/sample.js

Usage (as library):
    from boxjs_client import BoxJSClient

    client = BoxJSClient("http://localhost:8080")
    result = client.analyze("/path/to/sample.js", wait=True)
    print(result.iocs)
    print(result.active_urls)
"""

import time
import json
import logging
import requests
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("boxjs-client")


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class BoxJSResult:
    id:           str
    status:       str                    # "done" | "error" | "queued" | "running"
    exit_code:    Optional[int]  = None
    exit_meaning: Optional[str]  = None
    started_at:   Optional[str]  = None
    finished_at:  Optional[str]  = None
    error:        Optional[str]  = None

    # Analysis results
    urls:         list  = field(default_factory=list)
    active_urls:  list  = field(default_factory=list)
    resources:    dict  = field(default_factory=dict)
    snippets:     list  = field(default_factory=list)
    iocs:         list  = field(default_factory=list)

    @property
    def is_done(self) -> bool:
        return self.status in ("done", "error")

    @property
    def success(self) -> bool:
        return self.status == "done"

    def summary(self) -> dict:
        """Compact summary suitable for ext-analyzer reporting."""
        return {
            "id":           self.id,
            "status":       self.status,
            "exit_meaning": self.exit_meaning,
            "urls_count":   len(self.urls),
            "active_urls":  self.active_urls,
            "ioc_count":    len(self.iocs),
            "resources":    {
                k: {"type": v.get("type"), "md5": v.get("md5"), "path": v.get("path")}
                for k, v in self.resources.items()
            },
            "iocs":         self.iocs,
            "error":        self.error,
        }


# ── Client ────────────────────────────────────────────────────────────────────

class BoxJSClient:
    """
    HTTP client for the box-js REST API sandbox.

    Parameters
    ----------
    base_url : str
        Base URL of the API server, e.g. "http://localhost:8080"
    poll_interval : float
        Seconds between status poll requests (default 2.0)
    max_wait : float
        Maximum seconds to wait for analysis completion (default 120)
    timeout : float
        HTTP request timeout in seconds (default 10)
    """

    SUPPORTED_EXTENSIONS = {".js", ".jse", ".wsf", ".wsh", ".hta", ".vbs", ".vbe"}

    def __init__(
        self,
        base_url:      str   = "http://localhost:8080",
        poll_interval: float = 2.0,
        max_wait:      float = 120.0,
        timeout:       float = 10.0,
    ):
        self.base_url      = base_url.rstrip("/")
        self.poll_interval = poll_interval
        self.max_wait      = max_wait
        self.timeout       = timeout
        self._session      = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    # ── Public API ────────────────────────────────────────────────────────────

    def health(self) -> dict:
        """Check if the API server is alive."""
        r = self._get("/health")
        return r.json()

    def submit(self, sample_path: str) -> str:
        """
        Submit a sample file for analysis.

        Returns
        -------
        str
            The analysis UUID to use with poll() / get_report()
        """
        p = Path(sample_path)
        if not p.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        ext = p.suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            log.warning(
                "Extension '%s' is not in the known-supported list %s — submitting anyway",
                ext, self.SUPPORTED_EXTENSIONS,
            )

        with open(p, "rb") as fh:
            r = self._session.post(
                f"{self.base_url}/sample",
                files={"sample": (p.name, fh, "application/octet-stream")},
                timeout=self.timeout,
            )
        r.raise_for_status()
        data = r.json()
        if data.get("server_err", 0) != 0:
            raise RuntimeError(f"API error on submit: {data}")

        analysis_id = data["id"]
        log.info("Submitted %s → analysis ID: %s", p.name, analysis_id)
        return analysis_id

    def poll(self, analysis_id: str) -> dict:
        """Return the current status dict for an analysis."""
        r = self._get(f"/sample/{analysis_id}")
        return r.json()

    def get_report(self, analysis_id: str) -> BoxJSResult:
        """
        Retrieve the full analysis report.
        Raises RuntimeError if the analysis is not yet complete.
        """
        r = self._get(f"/sample/{analysis_id}/report")
        if r.status_code == 202:
            raise RuntimeError("Analysis not yet ready")
        r.raise_for_status()
        data = r.json()
        return self._parse_report(data)

    def wait_for_result(self, analysis_id: str) -> BoxJSResult:
        """
        Block until the analysis finishes, then return BoxJSResult.
        Raises TimeoutError if max_wait is exceeded.
        """
        deadline = time.monotonic() + self.max_wait
        log.info("Waiting for analysis %s (max %.0fs)…", analysis_id, self.max_wait)

        while time.monotonic() < deadline:
            try:
                status = self.poll(analysis_id)
            except requests.RequestException as e:
                log.warning("Poll failed: %s — retrying", e)
                time.sleep(self.poll_interval)
                continue

            current = status.get("status", "unknown")
            log.debug("  status: %s", current)

            if current in ("done", "error"):
                return self.get_report(analysis_id)

            time.sleep(self.poll_interval)

        raise TimeoutError(
            f"Analysis {analysis_id} did not finish within {self.max_wait}s"
        )

    def analyze(self, sample_path: str, wait: bool = True, cleanup: bool = False) -> BoxJSResult:
        """
        Full pipeline: submit → wait → get result → (optionally) cleanup.

        Parameters
        ----------
        sample_path : str
            Path to the sample file on disk.
        wait : bool
            If True (default), block until analysis is done.
        cleanup : bool
            If True, delete the analysis from the server after retrieving results.
        """
        analysis_id = self.submit(sample_path)

        if not wait:
            # Return a stub result so the caller can poll manually
            return BoxJSResult(id=analysis_id, status="queued")

        result = self.wait_for_result(analysis_id)

        if cleanup:
            try:
                self.delete(analysis_id)
            except Exception as e:
                log.warning("Cleanup failed for %s: %s", analysis_id, e)

        return result

    def delete(self, analysis_id: str) -> bool:
        """Delete analysis results from the server."""
        r = self._session.delete(
            f"{self.base_url}/sample/{analysis_id}",
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json().get("server_err", 99) == 0

    def list_analyses(self) -> list:
        """List all analyses tracked by the server."""
        r = self._get("/samples")
        return r.json().get("samples", [])

    # ── Internal ──────────────────────────────────────────────────────────────

    def _get(self, path: str) -> requests.Response:
        r = self._session.get(f"{self.base_url}{path}", timeout=self.timeout)
        r.raise_for_status()
        return r

    @staticmethod
    def _parse_report(data: dict) -> BoxJSResult:
        results = data.get("results", {})
        return BoxJSResult(
            id           = data.get("id", ""),
            status       = data.get("status", "unknown"),
            exit_code    = data.get("exitCode"),
            exit_meaning = data.get("exitMeaning"),
            started_at   = data.get("startedAt"),
            finished_at  = data.get("finishedAt"),
            error        = data.get("error"),
            urls         = results.get("urls",        []),
            active_urls  = results.get("activeUrls",  []),
            resources    = results.get("resources",   {}),
            snippets     = results.get("snippets",    []),
            iocs         = results.get("iocs",        []),
        )


# ── ext-analyzer integration hook ─────────────────────────────────────────────

def analyze_sample(file_path: str, api_url: str = "http://localhost:8080") -> dict:
    """
    Single-call integration entry point for ext-analyzer.

    Returns a dict with:
        success      bool
        status       str
        active_urls  list[str]
        iocs         list[dict]
        resources    dict
        error        str | None
    """
    client = BoxJSClient(base_url=api_url)
    try:
        result = client.analyze(file_path, wait=True, cleanup=False)
        return result.summary()
    except TimeoutError as e:
        return {"success": False, "status": "timeout", "error": str(e), "active_urls": [], "iocs": [], "resources": {}}
    except Exception as e:
        return {"success": False, "status": "error", "error": str(e), "active_urls": [], "iocs": [], "resources": {}}


# ── CLI entrypoint ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    parser = argparse.ArgumentParser(description="Submit a sample to the box-js sandbox")
    parser.add_argument("sample",     help="Path to the JS/JSE/HTA/WSF sample")
    parser.add_argument("--api",      default="http://localhost:8080", help="API base URL")
    parser.add_argument("--no-wait",  action="store_true", help="Submit only, don't wait")
    parser.add_argument("--cleanup",  action="store_true", help="Delete results after retrieval")
    parser.add_argument("--json",     action="store_true", help="Output raw JSON report")
    args = parser.parse_args()

    client = BoxJSClient(base_url=args.api)

    # Verify server is alive
    try:
        h = client.health()
        log.info("Server health: %s", h)
    except Exception as e:
        print(f"❌  Cannot reach API at {args.api}: {e}", file=sys.stderr)
        sys.exit(1)

    result = client.analyze(args.sample, wait=not args.no_wait, cleanup=args.cleanup)

    if args.json:
        print(json.dumps(result.summary(), indent=2))
    else:
        print(f"\n{'─'*60}")
        print(f"  Analysis ID : {result.id}")
        print(f"  Status      : {result.status} ({result.exit_meaning})")
        print(f"  Started     : {result.started_at}")
        print(f"  Finished    : {result.finished_at}")
        print(f"\n  URLs contacted ({len(result.urls)}):")
        for u in result.urls:
            print(f"    {u}")
        print(f"\n  ⚠️  Active (malware-dropping) URLs ({len(result.active_urls)}):")
        for u in result.active_urls:
            print(f"    🔴 {u}")
        print(f"\n  Resources written to disk ({len(result.resources)}):")
        for uuid, r in result.resources.items():
            print(f"    {uuid[:8]}…  type={r.get('type','?')}  md5={r.get('md5','?')}")
        print(f"\n  IOCs ({len(result.iocs)}):")
        for ioc in result.iocs:
            print(f"    {ioc}")
        if result.error:
            print(f"\n  ❌ Error: {result.error}")
        print(f"{'─'*60}\n")
