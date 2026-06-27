/**
 * Fakeium REST API Server
 * Mirrors the box-js API interface exactly:
 *   GET  /health
 *   POST /sample          → upload JS, returns { id }
 *   GET  /sample/:id      → poll status, returns { ready }
 *   GET  /sample/:id/report → full IOC report
 *   DELETE /sample/:id    → cleanup
 *
 * sandbox_runner.py needs zero changes — just point BOX_API_URL
 * at this server (default port 8081) instead of box-js (port 8080).
 *
 * IOC types emitted (compatible with sandbox_runner._score_file):
 *   UrlFetch      — fetch() / XMLHttpRequest / any URL string accessed
 *   ChromeAPI     — chrome.* API call (cookies, tabs, storage, webRequest…)
 *   EvalCall      — eval() or new Function() invocation
 *   FileWrite     — (rare in extensions, kept for parity with box-js scorer)
 */

import express  from "express";
import multer   from "multer";
import fs       from "fs";
import path     from "path";
import { v4 as uuidv4 } from "uuid";
import { Fakeium } from "fakeium";

// ── Config ────────────────────────────────────────────────────────────────────
const CONFIG = {
    port:        parseInt(process.env.API_PORT    || "8081"),
    concurrency: parseInt(process.env.CONCURRENCY || "4"),
    timeout:     parseInt(process.env.BOX_TIMEOUT || "30"),   // seconds
    samplesDir:  process.env.SAMPLES_DIR          || "/samples",
    outputDir:   process.env.OUTPUT_DIR           || "/results",
};

// ── State ─────────────────────────────────────────────────────────────────────
const queue  = [];
const status = new Map();
let   active = 0;

// ── Fakeium runner ────────────────────────────────────────────────────────────
async function runAnalysis(id) {
    const meta       = status.get(id);
    const samplePath = path.join(CONFIG.samplesDir, id, "sample");
    const outPath    = path.join(CONFIG.outputDir,  id);
    fs.mkdirSync(outPath, { recursive: true });

    meta.status    = "running";
    meta.startedAt = new Date().toISOString();
    active++;

    console.log(`[${id}] Starting Fakeium on ${samplePath}`);

    try {
        const source  = fs.readFileSync(samplePath, "utf8");
        const fakeium = new Fakeium({
            timeout: CONFIG.timeout * 1000,   // ms
        });

        // ── Hook the Chrome extension namespace ───────────────────────────────
        // Fakeium auto-mocks anything it doesn't know via Proxy.
        // We pre-seed commonly accessed globals so the extension doesn't
        // get undefined on first access and bail out early.
        fakeium.hook("chrome",          {});
        fakeium.hook("browser",         {});   // Firefox WebExtension compat alias
        fakeium.hook("self",            {});   // service worker global
        fakeium.hook("globalThis",      {});
        fakeium.hook("navigator.userAgent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        fakeium.hook("location.href",   "https://example.com/");
        fakeium.hook("document.cookie", "");

        await fakeium.run(id + ".js", source);
        const events = fakeium.getReport().getAll();

        // ── Convert Fakeium events → IOC / urls / snippets ────────────────────
        const iocs     = [];
        const urlSet   = new Set();
        const snippets = [];

        const URL_RE = /https?:\/\/[^\s'"`,)]{6,}/g;

        for (const ev of events) {
            const apiPath = ev.path || "";
            const args    = ev.args || [];

            // ── URL fetch detection ───────────────────────────────────────────
            if (
                apiPath === "fetch" ||
                apiPath.includes("XMLHttpRequest") ||
                apiPath.includes("open") && args[1] && String(args[1]).startsWith("http")
            ) {
                const url = String(args[1] || args[0] || "");
                if (url.startsWith("http")) {
                    urlSet.add(url);
                    iocs.push({ type: "UrlFetch", value: { url } });
                }
            }

            // ── Chrome API call detection ─────────────────────────────────────
            if (apiPath.startsWith("chrome.") || apiPath.startsWith("browser.")) {
                iocs.push({
                    type:  "ChromeAPI",
                    value: {
                        api:  apiPath,
                        args: args.slice(0, 3).map(a => String(a).slice(0, 200)),
                    },
                });

                // Pull URLs out of chrome API args
                for (const a of args) {
                    const s = String(a);
                    for (const m of s.matchAll(URL_RE)) urlSet.add(m[0]);
                }
            }

            // ── eval / new Function detection ─────────────────────────────────
            if (apiPath === "eval" || apiPath === "Function") {
                const body = String(args[0] || "").slice(0, 500);
                iocs.push({ type: "EvalCall", value: { body } });
                snippets.push(body);

                // Extract URLs from eval'd strings
                for (const m of body.matchAll(URL_RE)) urlSet.add(m[0]);
            }

            // ── String literals that look like URLs (set events) ──────────────
            if (ev.type === "set" || ev.type === "get") {
                const val = String(ev.value || "");
                for (const m of val.matchAll(URL_RE)) {
                    urlSet.add(m[0]);
                    iocs.push({ type: "UrlFetch", value: { url: m[0] } });
                }
            }
        }

        // ── Write output files (same layout as box-js .results dir) ──────────
        const resultDir = path.join(outPath, `${id}.results`);
        fs.mkdirSync(resultDir, { recursive: true });
        fs.writeFileSync(path.join(resultDir, "urls.json"),
            JSON.stringify([...urlSet]), "utf8");
        fs.writeFileSync(path.join(resultDir, "active_urls.json"),
            JSON.stringify([]), "utf8");
        fs.writeFileSync(path.join(resultDir, "IOC.json"),
            JSON.stringify(iocs), "utf8");
        fs.writeFileSync(path.join(resultDir, "snippets.json"),
            JSON.stringify(snippets.slice(0, 20)), "utf8");
        fs.writeFileSync(path.join(resultDir, "resources.json"),
            JSON.stringify({}), "utf8");
        // Raw events for debugging
        fs.writeFileSync(path.join(outPath, "events.json"),
            JSON.stringify(events, null, 2), "utf8");

        meta.status      = "done";
        meta.exitCode    = 0;
        meta.exitMeaning = "success";
        console.log(`[${id}] done — ${iocs.length} IOCs, ${urlSet.size} URLs`);

    } catch (err) {
        meta.status      = "error";
        meta.exitCode    = 1;
        meta.exitMeaning = "generic_error";
        meta.error       = err.message;
        console.error(`[${id}] error: ${err.message}`);
    } finally {
        meta.finishedAt = new Date().toISOString();
        active--;
        processQueue();
    }
}

function processQueue() {
    while (active < CONFIG.concurrency && queue.length > 0) {
        runAnalysis(queue.shift());
    }
}

// ── Result reader (mirrors box-js readJSON) ───────────────────────────────────
function readJSON(id, filename, fallback) {
    const outPath = path.join(CONFIG.outputDir, id);
    try {
        const entries = fs.readdirSync(outPath);
        const sub     = entries.find(e => e.endsWith(".results"));
        const dir     = sub ? path.join(outPath, sub) : outPath;
        return JSON.parse(fs.readFileSync(path.join(dir, filename), "utf8"));
    } catch { return fallback; }
}

function fullReport(id) {
    const meta = status.get(id) || {};
    return {
        id,
        status:      meta.status,
        exitCode:    meta.exitCode,
        exitMeaning: meta.exitMeaning,
        startedAt:   meta.startedAt,
        finishedAt:  meta.finishedAt,
        error:       meta.error || null,
        results: {
            urls:       readJSON(id, "urls.json",        []),
            activeUrls: readJSON(id, "active_urls.json", []),
            resources:  readJSON(id, "resources.json",   {}),
            snippets:   readJSON(id, "snippets.json",    []),
            iocs:       readJSON(id, "IOC.json",         []),
        },
    };
}

// ── Express app ───────────────────────────────────────────────────────────────
const app    = express();
const upload = multer({ dest: "/tmp/uploads/" });
app.use(express.json());

// GET /health  — identical shape to box-js
app.get("/health", (req, res) => {
    res.json({
        status: "ok", engine: "fakeium",
        active, queued: queue.length, concurrency: CONFIG.concurrency,
    });
});

// POST /sample  — identical to box-js
app.post("/sample", upload.single("sample"), (req, res) => {
    if (!req.file) return res.status(400).json({ server_err: 5, message: "No file given" });

    const id        = uuidv4();
    const sampleDir = path.join(CONFIG.samplesDir, id);
    fs.mkdirSync(sampleDir, { recursive: true });

    // copyFileSync + unlinkSync avoids EXDEV across /tmp → /samples
    fs.copyFileSync(req.file.path, path.join(sampleDir, "sample"));
    fs.unlinkSync(req.file.path);

    status.set(id, {
        status: "queued", queuedAt: new Date().toISOString(),
        startedAt: null, finishedAt: null,
        exitCode: null, exitMeaning: null, error: null,
    });
    queue.push(id);
    processQueue();

    console.log(`[${id}] queued (depth: ${queue.length})`);
    res.status(202).json({ server_err: 0, id });
});

// GET /sample/:id
app.get("/sample/:id", (req, res) => {
    const meta = status.get(req.params.id);
    if (!meta) return res.status(404).json({ server_err: 2, message: "Not found" });
    const done = meta.status === "done" || meta.status === "error";
    res.json({
        server_err: 0, id: req.params.id,
        status: meta.status, ready: done ? 1 : 0,
        exitCode: meta.exitCode, exitMeaning: meta.exitMeaning,
        queuedAt: meta.queuedAt, startedAt: meta.startedAt, finishedAt: meta.finishedAt,
    });
});

// GET /sample/:id/report
app.get("/sample/:id/report", (req, res) => {
    const meta = status.get(req.params.id);
    if (!meta) return res.status(404).json({ server_err: 2 });
    if (meta.status !== "done" && meta.status !== "error")
        return res.status(202).json({ server_err: 4, message: "Not ready" });
    res.json({ server_err: 0, ...fullReport(req.params.id) });
});

// GET /sample/:id/iocs
app.get("/sample/:id/iocs", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, iocs: readJSON(req.params.id, "IOC.json", []) });
});

// GET /sample/:id/urls
app.get("/sample/:id/urls", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, urls: readJSON(req.params.id, "urls.json", []) });
});

// DELETE /sample/:id
app.delete("/sample/:id", (req, res) => {
    const { id } = req.params;
    const meta   = status.get(id);
    if (!meta) return res.status(404).json({ server_err: 2 });
    if (meta.status === "running" || meta.status === "queued")
        return res.status(409).json({ server_err: 99, message: "Still running" });
    status.delete(id);
    fs.rmSync(path.join(CONFIG.samplesDir, id), { recursive: true, force: true });
    fs.rmSync(path.join(CONFIG.outputDir,  id), { recursive: true, force: true });
    res.json({ server_err: 0, deleted: id });
});

// GET /samples
app.get("/samples", (req, res) => {
    const list = [...status.entries()].map(([id, m]) =>
        ({ id, status: m.status, queuedAt: m.queuedAt, finishedAt: m.finishedAt }));
    res.json({ server_err: 0, total: list.length, samples: list });
});

// ── Start ──────────────────────────────────────────────────────────────────────
app.listen(CONFIG.port, "0.0.0.0", () => {
    console.log(`✅ Fakeium API ready on port ${CONFIG.port}`);
    console.log(`   Concurrency: ${CONFIG.concurrency} | Timeout: ${CONFIG.timeout}s`);
});
