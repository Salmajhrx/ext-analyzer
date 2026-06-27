"use strict";

const express  = require("express");
const multer   = require("multer");
const { spawn, exec } = require("child_process");
const fs       = require("fs");
const path     = require("path");
const { v4: uuidv4 } = require("uuid");

// ── Config ────────────────────────────────────────────────────────────────────
const CONFIG = {
    port:        parseInt(process.env.API_PORT    || "8080"),
    concurrency: parseInt(process.env.CONCURRENCY || "4"),
    timeout:     parseInt(process.env.BOX_TIMEOUT || "30"),
    outputDir:   process.env.OUTPUT_DIR           || "/results",
    samplesDir:  process.env.SAMPLES_DIR          || "/samples",
    boxjsImage:  process.env.BOXJS_IMAGE          || "capacitorset/box-js",
    useDocker:   process.env.USE_DOCKER           !== "false",
};

// ── State ─────────────────────────────────────────────────────────────────────
const queue   = [];
const status  = new Map();
let   active  = 0;

const EXIT_MEANING = {
    0: "success", 1: "generic_error", 2: "timeout",
    3: "rewrite_error", 4: "parse_error", 5: "shell_error", 255: "no_files",
};

// ── Analysis runner ───────────────────────────────────────────────────────────
function runAnalysis(id) {
    const meta       = status.get(id);
    const samplePath = path.join(CONFIG.samplesDir, id, "sample");
    const outPath    = path.join(CONFIG.outputDir, id);
    fs.mkdirSync(outPath, { recursive: true });

    meta.status    = "running";
    meta.startedAt = new Date().toISOString();
    active++;

    let cmd, args;
    if (CONFIG.useDocker) {
        cmd  = "docker";
        args = [
            "run", "--rm",
            "--network=none",
            "--memory=512m", "--cpus=1",
            `-v`, `${CONFIG.samplesDir}/${id}:/sample_in:ro`,
            `-v`, `${outPath}:/output`,
            CONFIG.boxjsImage,
            "box-js", "/sample_in/sample",
            `--output-dir=/output`,
            `--timeout=${CONFIG.timeout}`,
            "--loglevel=info", "--no-shell-error", "--no-echo",
        ];
    } else {
        cmd  = "box-js";
        args = [
            samplePath,
            `--output-dir=${outPath}`,
            `--timeout=${CONFIG.timeout}`,
            "--loglevel=info", "--no-shell-error",
        ];
    }

    console.log(`[${id}] Starting: ${cmd} ${args.join(" ")}`);
    const proc = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    proc.stdout.on("data", d => { stdout += d; });
    proc.stderr.on("data", d => { stderr += d; });

    proc.on("close", code => {
        active--;
        meta.finishedAt  = new Date().toISOString();
        meta.exitCode    = code;
        meta.exitMeaning = EXIT_MEANING[code] ?? `unknown_${code}`;
        meta.status      = (code === 0 || code === 2) ? "done" : "error";
        if (meta.status === "error") meta.error = stderr.slice(-2000);
        fs.writeFileSync(path.join(outPath, "stdout.log"), stdout);
        fs.writeFileSync(path.join(outPath, "stderr.log"), stderr);
        console.log(`[${id}] ${meta.status} (exit ${code}: ${meta.exitMeaning})`);
        processQueue();
    });

    proc.on("error", err => {
        active--;
        meta.status     = "error";
        meta.finishedAt = new Date().toISOString();
        meta.error      = err.message;
        console.error(`[${id}] Spawn error: ${err.message}`);
        processQueue();
    });
}

function processQueue() {
    while (active < CONFIG.concurrency && queue.length > 0) {
        runAnalysis(queue.shift());
    }
}

// ── Result helpers ────────────────────────────────────────────────────────────
function readJSON(id, filename, fallback) {
    const outPath = path.join(CONFIG.outputDir, id);
    try {
        const entries = fs.readdirSync(outPath);
        const sub     = entries.find(e => e.endsWith(".results"));
        const dir     = sub ? path.join(outPath, sub) : outPath;
        const fp      = path.join(dir, filename);
        return JSON.parse(fs.readFileSync(fp, "utf8"));
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

// GET /health
app.get("/health", (req, res) => {
    res.json({ status: "ok", active, queued: queue.length, concurrency: CONFIG.concurrency });
});

// POST /sample
app.post("/sample", upload.single("sample"), (req, res) => {
    if (!req.file) return res.status(400).json({ server_err: 5, message: "No file given" });

    const id        = uuidv4();
    const sampleDir = path.join(CONFIG.samplesDir, id);
    fs.mkdirSync(sampleDir, { recursive: true });
    fs.copyFileSync(req.file.path, path.join(sampleDir, "sample"));
    fs.unlinkSync(req.file.path);

    status.set(id, {
        status: "queued", queuedAt: new Date().toISOString(),
        startedAt: null, finishedAt: null, exitCode: null, exitMeaning: null, error: null,
    });
    queue.push(id);
    processQueue();

    console.log(`[${id}] Queued (depth: ${queue.length})`);
    res.status(202).json({ server_err: 0, id });
});

// GET /sample/:id
app.get("/sample/:id", (req, res) => {
    const meta = status.get(req.params.id);
    if (!meta) return res.status(404).json({ server_err: 2, message: "Not found" });
    const done = meta.status === "done" || meta.status === "error";
    res.json({ server_err: 0, id: req.params.id, status: meta.status, ready: done ? 1 : 0,
               exitCode: meta.exitCode, exitMeaning: meta.exitMeaning,
               queuedAt: meta.queuedAt, startedAt: meta.startedAt, finishedAt: meta.finishedAt });
});

// GET /sample/:id/report
app.get("/sample/:id/report", (req, res) => {
    const meta = status.get(req.params.id);
    if (!meta) return res.status(404).json({ server_err: 2 });
    if (meta.status !== "done" && meta.status !== "error")
        return res.status(202).json({ server_err: 4, message: "Not ready" });
    res.json({ server_err: 0, ...fullReport(req.params.id) });
});

// GET /sample/:id/urls
app.get("/sample/:id/urls", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, urls: readJSON(req.params.id, "urls.json", []) });
});

// GET /sample/:id/active_urls
app.get("/sample/:id/active_urls", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, active_urls: readJSON(req.params.id, "active_urls.json", []) });
});

// GET /sample/:id/iocs
app.get("/sample/:id/iocs", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, iocs: readJSON(req.params.id, "IOC.json", []) });
});

// GET /sample/:id/resources
app.get("/sample/:id/resources", (req, res) => {
    if (!status.has(req.params.id)) return res.status(404).json({ server_err: 2 });
    res.json({ server_err: 0, resources: readJSON(req.params.id, "resources.json", {}) });
});

// DELETE /sample/:id
app.delete("/sample/:id", (req, res) => {
    const { id } = req.params;
    const meta   = status.get(id);
    if (!meta) return res.status(404).json({ server_err: 2 });
    if (meta.status === "running" || meta.status === "queued")
        return res.status(409).json({ server_err: 99, message: "Still running" });
    status.delete(id);
    exec(`rm -rf "${path.join(CONFIG.samplesDir, id)}" "${path.join(CONFIG.outputDir, id)}"`);
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
    console.log(`✅ box-js API ready on port ${CONFIG.port}`);
    console.log(`   Concurrency: ${CONFIG.concurrency} | Timeout: ${CONFIG.timeout}s | Docker: ${CONFIG.useDocker}`);
});