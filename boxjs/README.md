# box-js Sandbox Integration

Single-tool sandbox built on **box-js** — the JavaScript malware emulator.  
The REST API wraps box-js CLI; each analysis runs in an isolated **sibling Docker container**.

```
ext-analyzer
    │  POST /sample (file upload)
    ▼
┌─────────────────────────┐
│  boxjs-api container    │  ← Hapi REST API (Node.js)
│  port 8080              │
└─────────┬───────────────┘
          │ docker run --network=none
          ▼
┌─────────────────────────┐
│  capacitorset/box-js    │  ← ephemeral, --rm, no network
│  (analysis container)   │
└─────────────────────────┘
          │ writes to shared volume
          ▼
    /results/{uuid}/
      ├── urls.json
      ├── active_urls.json
      ├── resources.json
      ├── snippets.json
      └── IOC.json
```

---

## Quick start

```bash
# 1. Clone / copy this folder
cd boxjs-sandbox

# 2. Pull the official box-js image (used by sibling containers)
docker pull capacitorset/box-js

# 3. Build the API image and start
docker compose up -d --build

# 4. Check health
curl http://localhost:8080/health
```

---

## REST API Reference

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/health` | Server health, active + queued count |
| `GET`  | `/concurrency` | Current concurrency limit |
| `POST` | `/concurrency` `{value}` | Change concurrency |
| `POST` | `/sample` `{sample: file}` | **Submit** a sample → returns `{id}` |
| `GET`  | `/sample/{id}` | Status: `{status, ready: 0|1}` |
| `GET`  | `/sample/{id}/report` | **Full report** (URLs + IOCs + resources + snippets) |
| `GET`  | `/sample/{id}/urls` | All contacted URLs |
| `GET`  | `/sample/{id}/active_urls` | URLs that dropped live malware |
| `GET`  | `/sample/{id}/resources` | Files written to disk by the sample |
| `GET`  | `/sample/{id}/iocs` | Indicators of Compromise |
| `GET`  | `/samples` | List all analyses |
| `DELETE` | `/sample/{id}` | Delete results + sample |

### Exit codes (mapped to `exitMeaning`)

| Code | Meaning | Action |
|------|---------|--------|
| 0 | `success` | — |
| 1 | `generic_error` | check stderr log |
| 2 | `timeout` | results may be partial; increase `BOX_TIMEOUT` |
| 3 | `rewrite_error` | resubmit with `--no-rewrite` (see advanced config) |
| 4 | `parse_error` | file is JSE/VBScript — decode first |
| 5 | `shell_error_uncaught` | resubmit with `--no-shell-error` |
| 255 | `no_files` | no sample was passed |

---

## Python client (ext-analyzer integration)

```python
from client.boxjs_client import BoxJSClient

client = BoxJSClient("http://localhost:8080")

# Full pipeline: submit → wait → result
result = client.analyze("/path/to/sample.js")

print(result.active_urls)   # list[str]
print(result.iocs)           # list[dict]
print(result.resources)      # dict[uuid → {type, md5, path}]

# Compact dict for your reporting layer
report = result.summary()
```

### Async (non-blocking) flow

```python
# Submit only
analysis_id = client.submit("/path/to/sample.js")

# Poll manually
while True:
    status = client.poll(analysis_id)
    if status["ready"] == 1:
        break
    time.sleep(2)

result = client.get_report(analysis_id)
client.delete(analysis_id)   # cleanup when done
```

### CLI

```bash
pip install requests
python client/boxjs_client.py sample.js --api http://localhost:8080 --json
```

---

## Configuration

Edit `.env`:

```
API_PORT=8080       # host port
CONCURRENCY=4       # parallel analyses (one per CPU is a good default)
BOX_TIMEOUT=30      # seconds before box-js times out a single sample
```

---

## Security notes

- Analysis containers run with `--network=none` by default (no outbound calls).  
  Remove or change this in `api-server.js` if you need `--download` behaviour.
- The Docker socket is mounted **read-only** into the API container.
- Each analysis container is ephemeral (`--rm`) — filesystem is discarded after exit.
- Shared volumes (`boxjs-samples`, `boxjs-results`) are the only persistence.
