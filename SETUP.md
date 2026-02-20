# ACIR Platform — Setup Guide
### Getting started from a fresh laptop (Windows)

---

## What You Need to Install First

Before touching the project, install these three things in order.

---

### 1. Python 3.11 or 3.13

Download from: **https://www.python.org/downloads/**

> During installation, on the first screen tick **"Add Python to PATH"** before clicking Install Now. This is critical — without it nothing will work.

Verify it worked by opening PowerShell and running:
```powershell
python --version
```
You should see something like `Python 3.13.7`.

---

### 2. Docker Desktop

Download from: **https://www.docker.com/products/docker-desktop/**

Docker is used to run Elasticsearch (the database that stores the logs and alerts). You do not need to know how Docker works — just install it and make sure the Docker Desktop application is **open and running** (look for the whale icon in your taskbar) before starting the project.

Verify it worked:
```powershell
docker --version
```
You should see `Docker version 27.x.x` or similar.

---

### 3. Git (optional — only needed if cloning from GitHub)

Download from: **https://git-scm.com/downloads**

If your friend is sending you a **ZIP file** instead, skip this — just extract the zip.

---

## Project Setup

### Step 1 — Extract the project

Extract the ZIP to a folder, for example `D:\Sentinel`.

You should have a folder structure like:
```
D:\Sentinel\
    acir_platform\
        config.py
        models.py
        requirements_task1.txt
        task1_ingestion\
        tests\
        frontend\
    SETUP.md
    ACIR_Implementation_Plan.md
```

---

### Step 2 — Open PowerShell in the project folder

Right-click the `D:\Sentinel` folder → **Open in Terminal** (or open PowerShell and type):
```powershell
cd D:\Sentinel
```

---

### Step 3 — Install Python dependencies

Run this single command — it installs every Python package the project needs:
```powershell
pip install fastapi uvicorn "elasticsearch>=8.13.0,<9.0.0" pyod presidio-analyzer presidio-anonymizer spacy faker pydantic httpx pytest pytest-asyncio numpy pandas scikit-learn python-multipart
```

This will take **2–5 minutes** depending on your internet speed. You will see a lot of text scrolling — that is normal.

After it finishes, download the English language model for the PII scrubber:
```powershell
python -m spacy download en_core_web_lg
```

---

### Step 4 — Start Elasticsearch (the database)

Make sure Docker Desktop is open, then run:
```powershell
docker run -d --name es-acir -p 9200:9200 -e "discovery.type=single-node" -e "xpack.security.enabled=false" -e "ES_JAVA_OPTS=-Xms512m -Xmx512m" elasticsearch:8.13.0
```

This downloads and starts Elasticsearch. The first time it runs it will download ~600 MB — subsequent starts are instant.

Wait about **30–45 seconds** for it to fully start, then verify it is running:
```powershell
Invoke-WebRequest -Uri http://localhost:9200 -UseBasicParsing | Select-Object StatusCode
```
You should see `StatusCode : 200`.

> **Next time you restart your laptop**, Elasticsearch will be stopped. Start it again with:
> ```powershell
> docker start es-acir
> ```

---

### Step 5 — Start the API server

```powershell
cd D:\Sentinel\acir_platform
python -m uvicorn task1_ingestion.api:app --host 0.0.0.0 --port 8001
```

You should see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001 (Press CTRL+C to quit)
```

**Leave this terminal window open.** The server runs in the foreground — closing the window stops the server.

> To stop the server later: press `Ctrl + C` in this terminal.

---

### Step 6 — Open the dashboard

Open this file in your browser (Chrome or Edge recommended):
```
D:\Sentinel\acir_platform\frontend\index.html
```

You can double-click it in File Explorer, or in PowerShell (open a **new** terminal tab so you don't stop the server):
```powershell
Start-Process "D:\Sentinel\acir_platform\frontend\index.html"
```

---

## Using the Dashboard

Once the dashboard is open you should see:
- **ES Mode** (green badge, top right of the Task 1 panel) — confirms Elasticsearch is connected
- **API Server: :8001** (bottom-left sidebar) — green dot confirms the API is running

### Running the pipeline

1. Use the **Log Volume** slider to choose how many fake security logs to generate (200 is a good start)
2. Use the **Attack Fraction** slider to control what percentage are injected attack events (8% = realistic, 30%+ = very noisy for testing)
3. Click **Run Pipeline**
4. After 10–30 seconds (depending on log volume), alerts will appear in the table
5. Click any alert row to see its full detail — risk score breakdown, time-series features, scrubbed payload

### PII Scrubber Demo

1. Scroll down to the **PII Scrubber Demo** panel
2. Click one of the example chips (Email, Credit Card, IBAN, etc.) or type your own text
3. Click **Scrub PII** — redacted tokens like `<EMAIL_ADDRESS>` and `<CREDIT_CARD>` will appear highlighted in orange

---

## Running the Tests

To run the full 84-test suite (with Elasticsearch running):

```powershell
cd D:\Sentinel\acir_platform
python -m pytest tests/test_task1.py -v
```

Expected result: `84 passed, 0 failed` in about 30 seconds.

---

## Quick-Start Checklist (every session)

When you come back after restarting your laptop:

- [ ] Open **Docker Desktop** (wait for the whale icon to stop animating)
- [ ] In PowerShell: `docker start es-acir`
- [ ] Wait 30 seconds, then in PowerShell: `cd D:\Sentinel\acir_platform` → `python -m uvicorn task1_ingestion.api:app --host 0.0.0.0 --port 8001`
- [ ] Open `D:\Sentinel\acir_platform\frontend\index.html` in browser

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `python` not found | Re-install Python and tick "Add Python to PATH" |
| `docker` not found | Open Docker Desktop and wait for it to finish starting |
| `ModuleNotFoundError` | Re-run the `pip install` command from Step 3 |
| ES Mode shows red / offline badge | Run `docker start es-acir` and wait 30 seconds, then click the refresh button in the dashboard header |
| Port 8001 already in use | Another instance of the server is running. Open Task Manager, find `python.exe`, end it, then restart |
| `pip install` fails on `pyod` | Run `pip install wheel` first, then retry |
| Scrubber returns an error | Run `python -m spacy download en_core_web_lg` (Step 3 second command) |
| Dashboard says "API server unreachable" | Make sure the `uvicorn` terminal is still open and the server printed "startup complete" |

---

## What Ports Are Used

| Port | Service |
|------|---------|
| `8001` | ACIR FastAPI server (the backend) |
| `9200` | Elasticsearch (the database) |

Make sure nothing else on your laptop is using these ports.

---

## Summary of All Software Required

| Software | Download Link | Why |
|----------|--------------|-----|
| Python 3.11+ | https://python.org/downloads | Runs all the code |
| Docker Desktop | https://docker.com/products/docker-desktop | Runs Elasticsearch |
| Chrome or Edge | Pre-installed on Windows | Opens the dashboard |
