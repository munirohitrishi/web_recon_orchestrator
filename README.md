# Web Recon Orchestrator

**Web Recon Orchestrator** is a lightweight Python wrapper that runs common reconnaissance and scanning tools (subfinder, dnsx, httpx, massdns, nmap, nuclei, gobuster, gau/waybackurls, wpscan, OWASP ZAP) and stores all outputs in a timestamped results directory.  
It’s built for repeatable, auditable scans with safe defaults (conservative threads / read-only checks).

> ⚠️ **Important:** Only run this script against targets you own or have explicit written permission to test. Scanning third-party systems without authorization may be illegal.

---

## Features
- Create a new `results/<target>_<timestamp>/` folder per run.
- Run a selectable subset of tools (skip modules with flags).
- Capture each tool's stdout/stderr into files for later review.
- Produce a `manifest.json` documenting the run (commands, timestamps, files).
- Conservative defaults: non-destructive, limited request counts.

---

## Requirements

### System packages (Ubuntu / WSL)
Install the tools you want to use (examples):
```bash
# essentials
sudo apt update
sudo apt install -y curl wget unzip git nmap jq python3 python3-venv python3-dev build-essential

# optional GUI tools
# OWASP ZAP usually installed separately (download/extract ZAP or install via package manager)
