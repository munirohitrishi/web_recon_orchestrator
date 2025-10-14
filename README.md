name: "Web Recon Orchestrator"
description: >
  Web Recon Orchestrator is a safe, configurable Python orchestrator that runs common
  reconnaissance and scanning tools (subfinder, dnsx, httpx, massdns, nmap, nuclei,
  gobuster, gau/waybackurls, wpscan, OWASP ZAP) and stores their raw outputs into a
  timestamped results folder. Designed for repeatable, auditable scans with conservative
  defaults (read-only probes, limited threads).

warning: >
  IMPORTANT: Only run this script against targets you own or have explicit written
  permission to test. Scanning third-party systems without authorization may be illegal.

features:
  - "Timestamped results folder per run (results/<target>_<timestamp>/)."
  - "Run selectable tools (flags to skip modules)."
  - "Capture each tool's stdout/stderr into files for later review."
  - "Produce manifest.json documenting the run (timestamp, commands, file paths)."
  - "Conservative defaults: non-destructive, limited concurrency, fetch-limits."

requirements:
  system_packages:
    - "curl"
    - "wget"
    - "unzip"
    - "git"
    - "nmap"
    - "jq"
    - "python3 (3.9+ recommended)"
    - "python3-venv"
    - "build-essential (for compiling libs if needed)"
  go_tools: >
    Recommended to install via `go install` (ensure $(go env GOPATH)/bin in PATH):
    - "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    - "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    - "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    - "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    - "github.com/OJ/gobuster/v3@latest"
  optional_tools:
    - "massdns"
    - "gau or waybackurls"
    - "wpscan"
    - "OWASP ZAP (for baseline scans)"
  python:
    - "Create a venv: python3 -m venv .venv && source .venv/bin/activate"
    - "Upgrade pip: pip install --upgrade pip"

install_instructions:
  - "Place web_recon_orchestrator.py at repo root and make executable: chmod +x web_recon_orchestrator.py"
  - "Ensure the external tools you plan to use are installed and available in PATH."
  - "Optional: add a .gitignore to avoid committing results/ (see below)."

git_ignore:
  content: |
    results/
    *.out
    *.err

usage:
  synopsis: "python3 web_recon_orchestrator.py -t <target> [options]"
  examples:
    - description: "Basic conservative run"
      command: "python3 web_recon_orchestrator.py -t docs.sprinto.com"
    - description: "Enable ZAP baseline and increase threads"
      command: "python3 web_recon_orchestrator.py -t docs.sprinto.com --zap --threads 30"
    - description: "Skip modules (skip nmap and nuclei)"
      command: "python3 web_recon_orchestrator.py -t example.com --no-nmap --no-nuclei"
    - description: "View help"
      command: "python3 web_recon_orchestrator.py -h"

cli_options:
  - name: "-t, --target"
    required: true
    description: "Target domain or host (eg. docs.sprinto.com)."
  - name: "-o, --outbase"
    default: "results"
    description: "Base output directory."
  - name: "--no-subfinder"
    description: "Skip subfinder."
  - name: "--no-dnsx"
    description: "Skip dnsx."
  - name: "--no-httpx"
    description: "Skip httpx."
  - name: "--no-nuclei"
    description: "Skip nuclei."
  - name: "--no-nmap"
    description: "Skip nmap."
  - name: "--no-gobuster"
    description: "Skip gobuster."
  - name: "--no-gau"
    description: "Skip gau/waybackurls."
  - name: "--no-wpscan"
    description: "Skip wpscan."
  - name: "--zap"
    description: "Run OWASP ZAP baseline (requires ZAP installed)."
  - name: "--wordlist"
    description: "Wordlist path for gobuster (optional)."
  - name: "--nmap-ports"
    default: "-F"
    description: "Nmap ports option (default -F quick scan)."
  - name: "--threads"
    default: 20
    description: "Default threads for httpx/gobuster."
  - name: "--nuclei-templates"
    description: "Path to nuclei-templates (if None uses default)."

output_layout:
  description: "Each run creates results/<target>_YYYYmmddTHHMMSS/ with:"
  files:
    - "manifest.json -> metadata of the run (timestamp, target, modules executed, result file paths)."
    - "<tool>.out / <tool>.err -> stdout and stderr for each tool (e.g., subfinder.out, subfinder.err)."
    - "subfinder.txt, dnsx_resolved.txt, httpx_out.txt, nuclei.json, nmap.xml, gobuster_dirs.txt -> tool-specific outputs."
    - "fetched/ -> downloaded archived pages (limited)."
    - "live_urls.txt -> consolidated list of live URLs found by httpx."

example_manifest_snippet: |
  {
    "target": "docs.sprinto.com",
    "timestamp": "20251014T123456Z",
    "commands": [],
    "results": {
      "subfinder": {"rc": 0, "stdout": "subfinder.out", "stderr": "subfinder.err", "path": "subfinder.txt"},
      "dnsx": {"rc": 0, "stdout": "dnsx.out", "stderr": "dnsx.err", "path": "dnsx_resolved.txt"},
      "httpx": {"rc": 0, "stdout": "httpx.out", "stderr": "httpx.err", "path": "httpx_out.txt"}
    }
  }

safety_best_practices:
  - "Authorization: Always have written permission before scanning third-party targets."
  - "Rate limiting: Use conservative thread counts (increase only with permission)."
  - "Non-destructive: Script defaults to read-only probes only. Do not enable aggressive scans without a test plan."
  - "Sensitive outputs: Treat results/ as sensitive. Do not upload raw outputs containing tokens/credentials publicly."
  - "Review: Manually validate findings before remediation or disclosure."

extending_customization:
  suggestions:
    - "Add or remap tools by editing the script's check_tool() and command sections."
    - "Change gobuster wordlists or nuclei templates via --wordlist and --nuclei-templates."
    - "Add a proxy option (for Burp/inspection) by injecting -p/--proxy for tools that support it."
    - "Integrate CI: run the script in a disposable environment and store artifacts in a secure bucket."

example_workflow_git:
  steps:
    - "Add web_recon_orchestrator.py and README.md to your repo."
    - "Create .gitignore to exclude results/."
    - "Commit and push: git add web_recon_orchestrator.py README.md .gitignore && git commit -m 'Add recon orchestrator' && git push origin <branch>"
    - "Run locally: python3 web_recon_orchestrator.py -t docs.sprinto.com"

troubleshooting:
  common_issues:
    - problem: "Tool not found"
      resolution: "Ensure the binary is in your PATH. For Go tools, ensure $(go env GOPATH)/bin is added to PATH."
    - problem: "Permission denied when running tools"
      resolution: "Run with appropriate user privileges or adjust file permissions. Avoid sudo unless needed."
    - problem: "Empty outputs"
      resolution: "Check the corresponding <tool>.err file in the results folder for errors. Re-run the single tool manually to debug."

license:
  recommended: "MIT"
  note: "Choose an appropriate OSS license (MIT or Apache-2.0 recommended)."

contributing:
  guidelines:
    - "Do not add sensitive data or example tokens."
    - "Keep default behavior conservative and non-destructive."
    - "Add unit tests for parsing or post-processing changes."

contact:
  author: "<Your Name / Handle>"
  note: "Use responsibly and always with permission."
