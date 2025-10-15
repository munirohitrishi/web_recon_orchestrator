#!/usr/bin/env python3
"""
web_recon_orchestrator_fixed.py

Enhanced version: Fixes empty subfinder/nuclei via config notes, active mode, timeouts, verbose.
Adds mini-fallback subs if subfinder empty. Debug file size logs.
"""

from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import sys

# ---------------------- Helper functions ----------------------

def check_tool(name: str) -> str | None:
    """Return path of tool if present in PATH, else None."""
    return shutil.which(name)

def log_file_size(path: Path, name: str):
    """Debug: Print file size for key outputs."""
    if path.exists():
        size = path.stat().st_size
        print(f"[DEBUG] {name}: {size} bytes ({'empty' if size == 0 else 'populated'})")
    else:
        print(f"[DEBUG] {name}: missing")

def run_cmd(cmd: list, outdir: Path, name: str, capture: bool = True,
            env: dict | None = None, timeout: int | None = None, dry_run: bool = False) -> dict:
    """
    Run command list `cmd` and save stdout/stderr to files in outdir with base name `name`.
    Returns a dict with return code and stdout/stderr file paths.
    Supports optional timeout (seconds) and dry-run.
    """
    stdout_f = outdir / f"{name}.out"
    stderr_f = outdir / f"{name}.err"

    if dry_run:
        print("[DRY-RUN]", " ".join(map(str, cmd)))
        return {"rc": 0, "stdout": str(stdout_f), "stderr": str(stderr_f), "note": "dry-run"}

    # Make sure parent exists (should already)
    stdout_f.parent.mkdir(parents=True, exist_ok=True)

    with open(stdout_f, "wb") as so, open(stderr_f, "wb") as se:
        try:
            proc = subprocess.run(cmd, stdout=so, stderr=se, env=env, timeout=timeout)
            return {"rc": proc.returncode, "stdout": str(stdout_f), "stderr": str(stderr_f)}
        except subprocess.TimeoutExpired as te:
            se.write(f"TimeoutExpired: {te}\n".encode())
            return {"rc": -2, "stdout": str(stdout_f), "stderr": str(stderr_f)}
        except Exception as e:
            se.write(f"Exception: {e}\n".encode())
            return {"rc": -1, "stdout": str(stdout_f), "stderr": str(stderr_f)}

# ---------------------- Orchestrator ----------------------

def main():
    p = argparse.ArgumentParser(description="Web Recon Orchestrator - runs tools and stores outputs")
    p.add_argument("-t", "--target", required=True, help="Target domain or host (eg. sprinto.com)")
    p.add_argument("-o", "--outbase", default="results", help="Base output directory")
    p.add_argument("--no-subfinder", action="store_true", help="Skip subfinder")
    p.add_argument("--subfinder-active", action="store_true", help="Enable active mode in subfinder (-all)")
    p.add_argument("--subfinder-verbose", action="store_true", help="Verbose output for subfinder (-v)")
    p.add_argument("--no-dnsx", action="store_true", help="Skip dnsx")
    p.add_argument("--no-httpx", action="store_true", help="Skip httpx")
    p.add_argument("--no-nuclei", action="store_true", help="Skip nuclei")
    p.add_argument("--nuclei-timeout", type=int, default=10, help="Nuclei request timeout (default 10s)")
    p.add_argument("--nuclei-verbose", action="store_true", help="Verbose output for nuclei (-v)")
    p.add_argument("--no-nmap", action="store_true", help="Skip nmap")
    p.add_argument("--no-gobuster", action="store_true", help="Skip gobuster")
    p.add_argument("--no-gau", action="store_true", help="Skip gau/wayback")
    p.add_argument("--no-wpscan", action="store_true", help="Skip wpscan")
    p.add_argument("--zap", action="store_true", help="Run OWASP ZAP baseline (requires ZAP daemon or zap.sh)")
    p.add_argument("--wordlist", default=None, help="Wordlist path for gobuster (optional)")
    p.add_argument("--nmap-ports", default="-F", help="Nmap ports option (default -F quick scan)")
    p.add_argument("--threads", type=int, default=20, help="Default threads for httpx/gobuster")
    p.add_argument("--nuclei-templates", default=None, help="Path to nuclei-templates (if None uses default)")
    p.add_argument("--dry-run", action="store_true", help="Print commands but do not execute them")
    args = p.parse_args()

    target = args.target.strip()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.outbase) / f"{target.replace('/', '_')}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "target": target,
        "timestamp": ts,
        "commands": [],
        "results": {}
    }

    print(f"[+] Output directory: {outdir}")
    print("[NOTE] For full subfinder: Configure API keys in ~/.config/subfinder/config.yaml")
    print("[NOTE] Run 'nuclei -update-templates' for latest templates")

    def record(name: str, info: dict):
        manifest["results"][name] = info
        with open(outdir / "manifest.json", "w") as mf:
            json.dump(manifest, mf, indent=2)

    # ---------------- Subfinder ----------------
    if not args.no_subfinder:
        binpath = check_tool("subfinder")
        if binpath:
            print("[>] Running subfinder")
            sub_out = outdir / "subfinder.txt"
            cmd = [binpath, "-d", target, "-silent", "-o", str(sub_out)]
            if args.subfinder_active:
                cmd.append("-all")  # Active mode for better coverage
            if args.subfinder_verbose:
                cmd.append("-v")
            r = run_cmd(cmd, outdir, "subfinder", dry_run=args.dry_run, env=os.environ)
            r.update({"path": str(sub_out)})
            record("subfinder", r)
            log_file_size(sub_out, "subfinder.txt")
        else:
            print("[!] subfinder not found; skipping")

    # ---------------- gau / waybackurls ---------------- (unchanged)
    if not args.no_gau:
        gau_bin = check_tool("gau") or check_tool("waybackurls")
        if gau_bin:
            print("[>] Gathering archived URLs (gau/waybackurls)")
            urls_f = outdir / "archived_urls.txt"
            cmd = [gau_bin, target]
            r = run_cmd(cmd, outdir, "gau", dry_run=args.dry_run, env=os.environ)
            try:
                if Path(r["stdout"]).exists():
                    shutil.move(r["stdout"], urls_f)
                    r["path"] = str(urls_f)
            except Exception:
                pass
            record("gau", r)
            log_file_size(urls_f, "archived_urls.txt")
        else:
            print("[!] gau/waybackurls not found; skipping")

    # ---------------- DNSX (resolve) ----------------
    if not args.no_dnsx:
        binpath = check_tool("dnsx")
        if binpath:
            print("[>] Resolving names with dnsx")
            candidates = outdir / "candidates_for_dns.txt"
            subfile = outdir / "subfinder.txt"
            if subfile.exists() and subfile.stat().st_size > 0:
                shutil.copy(subfile, candidates)
            else:
                # Fallback: Root + common subs if subfinder empty
                fallback_subs = [target, f"www.{target}", f"admin.{target}", f"docs.{target}", f"api.{target}"]
                candidates.write_text("\n".join(fallback_subs) + "\n")
                print("[DEBUG] Subfinder empty; using fallback subs for dnsx")
            dnsx_out = outdir / "dnsx_resolved.txt"
            cmd = [binpath, "-l", str(candidates), "-a", "-silent", "-o", str(dnsx_out)]
            r = run_cmd(cmd, outdir, "dnsx", dry_run=args.dry_run, env=os.environ)
            r.update({"path": str(dnsx_out)})
            record("dnsx", r)
            log_file_size(dnsx_out, "dnsx_resolved.txt")
        else:
            print("[!] dnsx not found; skipping")

    # Create hosts_for_httpx.txt (first column of dnsx) or fallback to subfinder (unchanged)
    dnsx_file = outdir / "dnsx_resolved.txt"
    hosts_for_httpx = outdir / "hosts_for_httpx.txt"
    if dnsx_file.exists() and dnsx_file.stat().st_size > 0:
        with open(dnsx_file) as inf, open(hosts_for_httpx, "w") as outf:
            for line in inf:
                parts = line.strip().split()
                if parts:
                    outf.write(parts[0] + "\n")
        record("hosts_for_httpx", {"path": str(hosts_for_httpx)})
        log_file_size(hosts_for_httpx, "hosts_for_httpx.txt")
    else:
        sf = outdir / "subfinder.txt"
        if sf.exists() and sf.stat().st_size > 0:
            shutil.copy(sf, hosts_for_httpx)
            record("hosts_for_httpx", {"path": str(hosts_for_httpx)})
            log_file_size(hosts_for_httpx, "hosts_for_httpx.txt")
        else:
            print("[!] No hosts for httpx; chain broken")

    # ---------------- httpx (probe) ----------------
    if not args.no_httpx:
        binpath = check_tool("httpx")
        if binpath:
            print("[>] Probing hosts with httpx")
            input_list = hosts_for_httpx if hosts_for_httpx.exists() and hosts_for_httpx.stat().st_size > 0 else (outdir / "subfinder.txt")

            if not input_list.exists() or input_list.stat().st_size == 0:
                print("[!] httpx: no input hosts to probe; skipping httpx")
                record("httpx", {"rc": 0, "note": "skipped - no input hosts"})
            else:
                url_list = outdir / "httpx_input_urls.txt"
                with open(input_list) as inf, open(url_list, "w") as outf:
                    for line in inf:
                        host = line.strip().split()[0] if line.strip() else ""
                        if not host:
                            continue
                        if host.startswith("http://") or host.startswith("https://"):
                            outf.write(host + "\n")
                        else:
                            outf.write("https://" + host + "\n")
                            outf.write("http://" + host + "\n")

                httpx_out = outdir / "httpx_out.txt"
                httpx_cmd = [
                    binpath,
                    "-l", str(url_list),
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-threads", str(args.threads),
                    "-o", str(httpx_out)
                ]
                r = run_cmd(httpx_cmd, outdir, "httpx", dry_run=args.dry_run, timeout=1200, env=os.environ)  # Increased timeout
                r.update({"path": str(httpx_out), "input": str(url_list)})
                record("httpx", r)
                log_file_size(httpx_out, "httpx_out.txt")

                if not args.dry_run and httpx_out.exists() and httpx_out.stat().st_size == 0:
                    print("[!] httpx produced empty output — check httpx.err for details")
        else:
            print("[!] httpx not found; skipping")

    # ---------------- gau fetch and JS download (unchanged) ----------------
    # ... (omitted for brevity; same as original)

    # ---------------- nuclei ----------------
    if not args.no_nuclei:
        binpath = check_tool("nuclei")
        if binpath:
            print("[>] Running nuclei")
            live_hosts = outdir / "httpx_out.txt"
            if not live_hosts.exists() or live_hosts.stat().st_size == 0:
                print("[!] nuclei: no live hosts file found or file empty, skipping nuclei")
                record("nuclei", {"rc": 0, "note": "skipped - no live hosts"})
            else:
                help_out = subprocess.run([binpath, "-h"], capture_output=True, text=True)
                help_txt = (help_out.stdout or "") + "\n" + (help_out.stderr or "")

                if "-jle" in help_txt or "--jsonl-export" in help_txt:
                    nuclei_out = outdir / "nuclei.jsonl"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-jle", str(nuclei_out), "-rate", "150", "-timeout", str(args.nuclei_timeout)]
                elif "-je" in help_txt or "--json-export" in help_txt:
                    nuclei_out = outdir / "nuclei.json"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-je", str(nuclei_out), "-rate", "150", "-timeout", str(args.nuclei_timeout)]
                elif "-jsonl" in help_txt:
                    nuclei_out = outdir / "nuclei.jsonl"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-jsonl", "-o", str(nuclei_out), "-rate", "150", "-timeout", str(args.nuclei_timeout)]
                else:
                    nuclei_out = outdir / "nuclei.txt"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-o", str(nuclei_out), "-rate", "150", "-timeout", str(args.nuclei_timeout)]

                if args.nuclei_verbose:
                    nuclei_args.append("-v")
                if args.nuclei_templates:
                    nuclei_args.extend(["-t", args.nuclei_templates])

                r = run_cmd(nuclei_args, outdir, "nuclei", timeout=1800, dry_run=args.dry_run, env=os.environ)
                r.update({"path": str(nuclei_out)})
                record("nuclei", r)
                log_file_size(nuclei_out, "nuclei output")
        else:
            print("[!] nuclei not found; skipping")

    # ---------------- nmap / gobuster / wpscan / ZAP ---------------- (unchanged from original)
    # ... (omitted; they run on target root, so independent of chain)

    # ---------------- Post processing ---------------- (unchanged)
    # ... (omitted)

    # Final manifest write
    with open(outdir / "manifest.json", "w") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"[+] Run complete. Results directory: {outdir}")
    print("[!] Treat any found tokens or sensitive files in the results folder as confidential.")

if __name__ == '__main__':
    main()
