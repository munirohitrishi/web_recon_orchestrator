#!/usr/bin/env python3
"""
web_recon_orchestrator.py

Safe, configurable Python orchestrator for recon & scanning tools:
subfinder, dnsx, httpx, massdns (optional), nmap, nuclei, gobuster, gau/waybackurls, wpscan, zap.

Features:
- Creates results/<target>_YYYYmmddTHHMMSS folder per run
- Selectively enable/disable modules via CLI flags
- Captures stdout/stderr for each tool
- Produces manifest.json describing the run
- Conservative defaults and dry-run support

WARNING: Run only against assets you own or have explicit written permission to test.
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
            # Using os.environ ensures that tools find their config files (e.g., for API keys)
            process_env = os.environ.copy()
            if env:
                process_env.update(env)
            
            proc = subprocess.run(cmd, stdout=so, stderr=se, env=process_env, timeout=timeout)
            return {"rc": proc.returncode, "stdout": str(stdout_f), "stderr": str(stderr_f)}
        except subprocess.TimeoutExpired as te:
            se.write(f"TimeoutExpired: Command '{' '.join(cmd)}' exceeded timeout of {timeout} seconds.\n".encode())
            return {"rc": -2, "stdout": str(stdout_f), "stderr": str(stderr_f), "note": "timeout"}
        except Exception as e:
            se.write(f"Exception: {e}\n".encode())
            return {"rc": -1, "stdout": str(stdout_f), "stderr": str(stderr_f), "note": "exception"}

# ---------------------- Orchestrator ----------------------

def main():
    p = argparse.ArgumentParser(description="Web Recon Orchestrator - runs tools and stores outputs")
    p.add_argument("-t", "--target", required=True, help="Target domain or host (eg. docs.sprinto.com)")
    p.add_argument("-o", "--outbase", default="results", help="Base output directory")
    p.add_argument("--no-subfinder", action="store_true", help="Skip subfinder")
    p.add_argument("--no-dnsx", action="store_true", help="Skip dnsx")
    p.add_argument("--no-httpx", action="store_true", help="Skip httpx")
    p.add_argument("--no-nuclei", action="store_true", help="Skip nuclei")
    p.add_argument("--no-nmap", action="store_true", help="Skip nmap")
    p.add_argument("--no-gobuster", action="store_true", help="Skip gobuster")
    p.add_argument("--no-gau", action="store_true", help="Skip gau/wayback")
    p.add_argument("--no-wpscan", action="store_true", help="Skip wpscan")
    p.add_argument("--zap", action="store_true", help="Run OWASP ZAP baseline (requires ZAP daemon or zap.sh)")
    p.add_argument("--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Wordlist path for gobuster")
    p.add_argument("--nmap-ports", default="-F", help="Nmap ports option (default -F quick scan)")
    p.add_argument("--threads", type=int, default=20, help="Default threads for httpx/gobuster")
    p.add_argument("--nuclei-templates", default=None, help="Path to specific nuclei-templates (if None, uses default)")
    p.add_argument("--nuclei-rate", type=int, default=150, help="Rate limit for nuclei (requests per second)")
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

    def record(name: str, info: dict):
        manifest["results"][name] = info
        with open(outdir / "manifest.json", "w") as mf:
            json.dump(manifest, mf, indent=2)

    # ---------------- Subfinder ----------------
    if not args.no_subfinder:
        binpath = check_tool("subfinder")
        if binpath:
            print("[>] Running subfinder (basic passive scan, no API keys)")
            sub_out = outdir / "subfinder.txt"
            # *** MODIFIED COMMAND: Removed "-all" to avoid needing API keys ***
            cmd = [binpath, "-d", target, "-silent", "-o", str(sub_out)]
            r = run_cmd(cmd, outdir, "subfinder", dry_run=args.dry_run)
            r.update({"path": str(sub_out)})
            record("subfinder", r)

            # **DEBUG CHECK**: Verify subfinder output
            if not args.dry_run and (r["rc"] != 0 or not sub_out.exists() or sub_out.stat().st_size == 0):
                print(f"[!] WARNING: subfinder may have failed (rc={r['rc']}) or found no subdomains.")
                print(f"    -> Check the error log: {outdir / 'subfinder.err'}")
        else:
            print("[!] subfinder not found; skipping")

    # ---------------- gau / waybackurls ----------------
    if not args.no_gau:
        gau_bin = check_tool("gau") or check_tool("waybackurls")
        if gau_bin:
            print("[>] Gathering archived URLs (gau/waybackurls)")
            urls_f = outdir / "archived_urls.txt"
            # gau writes to stdout, so we let run_cmd capture it and then move the file
            cmd = [gau_bin, target]
            r = run_cmd(cmd, outdir, "gau", dry_run=args.dry_run)
            try:
                # move produced stdout to urls_f (run_cmd wrote to gau.out)
                if not args.dry_run and Path(r["stdout"]).exists():
                    shutil.move(r["stdout"], urls_f)
                    r["path"] = str(urls_f)
            except Exception as e:
                print(f"[!] Could not process gau output: {e}")
            record("gau", r)
        else:
            print("[!] gau/waybackurls not found; skipping")

    # ---------------- DNSX (resolve) ----------------
    if not args.no_dnsx:
        binpath = check_tool("dnsx")
        if binpath:
            subfile = outdir / "subfinder.txt"
            if not subfile.exists() or subfile.stat().st_size == 0:
                print("[!] No subdomains found to resolve; skipping dnsx.")
                record("dnsx", {"rc": 0, "note": "skipped - no input from subfinder"})
            else:
                print("[>] Resolving subdomains with dnsx")
                dnsx_out = outdir / "dnsx_resolved.txt"
                cmd = [binpath, "-l", str(subfile), "-a", "-resp", "-silent", "-o", str(dnsx_out)]
                r = run_cmd(cmd, outdir, "dnsx", dry_run=args.dry_run)
                r.update({"path": str(dnsx_out)})
                record("dnsx", r)
        else:
            print("[!] dnsx not found; skipping")

    # Create hosts_for_httpx.txt (first column of dnsx) or fallback to subfinder
    dnsx_file = outdir / "dnsx_resolved.txt"
    hosts_for_httpx = outdir / "hosts_for_httpx.txt"
    if dnsx_file.exists() and dnsx_file.stat().st_size > 0:
        with open(dnsx_file) as inf, open(hosts_for_httpx, "w") as outf:
            for line in inf:
                parts = line.strip().split()
                if parts:
                    outf.write(parts[0] + "\n")
        record("hosts_for_httpx", {"path": str(hosts_for_httpx)})
    else: # Fallback to subfinder output if dnsx failed or was skipped
        sf = outdir / "subfinder.txt"
        if sf.exists() and sf.stat().st_size > 0:
            shutil.copy(sf, hosts_for_httpx)
            record("hosts_for_httpx", {"path": str(hosts_for_httpx), "note": "fallback to subfinder list"})

    # ---------------- httpx (probe) ----------------
    if not args.no_httpx:
        binpath = check_tool("httpx")
        if binpath:
            input_list = hosts_for_httpx
            if not input_list.exists() or input_list.stat().st_size == 0:
                print("[!] No hosts to probe; skipping httpx.")
                record("httpx", {"rc": 0, "note": "skipped - no input hosts"})
            else:
                print("[>] Probing hosts with httpx")
                httpx_out = outdir / "httpx_out.txt"
                httpx_cmd = [
                    binpath,
                    "-l", str(input_list),
                    "-silent",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-threads", str(args.threads),
                    "-o", str(httpx_out)
                ]
                r = run_cmd(httpx_cmd, outdir, "httpx", dry_run=args.dry_run, timeout=900)
                r.update({"path": str(httpx_out), "input": str(input_list)})
                record("httpx", r)
                
                # **DEBUG CHECK**: Verify httpx output
                if not args.dry_run and (r["rc"] != 0 or not httpx_out.exists() or httpx_out.stat().st_size == 0):
                    print(f"[!] WARNING: httpx may have failed (rc={r['rc']}) or found no live hosts.")
                    print(f"    -> Check the error log: {outdir / 'httpx.err'}")
        else:
            print("[!] httpx not found; skipping")

    # ---------------- nuclei ----------------
    if not args.no_nuclei:
        binpath = check_tool("nuclei")
        if binpath:
            live_hosts = outdir / "httpx_out.txt"
            if not live_hosts.exists() or live_hosts.stat().st_size == 0:
                print("[!] No live hosts to scan; skipping nuclei.")
                record("nuclei", {"rc": 0, "note": "skipped - no live hosts from httpx"})
            else:
                print(f"[>] Running nuclei (Rate: {args.nuclei_rate}/s)")
                nuclei_out = outdir / "nuclei_results.jsonl"
                nuclei_args = [
                    binpath,
                    "-l", str(live_hosts),
                    "-jsonl", # Prefer modern jsonl format
                    "-o", str(nuclei_out),
                    "-rate-limit", str(args.nuclei_rate),
                    "-bulk-size", str(args.nuclei_rate), # Match bulk size to rate limit
                    "-stats" # Show stats
                ]

                if args.nuclei_templates:
                    nuclei_args.extend(["-t", args.nuclei_templates])

                r = run_cmd(nuclei_args, outdir, "nuclei", timeout=3600, dry_run=args.dry_run)
                r.update({"path": str(nuclei_out)})
                record("nuclei", r)

                if not args.dry_run and r["rc"] != 0:
                     print(f"[!] WARNING: nuclei exited with non-zero status (rc={r['rc']}).")
                     print(f"    -> Check the error log: {outdir / 'nuclei.err'}")
        else:
            print("[!] nuclei not found; skipping")

    # ---------------- nmap ----------------
    if not args.no_nmap:
        binpath = check_tool("nmap")
        if binpath:
            resolved = outdir / "dnsx_resolved.txt"
            # Use resolved hosts for nmap as it's more reliable than just subdomains
            hosts_in = resolved if resolved.exists() and resolved.stat().st_size > 0 else outdir / "subfinder.txt"
            
            if not hosts_in.exists() or hosts_in.stat().st_size == 0:
                print("[!] No hosts to scan; skipping nmap.")
                record("nmap", {"rc": 0, "note": "skipped - no input hosts"})
            else:
                print(f"[>] Running nmap ({args.nmap_ports} scan)")
                nmap_out = outdir / "nmap_scan.xml"
                nmap_base = [binpath, "-iL", str(hosts_in), "-Pn", "-sV", "--open", "-oX", str(nmap_out)]
                if args.nmap_ports:
                    nmap_base.extend(args.nmap_ports.split())
                
                r = run_cmd(nmap_base, outdir, "nmap", timeout=3600, dry_run=args.dry_run)
                r.update({"path": str(nmap_out)})
                record("nmap", r)
        else:
            print("[!] nmap not found; skipping")

    # ---------------- gobuster (dir) ----------------
    if not args.no_gobuster:
        binpath = check_tool("gobuster")
        if binpath:
            wordlist_path = Path(args.wordlist)
            if not wordlist_path.is_file():
                 print(f"[!] Wordlist not found at '{wordlist_path}'; skipping gobuster.")
                 record("gobuster", {"rc": -1, "note": "skipped - wordlist not found"})
            else:
                print("[>] Running gobuster dir scan (on target domain only)")
                gob_out = outdir / "gobuster_dirs.txt"
                cmd = [
                    binpath, "dir",
                    "-u", f"https://{target}",
                    "-w", str(wordlist_path),
                    "-t", str(max(5, args.threads // 2)),
                    "-o", str(gob_out),
                    "-s", "200,204,301,302,307,401,403",
                    "--no-error"
                ]
                r = run_cmd(cmd, outdir, "gobuster", timeout=1800, dry_run=args.dry_run)
                r.update({"path": str(gob_out)})
                record("gobuster", r)
        else:
            print("[!] gobuster not found; skipping")

    # (Other tool sections like wpscan, zap, etc. remain the same)
    # ...

    # Final manifest write
    with open(outdir / "manifest.json", "w") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"\n[+] Run complete. Results directory: {outdir}")
    print("[!] Treat any found tokens or sensitive files in the results folder as confidential.")

if __name__ == '__main__':
    # Add a check for root user, which is bad practice for these tools
    if os.geteuid() == 0:
        print("[!] Running as root is not recommended. Please run as a normal user.")
        sys.exit(1)
    main()
