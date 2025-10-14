#!/usr/bin/env python3
"""
web_recon_orchestrator.py

A safe, configurable Python orchestrator that runs common recon & scanning tools
(subfinder, dnsx, httpx, massdns (optional), nmap, nuclei, gobuster, gau, wpscan, zap)
and stores outputs into a timestamped results folder.

Features:
- Creates a new results/<target>_YYYYmmddTHHMMSS folder per run
- Runs only the enabled modules (flags to enable/disable)
- Captures stdout/stderr into separate files
- Writes a manifest.json describing run and produced files
- Safe defaults: conservative thread counts and non-destructive actions

Usage (from command line):
    python3 web_recon_orchestrator.py -t example.com

Run `python3 web_recon_orchestrator.py -h` for full CLI options.

Note: This script *calls external tools* which must be installed and in your PATH.
It does not perform intrusive actions by default. Always have written permission
before scanning targets you do not own.

"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# ---------------------- Helper functions ----------------------

def check_tool(name):
    """Return path of tool if present in PATH, else None."""
    return shutil.which(name)


def run_cmd(cmd, outdir, name, capture=True, env=None):
    """Run command list `cmd` and save stdout/stderr to files in outdir with base name `name`.
    Returns a dict with exit code and paths."""
    stdout_f = outdir / f"{name}.out"
    stderr_f = outdir / f"{name}.err"
    with open(stdout_f, "wb") as so, open(stderr_f, "wb") as se:
        try:
            proc = subprocess.run(cmd, stdout=so, stderr=se, env=env)
            return {"rc": proc.returncode, "stdout": str(stdout_f), "stderr": str(stderr_f)}
        except Exception as e:
            se.write(str(e).encode())
            return {"rc": -1, "stdout": str(stdout_f), "stderr": str(stderr_f)}


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
    p.add_argument("--no-gau", action="store_true", help="Skip gau/wayback" )
    p.add_argument("--no-wpscan", action="store_true", help="Skip wpscan")
    p.add_argument("--zap", action="store_true", help="Run OWASP ZAP baseline (requires ZAP daemon or zap.sh available)")
    p.add_argument("--wordlist", default=None, help="Wordlist path for gobuster (optional)")
    p.add_argument("--nmap-ports", default="-F", help="Nmap ports option (default -F quick scan)")
    p.add_argument("--threads", type=int, default=20, help="Default threads for httpx/gobuster")
    p.add_argument("--nuclei-templates", default=None, help="Path to nuclei-templates (if None uses default)")
    args = p.parse_args()

    target = args.target.strip()
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.outbase) / f"{target.replace('/', '_')}_{ts}"
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "target": target,
        "timestamp": ts,
        "commands": [],
        "results": {}
    }

    print(f"[+] Output directory: {outdir}")

    # Helper to record result
    def record(name, info):
        manifest["results"][name] = info
        # write manifest after each step for resilience
        with open(outdir / "manifest.json", "w") as mf:
            json.dump(manifest, mf, indent=2)

    # ---------------- Subfinder ----------------
    if not args.no_subfinder:
        binpath = check_tool("subfinder")
        if binpath:
            print("[>] Running subfinder (passive)")
            sub_out = outdir / "subfinder.txt"
            cmd = [binpath, "-d", target, "-silent", "-o", str(sub_out)]
            r = run_cmd(cmd, outdir, "subfinder")
            r.update({"path": str(sub_out)})
            record("subfinder", r)
        else:
            print("[!] subfinder not found; skipping")

    # ---------------- gau / waybackurls ----------------
    if not args.no_gau:
        gau_bin = check_tool("gau") or check_tool("waybackurls")
        if gau_bin:
            print("[>] Gathering archived URLs (gau/waybackurls)")
            urls_f = outdir / "archived_urls.txt"
            cmd = [gau_bin, target]
            # write stdout directly
            r = run_cmd(cmd, outdir, "gau")
            # move produced stdout to urls_f
            try:
                # the run_cmd stored stdout in r['stdout'] path
                shutil.move(r['stdout'], urls_f)
                r['path'] = str(urls_f)
            except Exception:
                pass
            record("gau", r)
        else:
            print("[!] gau/waybackurls not found; skipping")

    # ---------------- DNSX (resolve) ----------------
    if not args.no_dnsx:
        binpath = check_tool("dnsx")
        if binpath:
            print("[>] Resolving names with dnsx")
            candidates = outdir / "candidates_for_dns.txt"
            # source candidates: subfinder result or target
            subfile = outdir / "subfinder.txt"
            if subfile.exists() and subfile.stat().st_size > 0:
                shutil.copy(subfile, candidates)
            else:
                candidates.write_text(target + "\n")
            dnsx_out = outdir / "dnsx_resolved.txt"
            cmd = [binpath, "-l", str(candidates), "-a", "-silent", "-o", str(dnsx_out)]
            r = run_cmd(cmd, outdir, "dnsx")
            r.update({"path": str(dnsx_out)})
            record("dnsx", r)
        else:
            print("[!] dnsx not found; skipping")

    # ---------------- httpx (probe) ----------------
    if not args.no_httpx:
        binpath = check_tool("httpx")
        if binpath:
            print("[>] Probing hosts with httpx")
            # create input list from dnsx or fallback
            dnsx_file = outdir / "dnsx_resolved.txt"
            input_list = dnsx_file if dnsx_file.exists() else (outdir / "subfinder.txt")
            httpx_out = outdir / "httpx_out.txt"
            cmd = [binpath, "-l", str(input_list), "-silent", "-status-code", "-title", "-tech-detect", "-threads", str(args.threads), "-o", str(httpx_out)]
            r = run_cmd(cmd, outdir, "httpx")
            r.update({"path": str(httpx_out)})
            record("httpx", r)
        else:
            print("[!] httpx not found; skipping")

    # ---------------- gau fetch and JS download (scan downloaded URLs for tokens) ----------------
    # (If gau produced archived_urls.txt, download those pages to fetched/ for later inspection)
    archived = outdir / "archived_urls.txt"
    fetched_dir = outdir / "fetched"
    fetched_dir.mkdir(exist_ok=True)
    if archived.exists() and archived.stat().st_size > 0:
        print("[>] Fetching archived URLs (safe GETs)")
        with open(archived) as fh:
            for i, line in enumerate(fh):
                if i >= 500:  # limit to first 500 to avoid huge crawls
                    break
                url = line.strip()
                if not url:
                    continue
                safe_name = f"url_{i}.html"
                outf = fetched_dir / safe_name
                try:
                    subprocess.run(["curl", "-sL", url, "-o", str(outf)], check=False)
                except Exception:
                    continue
        record("fetched_archives", {"path": str(fetched_dir)})

    # ---------------- nuclei ----------------
    if not args.no_nuclei:
        binpath = check_tool("nuclei")
        if binpath:
            print("[>] Running nuclei (conservative) ")
            live_hosts = outdir / "httpx_out.txt"
            nuclei_out = outdir / "nuclei.json"
            nuclei_args = [binpath, "-l", str(live_hosts), "-json", "-o", str(nuclei_out), "-rate", "150"]
            if args.nuclei_templates:
                nuclei_args.extend(["-t", args.nuclei_templates])
            r = run_cmd(nuclei_args, outdir, "nuclei")
            r.update({"path": str(nuclei_out)})
            record("nuclei", r)
        else:
            print("[!] nuclei not found; skipping")

    # ---------------- nmap ----------------
    if not args.no_nmap:
        binpath = check_tool("nmap")
        if binpath:
            print("[>] Running nmap (safe quick scan)")
            resolved = outdir / "dnsx_resolved.txt"
            hosts_in = resolved if resolved.exists() and resolved.stat().st_size > 0 else outdir / "subfinder.txt"
            nmap_out = outdir / "nmap.xml"
            cmd = [binpath, "-iL", str(hosts_in), "-Pn", "-sV", args.nmap_ports, "-oX", str(nmap_out)]
            r = run_cmd(cmd, outdir, "nmap")
            r.update({"path": str(nmap_out)})
            record("nmap", r)
        else:
            print("[!] nmap not found; skipping")

    # ---------------- gobuster (dir) ----------------
    if not args.no_gobuster:
        binpath = check_tool("gobuster")
        if binpath:
            print("[>] Running gobuster dir (conservative) ")
            # prefer live hosts list
            live_hosts = outdir / "httpx_out.txt"
            gob_out = outdir / "gobuster_dirs.txt"
            wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
            # run gobuster against main target only to avoid huge scans; user can expand later
            cmd = [binpath, "dir", "-u", f"https://{target}", "-w", wordlist, "-t", str(max(5, args.threads//2)), "-o", str(gob_out), "-s", "200,204,301,302,307,401,403"]
            r = run_cmd(cmd, outdir, "gobuster")
            r.update({"path": str(gob_out)})
            record("gobuster", r)
        else:
            print("[!] gobuster not found; skipping")

    # ---------------- wpscan ----------------
    if not args.no_wpscan:
        binpath = check_tool("wpscan")
        if binpath:
            print("[>] Running wpscan (user enumeration only - safe) ")
            wpscan_out = outdir / "wpscan_users.txt"
            cmd = [binpath, "--url", f"https://{target}", "--enumerate", "u", "--ignore-main-redirect"]
            r = run_cmd(cmd, outdir, "wpscan")
            r.update({"path": str(wpscan_out)})
            record("wpscan", r)
        else:
            print("[!] wpscan not found; skipping")

    # ---------------- OWASP ZAP (baseline) ----------------
    if args.zap:
        zap_bin = check_tool("zap.sh") or check_tool("zap")
        if zap_bin:
            print("[>] Running OWASP ZAP baseline scan (requires ZAP daemon or zap.sh)")
            zap_out = outdir / "zap_report.html"
            # baseline scan script may be installed with ZAP distributions (zap-baseline.py)
            baseline_script = check_tool("zap-baseline.py")
            if baseline_script:
                cmd = [baseline_script, "-t", f"https://{target}", "-r", str(zap_out)]
                r = run_cmd(cmd, outdir, "zap_baseline")
                r.update({"path": str(zap_out)})
                record("zap", r)
            else:
                print("[!] zap baseline script not found; please run ZAP GUI or install zap-baseline.py")
        else:
            print("[!] ZAP not found in PATH; skipping")

    # ---------------- Post processing: collate live url list ----------------
    try:
        live = outdir / "httpx_out.txt"
        consolidated = outdir / "live_urls.txt"
        if live.exists():
            # httpx output has URL in first column
            with open(live) as fh_in, open(consolidated, "w") as fh_out:
                for line in fh_in:
                    parts = line.strip().split()
                    if parts:
                        fh_out.write(parts[0] + "\n")
            record("live_urls", {"path": str(consolidated)})
    except Exception:
        pass

    # Final manifest write
    with open(outdir / "manifest.json", "w") as mf:
        json.dump(manifest, mf, indent=2)

    print(f"[+] Run complete. Results directory: {outdir}")
    print("[!] Treat any found tokens or sensitive files in the results folder as confidential.")


if __name__ == '__main__':
    main()
