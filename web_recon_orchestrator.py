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

    def record(name: str, info: dict):
        manifest["results"][name] = info
        with open(outdir / "manifest.json", "w") as mf:
            json.dump(manifest, mf, indent=2)

    # ---------------- Subfinder ----------------
    if not args.no_subfinder:
        binpath = check_tool("subfinder")
        if binpath:
            print("[>] Running subfinder (passive)")
            sub_out = outdir / "subfinder.txt"
            cmd = [binpath, "-d", target, "-silent", "-o", str(sub_out)]
            r = run_cmd(cmd, outdir, "subfinder", dry_run=args.dry_run, env=os.environ)
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
            r = run_cmd(cmd, outdir, "gau", dry_run=args.dry_run, env=os.environ)
            try:
                # move produced stdout to urls_f (run_cmd wrote to gau.out)
                if Path(r["stdout"]).exists():
                    shutil.move(r["stdout"], urls_f)
                    r["path"] = str(urls_f)
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
            subfile = outdir / "subfinder.txt"
            if subfile.exists() and subfile.stat().st_size > 0:
                shutil.copy(subfile, candidates)
            else:
                candidates.write_text(target + "\n")
            dnsx_out = outdir / "dnsx_resolved.txt"
            cmd = [binpath, "-l", str(candidates), "-a", "-silent", "-o", str(dnsx_out)]
            r = run_cmd(cmd, outdir, "dnsx", dry_run=args.dry_run, env=os.environ)
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
    else:
        sf = outdir / "subfinder.txt"
        if sf.exists() and sf.stat().st_size > 0:
            shutil.copy(sf, hosts_for_httpx)
            record("hosts_for_httpx", {"path": str(hosts_for_httpx)})

    # ---------------- httpx (probe) ----------------
    if not args.no_httpx:
        binpath = check_tool("httpx")
        if binpath:
            print("[>] Probing hosts with httpx")

            # prefer pre-generated hosts list
            input_list = hosts_for_httpx if hosts_for_httpx.exists() and hosts_for_httpx.stat().st_size > 0 else (outdir / "subfinder.txt")

            if not input_list.exists() or input_list.stat().st_size == 0:
                print("[!] httpx: no input hosts to probe; skipping httpx")
                record("httpx", {"rc": 0, "note": "skipped - no input hosts"})
            else:
                # create a URL list that contains both http and https versions (helps discovery)
                url_list = outdir / "httpx_input_urls.txt"
                with open(input_list) as inf, open(url_list, "w") as outf:
                    for line in inf:
                        host = line.strip().split()[0] if line.strip() else ""
                        if not host:
                            continue
                        # skip if it already looks like a URL
                        if host.startswith("http://") or host.startswith("https://"):
                            outf.write(host + "\n")
                        else:
                            outf.write("https://" + host + "\n")
                            outf.write("http://" + host + "\n")

                # run httpx using the URL list; set env to inherit current PATH/venv
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
                # set a safe timeout; httpx handles many hosts, but we bound overall runtime
                r = run_cmd(httpx_cmd, outdir, "httpx", dry_run=args.dry_run, timeout=900, env=os.environ)
                r.update({"path": str(httpx_out), "input": str(url_list)})
                record("httpx", r)

                # if output is empty, save a small debug snapshot of stderr
                if not args.dry_run and httpx_out.exists() and httpx_out.stat().st_size == 0:
                    print("[!] httpx produced empty output — check httpx.err for details")
                    debug_err = outdir / "httpx_debug.err"
                    try:
                        with open(outdir / "httpx.err") as e_in, open(debug_err, "w") as e_out:
                            for i, l in enumerate(e_in):
                                if i >= 200:
                                    break
                                e_out.write(l)
                        record("httpx_debug", {"path": str(debug_err)})
                    except Exception:
                        pass
        else:
            print("[!] httpx not found; skipping")

    # ---------------- gau fetch and JS download (safe GETs, limited) ----------------
    archived = outdir / "archived_urls.txt"
    fetched_dir = outdir / "fetched"
    fetched_dir.mkdir(parents=True, exist_ok=True)
    if archived.exists() and archived.stat().st_size > 0:
        print("[>] Fetching archived URLs (safe GETs)")
        with open(archived) as fh:
            for i, line in enumerate(fh):
                if i >= 500:
                    break
                url = line.strip()
                if not url:
                    continue
                safe_name = f"url_{i}.html"
                outf = fetched_dir / safe_name
                try:
                    if args.dry_run:
                        print("[DRY-RUN] curl -sL", url)
                    else:
                        subprocess.run(["curl", "-sL", url, "-o", str(outf)], check=False, timeout=30)
                except Exception:
                    continue
        record("fetched_archives", {"path": str(fetched_dir)})

    # ---------------- nuclei (auto-detect output flag) ----------------
    if not args.no_nuclei:
        binpath = check_tool("nuclei")
        if binpath:
            print("[>] Running nuclei (conservative)")
            live_hosts = outdir / "httpx_out.txt"
            if not live_hosts.exists() or live_hosts.stat().st_size == 0:
                print("[!] nuclei: no live hosts file found or file empty, skipping nuclei")
                record("nuclei", {"rc": 0, "note": "skipped - no live hosts"})
            else:
                help_out = subprocess.run([binpath, "-h"], capture_output=True, text=True)
                help_txt = (help_out.stdout or "") + "\n" + (help_out.stderr or "")

                if "-jle" in help_txt or "--jsonl-export" in help_txt:
                    nuclei_out = outdir / "nuclei.jsonl"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-jle", str(nuclei_out), "-rate", "150"]
                elif "-je" in help_txt or "--json-export" in help_txt:
                    nuclei_out = outdir / "nuclei.json"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-je", str(nuclei_out), "-rate", "150"]
                elif "-jsonl" in help_txt:
                    nuclei_out = outdir / "nuclei.jsonl"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-jsonl", "-o", str(nuclei_out), "-rate", "150"]
                else:
                    nuclei_out = outdir / "nuclei.txt"
                    nuclei_args = [binpath, "-l", str(live_hosts), "-o", str(nuclei_out), "-rate", "150"]

                if args.nuclei_templates:
                    nuclei_args.extend(["-t", args.nuclei_templates])

                r = run_cmd(nuclei_args, outdir, "nuclei", timeout=1800, dry_run=args.dry_run, env=os.environ)
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
            nmap_base = [binpath, "-iL", str(hosts_in), "-Pn", "-sV", "-oX", str(nmap_out)]
            if args.nmap_ports:
                nmap_base.extend(args.nmap_ports.split())
            cmd = nmap_base
            r = run_cmd(cmd, outdir, "nmap", timeout=3600, dry_run=args.dry_run, env=os.environ)
            r.update({"path": str(nmap_out)})
            record("nmap", r)
        else:
            print("[!] nmap not found; skipping")

    # ---------------- gobuster (dir) ----------------
    if not args.no_gobuster:
        binpath = check_tool("gobuster")
        if binpath:
            print("[>] Running gobuster dir (conservative)")
            gob_out = outdir / "gobuster_dirs.txt"
            wordlist = args.wordlist or "/usr/share/wordlists/dirb/common.txt"
            cmd = [binpath, "dir", "-u", f"https://{target}", "-w", wordlist,
                   "-t", str(max(5, args.threads // 2)), "-o", str(gob_out), "-s", "200,204,301,302,307,401,403"]
            r = run_cmd(cmd, outdir, "gobuster", timeout=1800, dry_run=args.dry_run, env=os.environ)
            r.update({"path": str(gob_out)})
            record("gobuster", r)
        else:
            print("[!] gobuster not found; skipping")

    # ---------------- wpscan ----------------
    if not args.no_wpscan:
        binpath = check_tool("wpscan")
        if binpath:
            print("[>] Running wpscan (user enumeration only - safe)")
            wpscan_out = outdir / "wpscan_users.txt"
            cmd = [binpath, "--url", f"https://{target}", "--enumerate", "u", "--ignore-main-redirect"]
            r = run_cmd(cmd, outdir, "wpscan", timeout=600, dry_run=args.dry_run, env=os.environ)
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
            baseline_script = check_tool("zap-baseline.py")
            if baseline_script:
                cmd = [baseline_script, "-t", f"https://{target}", "-r", str(zap_out)]
                r = run_cmd(cmd, outdir, "zap_baseline", timeout=3600, dry_run=args.dry_run, env=os.environ)
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
