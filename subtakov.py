#!/usr/bin/env python3
import argparse
import re
import sys
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional

try:
    import httpx
except ImportError:
    print("[!] httpx not found. Install: pip install httpx")
    sys.exit(1)

# ──────────────────────────────────────────────
# FINGERPRINTS
# Setiap entry sekarang punya: regex pattern + expected status codes
# Fingerprint dianggap match HANYA kalau body match DAN status code cocok
# ──────────────────────────────────────────────
FINGERPRINTS: dict[str, dict[str, object]] = {
    'aws-s3':         {"pattern": r"NoSuchBucket|The specified bucket does not exist", "status": {404}},
    'github':         {"pattern": r"There isn't a GitHub Pages site here", "status": {404}},
    'gitlab':         {"pattern": r"Project could not be found", "status": {404}},
    'bitbucket':      {"pattern": r"Repository not found", "status": {404}},
    'netlify':        {"pattern": r"Not Found - Request ID", "status": {404}},
    'heroku':         {"pattern": r"No such app", "status": {404}},
    'vercel':         {"pattern": r"The deployment could not be found", "status": {404}},
    'firebase':       {"pattern": r"Hosting.*Not Found", "status": {404}},
    'azure':          {"pattern": r"404 Web Site not found", "status": {404}},
    'render':         {"pattern": r"Render\.com.*not found|is not available", "status": {404, 502}},
    'surge':          {"pattern": r"project not found", "status": {404}},
    'shopify':        {"pattern": r"Sorry, this shop is currently unavailable", "status": {404, 500}},
    'wordpress':      {"pattern": r"Do you want to register", "status": {404, 200}},
    'wix':            {"pattern": r"Looks Like This Domain Isn't Connected", "status": {404, 403}},
    'squarespace':    {"pattern": r"No such application could be found", "status": {404}},
    'webflow':        {"pattern": r"The page you were looking for doesn't exist", "status": {404}},
    'fastly':         {"pattern": r"Fastly error: unknown domain", "status": {500, 503}},
    'zendesk':        {"pattern": r"Help Center Closed", "status": {404, 403}},
    'freshdesk':      {"pattern": r"Freshdesk.*not found|is not configured", "status": {404, 403}},
    'readthedocs':    {"pattern": r"unknown to Read the Docs|is not a registered prefix", "status": {404}},
    'ngrok':          {"pattern": r"Tunnel.*not found", "status": {404}},
    'ghost':          {"pattern": r"The thing you were looking for is no longer here", "status": {404}},
    'tumblr':         {"pattern": r"Whatever you were looking for doesn't currently exist", "status": {404}},
    'supabase':       {"pattern": r"Project not found", "status": {404}},
    'fly':            {"pattern": r"fly\.io.*not found|this application has been deleted", "status": {404}},
    'launchrock':     {"pattern": r"This site is no longer available", "status": {404}},
    'strikingly':     {"pattern": r"strikingly\.com.*page not found|Build a website in minutes", "status": {404}},
    'discord':        {"pattern": r"Invalid invite", "status": {404}},
    'slack':          {"pattern": r"Workspace not found", "status": {404}},
    'pantheon':       {"pattern": r"The gods are wise|404 error unknown site", "status": {404}},
    'kinsta':         {"pattern": r"No Site For Domain", "status": {404}},
    'acquia':         {"pattern": r"The site you are looking for could not be found", "status": {404}},
    'cloudfront':     {"pattern": r"ERROR: The request could not be satisfied", "status": {403, 502}},
    'hubspot':        {"pattern": r"Domain not found|This page isn't available", "status": {404}},
    'intercom':       {"pattern": r"This page is reserved for artistic inspiration", "status": {404}},
    'helpscout':      {"pattern": r"No settings were found for this company", "status": {404}},
    'campaignmonitor': {"pattern": r"Double check the URL|Trying to access your account", "status": {404}},
    'mailchimp':      {"pattern": r"Mailchimp - 404", "status": {404}},
    'uservoice':      {"pattern": r"This UserVoice subdomain is currently available", "status": {404, 200}},
    'tilda':          {"pattern": r"Please renew your subscription", "status": {404, 200}},
    'agilecrm':       {"pattern": r"Sorry, this page is no longer available", "status": {404}},
    'pingdom':        {"pattern": r"This public report page has been removed", "status": {404}},
    'statuspage':     {"pattern": r"StatusPage.*not found|status page is no longer active", "status": {404, 302}},
    'readme':         {"pattern": r"Project doesnt exist|Uh oh. That page doesn't exist", "status": {404}},
    'gitbook':        {"pattern": r"Space Not Found|We can't find that space", "status": {404}},
    'cargo':          {"pattern": r"Cargo Collective.*404|If you're the owner", "status": {404}},
    'feedpress':      {"pattern": r"The feed has not been found", "status": {404}},
    'smartjobboard':  {"pattern": r"This job board website is either expired", "status": {404}},
    'cargocollective': {"pattern": r"If you're the site owner", "status": {404}},
    'jazzhr':         {"pattern": r"Applicant Tracking System", "status": {404}},
    'teamwork':       {"pattern": r"Teamwork - Account not found", "status": {404}},
    'proposify':      {"pattern": r"The account you are trying to reach doesn't exist", "status": {404}},
}

# ──────────────────────────────────────────────
# COLORS
# ──────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

def banner() -> None:
    print(f"""{C.CYAN}{C.BOLD}
  ____        _  _____     _                             
 / ___| _   _| ||_   _|_ _| | _____  _____   ___ _ __  
 \\___ \\| | | | '_ \\| |/ _` | |/ / _ \\/ _ \\ / _ \\ '__| 
  ___) | |_| | |_) | | (_| |   <  __/ (_) |  __/ |    
 |____/ \\__,_|_.__/|_|\\__,_|_|\\_\\___|\\___/ \\___|_|    
{C.RESET}{C.DIM}  Subdomain Takeover Detection Tool v2.0{C.RESET}
""")

# ──────────────────────────────────────────────
# DNS CHECK (with fallback and CNAME cache)
# ──────────────────────────────────────────────
_cname_cache: dict[str, Optional[str]] = {}

def _dig_cname(subdomain: str) -> Optional[str]:
    """Ambil CNAME record via dig."""
    try:
        result = subprocess.run(
            ["dig", "CNAME", subdomain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip()
        return cname if cname else None
    except subprocess.TimeoutExpired:
        print(f"  {C.DIM}[dig] timeout for {subdomain}{C.RESET}")
        return None
    except FileNotFoundError:
        return None  # dig not available, caller will try fallback

def _nslookup_cname(subdomain: str) -> Optional[str]:
    """Fallback: ambil CNAME via nslookup jika dig tidak tersedia."""
    try:
        result = subprocess.run(
            ["nslookup", "-type=CNAME", subdomain],
            capture_output=True, text=True, timeout=10
        )
        # Parse nslookup output for canonical name
        for line in result.stdout.splitlines():
            line_lower = line.strip().lower()
            if "canonical name" in line_lower:
                # Format: "subdomain canonical name = target.example.com"
                match = re.search(r"canonical name\s*=\s*(\S+)", line, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

def get_cname(subdomain: str) -> Optional[str]:
    """Ambil CNAME record dengan caching + fallback ke nslookup."""
    if subdomain in _cname_cache:
        return _cname_cache[subdomain]

    cname = _dig_cname(subdomain)

    # Fallback ke nslookup kalau dig gagal / not found
    if cname is None:
        cname = _nslookup_cname(subdomain)
        if cname is None:
            # Masih None? Bisa jadi memang gak ada CNAME, atau kedua tools gagal
            pass

    # Strip trailing dot (bikin mismatch kalau gak di-strip)
    if cname:
        cname = cname.rstrip(".")

    _cname_cache[subdomain] = cname
    return cname

def is_nxdomain(domain: str) -> bool:
    """Cek apakah domain resolve ke NXDOMAIN."""
    try:
        result = subprocess.run(
            ["dig", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        return output == ""
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        # Fallback nslookup
        try:
            result = subprocess.run(
                ["nslookup", domain],
                capture_output=True, text=True, timeout=10
            )
            # Kalau ada "can't find" atau "NXDOMAIN" di stderr/stdout -> NXDOMAIN
            combined = result.stdout + result.stderr
            if "can't find" in combined.lower() or "nxdomain" in combined.lower():
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            print(f"  {C.YELLOW}[!] Neither dig nor nslookup available. DNS checks will be unreliable.{C.RESET}")
            return False

# ──────────────────────────────────────────────
# HTTP PROBE (reusable client + retry)
# ──────────────────────────────────────────────
_http_client: Optional[httpx.Client] = None

def _get_http_client(timeout: int = 10) -> httpx.Client:
    """Get or create a reusable httpx.Client."""
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = httpx.Client(
            verify=False,
            follow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 SubTakeover/2.0"},
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    return _http_client

def http_probe(
    subdomain: str,
    timeout: int = 10,
    max_retries: int = 1,
    skip_http: bool = False,
) -> tuple[Optional[int], str, Optional[str]]:
    """
    Probe HTTP/HTTPS, return (status_code, body, error_type).
    error_type: None jika sukses, "timeout", "connection", "unknown" jika gagal.
    Retry 1x jika request gagal.
    """
    if skip_http:
        return None, "", None

    client = _get_http_client(timeout)
    last_error_type: Optional[str] = None

    for scheme in ["https", "http"]:
        url = f"{scheme}://{subdomain}"
        for attempt in range(1 + max_retries):
            try:
                r = client.get(url)
                return r.status_code, r.text, None
            except httpx.TimeoutException:
                last_error_type = "timeout"
            except httpx.ConnectError:
                last_error_type = "connection"
            except httpx.HTTPError:
                last_error_type = "http_error"
            except Exception:
                last_error_type = "unknown"

            # Kalau masih ada retry, tunggu sebentar
            if attempt < max_retries:
                time.sleep(0.5)

    return None, "", last_error_type

def match_fingerprint(body: str, status_code: Optional[int]) -> Optional[str]:
    """
    Match body + status code ke fingerprint.
    Return service name atau None.
    Status code harus cocok dengan expected status set.
    """
    if not body or status_code is None:
        return None

    for service, fp in FINGERPRINTS.items():
        pattern: str = fp["pattern"]   # type: ignore[assignment]
        expected_status: set[int] = fp["status"]   # type: ignore[assignment]

        # Body harus match pattern
        if not re.search(pattern, body, re.IGNORECASE):
            continue

        # Status code harus ada di expected set
        if status_code not in expected_status:
            continue

        return service

    return None

# ──────────────────────────────────────────────
# CORE CHECKER
# ──────────────────────────────────────────────
def check_subdomain(subdomain: str, timeout: int = 10) -> dict:
    subdomain = subdomain.strip().lower()
    result: dict[str, object] = {
        "subdomain" : subdomain,
        "cname"     : None,
        "nxdomain"  : False,
        "status"    : None,
        "service"   : None,
        "vulnerable": False,
        "note"      : "",
        "error"     : None,
    }

    # Step 1: CNAME (cached)
    cname = get_cname(subdomain)
    result["cname"] = cname

    # Step 2: Cek apakah CNAME target NXDOMAIN
    skip_http = False
    if cname:
        if is_nxdomain(cname):
            result["nxdomain"] = True
            # Kalau NXDOMAIN jelas, skip HTTP probe (optimisasi)
            skip_http = True

    # Step 3: HTTP probe + fingerprint match
    status, body, error_type = http_probe(subdomain, timeout, skip_http=skip_http)
    result["status"] = status
    result["error"] = error_type

    if body:
        service = match_fingerprint(body, status)
        if service:
            result["service"]    = service
            result["vulnerable"] = True
            result["note"]       = f"Fingerprint matched: {service} (HTTP {status})"

    # Kalau NXDOMAIN tapi gak ada fingerprint, tetap flag sebagai suspect
    if result["nxdomain"] and not result["vulnerable"]:
        result["note"] = "CNAME pointing to NXDOMAIN (unconfirmed, manual check needed)"

    # Tambah error info jika ada
    if error_type and not result["vulnerable"]:
        error_msgs = {
            "timeout":    "HTTP request timed out",
            "connection": "Connection refused / unreachable",
            "http_error": "HTTP protocol error",
            "unknown":    "Unknown error during HTTP probe",
        }
        error_note = error_msgs.get(error_type, error_type)
        if result["note"]:
            result["note"] += f" | {error_note}"
        else:
            result["note"] = error_note

    return result

# ──────────────────────────────────────────────
# OUTPUT
# ──────────────────────────────────────────────
def print_result(r: dict) -> None:
    sub     = r["subdomain"]
    cname   = r["cname"] or "-"
    status  = r["status"] or "-"
    service = r["service"] or "-"
    note    = r["note"]
    error   = r.get("error")

    if r["vulnerable"]:
        tag = f"{C.RED}{C.BOLD}[VULN]{C.RESET}"
    elif r["nxdomain"]:
        tag = f"{C.YELLOW}[SUSPECT]{C.RESET}"
    elif error:
        tag = f"{C.DIM}[ERROR]{C.RESET}"
    else:
        tag = f"{C.DIM}[SAFE]{C.RESET}"

    print(f"  {tag} {C.BOLD}{sub}{C.RESET}")
    print(f"        CNAME  : {C.CYAN}{cname}{C.RESET}")
    print(f"        Status : {status}")
    if r["vulnerable"] or r["nxdomain"] or error:
        if r["vulnerable"]:
            print(f"        Service: {C.GREEN}{service}{C.RESET}")
        if note:
            print(f"        Note   : {note}")
    print()

def save_results(results: list[dict], outfile: str, elapsed: float) -> None:
    vuln    = [r for r in results if r["vulnerable"]]
    suspect = [r for r in results if r["nxdomain"] and not r["vulnerable"]]
    errors  = [r for r in results if r.get("error") and not r["vulnerable"]]

    with open(outfile, "w") as f:
        f.write(f"SubTakeover Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan Duration: {elapsed:.1f}s\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"[VULNERABLE] ({len(vuln)} found)\n")
        for r in vuln:
            f.write(f"  {r['subdomain']} -> {r['cname']} [{r['service']}] (HTTP {r['status']})\n")

        f.write(f"\n[SUSPECT - Manual Check] ({len(suspect)} found)\n")
        for r in suspect:
            f.write(f"  {r['subdomain']} -> {r['cname']}\n")

        if errors:
            f.write(f"\n[ERRORS] ({len(errors)} found)\n")
            for r in errors:
                f.write(f"  {r['subdomain']} -> {r.get('error', 'unknown')}\n")

        f.write(f"\n[ALL RESULTS]\n")
        for r in results:
            f.write(f"  {r['subdomain']} | CNAME: {r['cname']} | Status: {r['status']} | Service: {r['service']} | Note: {r['note']}\n")

    print(f"  {C.GREEN}[+] Report saved to: {outfile}{C.RESET}")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main() -> None:
    banner()

    parser = argparse.ArgumentParser(description="Subdomain Takeover Detection Tool")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain",  help="Single subdomain to check")
    group.add_argument("-l", "--list",    help="File containing list of subdomains")
    parser.add_argument("-o", "--output",   help="Save report to file", default=None)
    parser.add_argument("-t", "--threads",  help="Number of threads (default: 10)", type=int, default=10)
    parser.add_argument("--timeout",        help="HTTP timeout in seconds (default: 10)", type=int, default=10)
    args = parser.parse_args()

    # Kumpulkan target
    targets: list[str] = []
    if args.domain:
        targets = [args.domain]
    elif args.list:
        try:
            with open(args.list) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"  {C.RED}[!] File not found: {args.list}{C.RESET}")
            sys.exit(1)

    if not targets:
        print(f"  {C.RED}[!] No targets provided.{C.RESET}")
        sys.exit(1)

    print(f"  {C.CYAN}[*] Targets      : {len(targets)}{C.RESET}")
    print(f"  {C.CYAN}[*] Threads      : {args.threads}{C.RESET}")
    print(f"  {C.CYAN}[*] Timeout      : {args.timeout}s{C.RESET}")
    print(f"  {C.CYAN}[*] Fingerprints : {len(FINGERPRINTS)} loaded{C.RESET}")
    print()

    results: list[dict] = []
    vuln_count     = 0
    suspect_count  = 0
    error_count    = 0
    start_time     = time.time()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_subdomain, t, args.timeout): t for t in targets}
            for i, future in enumerate(as_completed(futures), 1):
                try:
                    r = future.result()
                except Exception as exc:
                    target = futures[future]
                    r = {
                        "subdomain": target, "cname": None, "nxdomain": False,
                        "status": None, "service": None, "vulnerable": False,
                        "note": f"Unhandled exception: {exc}", "error": "exception",
                    }
                results.append(r)
                print_result(r)
                if r["vulnerable"]:
                    vuln_count += 1
                elif r["nxdomain"]:
                    suspect_count += 1
                if r.get("error"):
                    error_count += 1

                # Progress
                sys.stdout.write(f"\r  {C.DIM}Progress: {i}/{len(targets)}{C.RESET}  ")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}[!] Scan dihentikan oleh user (Ctrl+C){C.RESET}")
        print(f"  {C.DIM}    Menampilkan hasil yang sudah terkumpul...{C.RESET}\n")

    elapsed = time.time() - start_time
    safe_count = len(results) - vuln_count - suspect_count

    # ── Summary ──
    print(f"\n\n  {'─'*50}")
    print(f"  {C.BOLD}SCAN COMPLETE{C.RESET}")
    print(f"  {'─'*50}")
    print(f"   Total scanned : {len(results)}/{len(targets)}")
    print(f"   {C.RED}{C.BOLD}Vulnerable    : {vuln_count}{C.RESET}")
    print(f"   {C.YELLOW}Suspect       : {suspect_count}{C.RESET}")
    print(f"   Safe          : {safe_count}")
    if error_count:
        print(f"   {C.DIM}Errors        : {error_count}{C.RESET}")
    print(f"   Duration      : {elapsed:.1f}s")
    print(f"  {'─'*50}")
    print()

    if args.output:
        save_results(results, args.output, elapsed)

    # Cleanup client
    global _http_client
    if _http_client and not _http_client.is_closed:
        _http_client.close()

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
