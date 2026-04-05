#!/usr/bin/env python3
import argparse
import asyncio
import re
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import httpx
except ImportError:
    print("[!] httpx not found. Install: pip install httpx")
    sys.exit(1)

# ──────────────────────────────────────────────
# FINGERPRINTS
# ──────────────────────────────────────────────
FINGERPRINTS = {
    'aws-s3'        : r"NoSuchBucket|The specified bucket does not exist",
    'github'        : r"There isn't a GitHub Pages site here",
    'gitlab'        : r"Project could not be found",
    'bitbucket'     : r"Repository not found",
    'netlify'       : r"Not Found - Request ID",
    'heroku'        : r"No such app",
    'vercel'        : r"The deployment could not be found",
    'firebase'      : r"Hosting.*Not Found",
    'azure'         : r"404 Web Site not found",
    'render'        : r"Not Found",
    'surge'         : r"project not found",
    'shopify'       : r"Sorry, this shop is currently unavailable",
    'wordpress'     : r"Do you want to register",
    'wix'           : r"Looks Like This Domain Isn't Connected",
    'squarespace'   : r"No such application could be found",
    'webflow'       : r"The page you were looking for doesn't exist",
    'fastly'        : r"Fastly error: unknown domain",
    'zendesk'       : r"Help Center Closed",
    'freshdesk'     : r"Page Not Found",
    'readthedocs'   : r"404 - Page Not Found",
    'ngrok'         : r"Tunnel.*not found",
    'ghost'         : r"The thing you were looking for is no longer here",
    'tumblr'        : r"Whatever you were looking for doesn't currently exist",
    'supabase'      : r"Project not found",
    'fly'           : r"404 not found",
    'launchrock'    : r"This site is no longer available",
    'strikingly'    : r"Page not found",
    'discord'       : r"Invalid invite",
    'slack'         : r"Workspace not found",
    'pantheon'      : r"The gods are wise|404 error unknown site",
    'kinsta'        : r"No Site For Domain",
    'acquia'        : r"The site you are looking for could not be found",
    'cloudfront'    : r"The request could not be satisfied|ERROR: The request could not be satisfied",
    'hubspot'       : r"Domain not found|This page isn't available",
    'intercom'      : r"This page is reserved for artistic inspiration",
    'helpscout'     : r"No settings were found for this company",
    'campaignmonitor': r"Double check the URL|Trying to access your account",
    'mailchimp'     : r"Mailchimp - 404",
    'uservoice'     : r"This UserVoice subdomain is currently available",
    'tilda'         : r"Please renew your subscription",
    'agilecrm'      : r"Sorry, this page is no longer available",
    'pingdom'       : r"This public report page has been removed",
    'statuspage'    : r"You are being redirected|Page Not Found",
    'readme'        : r"Project doesnt exist|Uh oh. That page doesn't exist",
    'gitbook'       : r"Space Not Found|We can't find that space",
    'cargo'         : r"Cargo Collective|404",
    'feedpress'     : r"The feed has not been found",
    'smartjobboard' : r"This job board website is either expired",
    'cargocollective': r"If you're the site owner",
    'jazzhr'        : r"Applicant Tracking System",
    'teamwork'      : r"Teamwork - Account not found",
    'proposify'     : r"The account you are trying to reach doesn't exist",
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

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ____        _  _____     _                             
 / ___| _   _| ||_   _|_ _| | _____  _____   ___ _ __  
 \___ \| | | | '_ \| |/ _` | |/ / _ \/ _ \ / _ \ '__| 
  ___) | |_| | |_) | | (_| |   <  __/ (_) |  __/ |    
 |____/ \__,_|_.__/|_|\__,_|_|\_\___|\___/ \___|_|    
{C.RESET}{C.DIM}  Subdomain Takeover Detection Tool{C.RESET}
""")

# ──────────────────────────────────────────────
# DNS CHECK
# ──────────────────────────────────────────────
def get_cname(subdomain: str) -> str | None:
    """Ambil CNAME record via dig"""
    try:
        result = subprocess.run(
            ["dig", "CNAME", subdomain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        cname = result.stdout.strip()
        return cname if cname else None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None

def is_nxdomain(domain: str) -> bool:
    """Cek apakah domain resolve ke NXDOMAIN"""
    try:
        result = subprocess.run(
            ["dig", domain, "+short"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        # Kalau kosong = NXDOMAIN / tidak resolve
        return output == ""
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

# ──────────────────────────────────────────────
# HTTP PROBE
# ──────────────────────────────────────────────
def http_probe(subdomain: str, timeout: int = 10) -> tuple[int | None, str]:
    """Probe HTTP/HTTPS, return (status_code, body)"""
    for scheme in ["https", "http"]:
        try:
            with httpx.Client(
                verify=False,
                follow_redirects=True,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0 SubTakeover/1.0"}
            ) as client:
                r = client.get(f"{scheme}://{subdomain}")
                return r.status_code, r.text
        except Exception:
            continue
    return None, ""

def match_fingerprint(body: str) -> str | None:
    """Match body ke fingerprint, return service name atau None"""
    for service, pattern in FINGERPRINTS.items():
        if re.search(pattern, body, re.IGNORECASE):
            return service
    return None

# ──────────────────────────────────────────────
# CORE CHECKER
# ──────────────────────────────────────────────
def check_subdomain(subdomain: str, timeout: int = 10) -> dict:
    subdomain = subdomain.strip().lower()
    result = {
        "subdomain" : subdomain,
        "cname"     : None,
        "nxdomain"  : False,
        "status"    : None,
        "service"   : None,
        "vulnerable": False,
        "note"      : ""
    }

    # Step 1: CNAME
    cname = get_cname(subdomain)
    result["cname"] = cname

    # Step 2: Cek apakah CNAME target NXDOMAIN
    if cname:
        cname_clean = cname.rstrip(".")
        if is_nxdomain(cname_clean):
            result["nxdomain"] = True

    # Step 3: HTTP probe + fingerprint match
    status, body = http_probe(subdomain, timeout)
    result["status"] = status

    if body:
        service = match_fingerprint(body)
        if service:
            result["service"]  = service
            result["vulnerable"] = True
            result["note"] = f"Fingerprint matched: {service}"

    # Kalau NXDOMAIN tapi gak ada fingerprint, tetap flag sebagai suspect
    if result["nxdomain"] and not result["vulnerable"]:
        result["note"] = "CNAME pointing to NXDOMAIN (unconfirmed, manual check needed)"

    return result

# ──────────────────────────────────────────────
# OUTPUT
# ──────────────────────────────────────────────
def print_result(r: dict):
    sub     = r["subdomain"]
    cname   = r["cname"] or "-"
    status  = r["status"] or "-"
    service = r["service"] or "-"
    note    = r["note"]

    if r["vulnerable"]:
        tag = f"{C.RED}{C.BOLD}[VULN]{C.RESET}"
    elif r["nxdomain"]:
        tag = f"{C.YELLOW}[SUSPECT]{C.RESET}"
    else:
        tag = f"{C.DIM}[SAFE]{C.RESET}"

    print(f"{tag} {C.BOLD}{sub}{C.RESET}")
    print(f"      CNAME  : {C.CYAN}{cname}{C.RESET}")
    print(f"      Status : {status}")
    if r["vulnerable"] or r["nxdomain"]:
        print(f"      Service: {C.GREEN}{service}{C.RESET}")
        print(f"      Note   : {note}")
    print()

def save_results(results: list[dict], outfile: str):
    vuln    = [r for r in results if r["vulnerable"]]
    suspect = [r for r in results if r["nxdomain"] and not r["vulnerable"]]

    with open(outfile, "w") as f:
        f.write(f"SubTakeover Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"[VULNERABLE] ({len(vuln)} found)\n")
        for r in vuln:
            f.write(f"  {r['subdomain']} -> {r['cname']} [{r['service']}]\n")

        f.write(f"\n[SUSPECT - Manual Check] ({len(suspect)} found)\n")
        for r in suspect:
            f.write(f"  {r['subdomain']} -> {r['cname']}\n")

        f.write(f"\n[ALL RESULTS]\n")
        for r in results:
            f.write(f"  {r['subdomain']} | CNAME: {r['cname']} | Status: {r['status']} | Service: {r['service']} | Note: {r['note']}\n")

    print(f"{C.GREEN}[+] Report saved to: {outfile}{C.RESET}")

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
def main():
    banner()

    parser = argparse.ArgumentParser(description="Subdomain Takeover Detection Tool")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--domain", help="Single subdomain to check")
    group.add_argument("-l", "--list",   help="File containing list of subdomains")
    parser.add_argument("-o", "--output",   help="Save report to file", default=None)
    parser.add_argument("-t", "--threads",  help="Number of threads (default: 10)", type=int, default=10)
    parser.add_argument("--timeout",        help="HTTP timeout in seconds (default: 10)", type=int, default=10)
    args = parser.parse_args()

    # Kumpulkan target
    targets = []
    if args.domain:
        targets = [args.domain]
    elif args.list:
        try:
            with open(args.list) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"{C.RED}[!] File not found: {args.list}{C.RESET}")
            sys.exit(1)

    print(f"{C.CYAN}[*] Targets   : {len(targets)}{C.RESET}")
    print(f"{C.CYAN}[*] Threads   : {args.threads}{C.RESET}")
    print(f"{C.CYAN}[*] Timeout   : {args.timeout}s{C.RESET}")
    print(f"{C.CYAN}[*] Services  : {len(FINGERPRINTS)} fingerprints loaded{C.RESET}")
    print()

    results = []
    vuln_count    = 0
    suspect_count = 0

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(check_subdomain, t, args.timeout): t for t in targets}
            for i, future in enumerate(as_completed(futures), 1):
                r = future.result()
                results.append(r)
                print_result(r)
                if r["vulnerable"]:
                    vuln_count += 1
                elif r["nxdomain"]:
                    suspect_count += 1

                # Progress
                sys.stdout.write(f"\r{C.DIM}Progress: {i}/{len(targets)}{C.RESET}  ")
                sys.stdout.flush()

    except KeyboardInterrupt:
        print(f"\n\n{C.YELLOW}[!] Scan dihentikan oleh user (Ctrl+C){C.RESET}")
        print(f"{C.DIM}    Menampilkan hasil yang sudah terkumpul...{C.RESET}\n")

    print(f"\n\n{'='*50}")
    print(f"{C.BOLD}Summary{C.RESET}")
    print(f"  Total scanned : {len(results)}")
    print(f"  {C.RED}{C.BOLD}Vulnerable    : {vuln_count}{C.RESET}")
    print(f"  {C.YELLOW}Suspect       : {suspect_count}{C.RESET}")
    print(f"  Safe          : {len(results) - vuln_count - suspect_count}")
    print()

    if args.output:
        save_results(results, args.output)

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()
    main()
