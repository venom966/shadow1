import requests
from urllib.parse import urljoin, urlparse
import subprocess
import datetime
import os
import sys

COMMON_PATHS = [
    "admin", "login", "phpmyadmin", "config",
    ".git", ".env", "robots.txt", "dashboard",
    "cpanel", "server-status", "sitemap.xml"
]

HEADERS_TO_CHECK = [
    "X-Frame-Options",
    "X-XSS-Protection",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "Server"
]

REPORT_FILE = "shadow_full_report.txt"
REQUEST_HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ShadowScanner/3.0)"}

def write_report(text):
    with open(REPORT_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n")

def banner():
    print(r'''
  __  _               _            
 / __|| |_   _ _ ___| | ____ _ __ 
 \___ \| '_ \ / _` / __| |/ / _ \ '__|
  _) | | | | (| \_ \   <  __/ |   
 |____/|_| |_|\__,_|___/_|\_\___|_|   
         SHADOW Full Web Scanner v3.0
    ''')

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/"):
        url += "/"
    return url

def check_common_paths(base_url):
    print("\n[🔎] Checking common paths...")
    write_report("\n[🔎] Checking common paths...")
    for path in COMMON_PATHS:
        url = urljoin(base_url, path)
        try:
            response = requests.get(url, headers=REQUEST_HEADERS, timeout=6)
            status = response.status_code
            if status == 200:
                msg = f"[⚠️] Found: {url} (Status: 200)"
                print(msg)
                write_report(msg)
                if path in ['robots.txt', 'sitemap.xml']:
                    # Save content
                    filename = path.replace('.', '_') + ".txt"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(response.text)
                    print(f"    -> Content saved to {filename}")
                    write_report(f"    -> Content saved to {filename}")
            elif status in [401, 403]:
                msg = f"[🔒] Protected: {url} (Status: {status})"
                print(msg)
                write_report(msg)
        except requests.RequestException as e:
            print(f"[!] Error accessing {url}: {e}")
            write_report(f"[!] Error accessing {url}: {e}")

def check_security_headers(base_url):
    print("\n[🧠] Checking security headers...")
    write_report("\n[🧠] Checking security headers...")
    try:
        response = requests.get(base_url, headers=REQUEST_HEADERS, timeout=6)
        for header in HEADERS_TO_CHECK:
            if header in response.headers:
                msg = f"[✅] {header} found: {response.headers[header]}"
                print(msg)
                write_report(msg)
            else:
                msg = f"[❌] {header} missing"
                print(msg)
                write_report(msg)
    except requests.RequestException as e:
        msg = f"[!] Could not connect to the site: {e}"
        print(msg)
        write_report(msg)

def run_nmap(target):
    print("\n[🛡️] Running nmap port scan...")
    write_report("\n[🛡️] Running nmap port scan...")
    try:
        parsed = urlparse(target)
        host = parsed.netloc if parsed.netloc else target
        result = subprocess.run(
            ["nmap", "-sV", "-Pn", host],
            capture_output=True, text=True, timeout=120, check=True
        )
        print(result.stdout)
        write_report(result.stdout)
    except subprocess.TimeoutExpired:
        msg = "[!] Nmap scan timed out."
        print(msg)
        write_report(msg)
    except subprocess.CalledProcessError as e:
        msg = f"[!] Error running nmap: {e}"
        print(msg)
        write_report(msg)
    except Exception as e:
        msg = f"[!] Unexpected error running nmap: {e}"
        print(msg)
        write_report(msg)

def run_nikto(target):
    print("\n[🕵️‍♂️] Running nikto web server scan...")
    write_report("\n[🕵️‍♂️] Running nikto web server scan...")
    try:
        result = subprocess.run(
            ["nikto", "-h", target],
            capture_output=True, text=True, timeout=300, check=True
        )
        print(result.stdout)
        write_report(result.stdout)
    except subprocess.TimeoutExpired:
        msg = "[!] Nikto scan timed out."
        print(msg)
        write_report(msg)
    except subprocess.CalledProcessError as e:
        msg = f"[!] Error running nikto: {e}"
        print(msg)
        write_report(msg)
    except Exception as e:
        msg = f"[!] Unexpected error running nikto: {e}"
        print(msg)
        write_report(msg)

def main():
    try:
        if os.path.exists(REPORT_FILE):
            os.remove(REPORT_FILE)

        banner()
        target = input("🌐 Enter website URL or IP (e.g. https://example.com or 192.168.1.1): ").strip()
        target = normalize_url(target)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        write_report(f"SHADOW Full Scan Report - Date & Time: {timestamp}")
        write_report(f"Target: {target}")

        check_common_paths(target)
        check_security_headers(target)

        run_nmap(target)
        run_nikto(target)

        print(f"\n[✔] Scan completed. Report saved to: {REPORT_FILE}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    main()
