#!/usr/bin/env python3
"""
fingerprint.py
---------------
Mục đích: fingerprinting tech stack theo 2 lớp:
  1. Phân tích THỦ CÔNG header + cookie (để hiểu vì sao công cụ như
     Wappalyzer/WhatWeb kết luận như vậy — không chỉ tin mù kết quả tool).
  2. Gọi WhatWeb (nếu có cài) để đối chiếu, tự động hoá phần lặp lại.

Cài đặt:
  pip install requests
  # WhatWeb (Ruby, thường có sẵn trên Kali): whatweb --version

Dùng:
  python3 fingerprint.py https://target.example
  python3 fingerprint.py https://target.example --json report.json
"""

import argparse
import json
import re
import shutil
import subprocess
import sys

import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (recon-toolkit; authorized-testing)"}

# Header/cookie -> gợi ý công nghệ. Đây là phần "hiểu vì sao", không phải
# danh sách đầy đủ — nên mở rộng dần khi gặp target mới.
SIGNATURES = {
    "server": {
        r"nginx": "Nginx",
        r"apache": "Apache HTTPD",
        r"cloudflare": "Cloudflare (proxy/CDN)",
        r"microsoft-iis": "IIS",
        r"gunicorn": "Gunicorn (Python WSGI)",
        r"werkzeug": "Flask dev server (Werkzeug)",
    },
    "x-powered-by": {
        r"express": "Express.js (Node)",
        r"php": "PHP",
        r"asp\.net": "ASP.NET",
    },
    "set-cookie": {
        r"laravel_session": "Laravel (PHP)",
        r"phpsessid": "PHP",
        r"jsessionid": "Java (Servlet/Spring)",
        r"connect\.sid": "Express.js session",
        r"django": "Django (Python)",
        r"csrftoken": "Django CSRF cookie",
    },
}

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def analyze_headers(headers: dict) -> dict:
    lower_headers = {k.lower(): v for k, v in headers.items()}
    findings = []

    for header_name, patterns in SIGNATURES.items():
        value = lower_headers.get(header_name, "")
        for pattern, tech in patterns.items():
            if re.search(pattern, value, re.I):
                findings.append({"source": header_name, "value": value, "tech": tech})

    missing_security = [h for h in SECURITY_HEADERS if h not in lower_headers]
    present_security = [h for h in SECURITY_HEADERS if h in lower_headers]

    return {
        "raw_headers": dict(headers),
        "tech_findings": findings,
        "security_headers_present": present_security,
        "security_headers_missing": missing_security,
    }


def run_whatweb(url: str):
    if not shutil.which("whatweb"):
        return {"available": False, "note": "whatweb chưa được cài / không có trong PATH"}
    try:
        out = subprocess.run(
            ["whatweb", "-a", "3", "--log-json=-", url],
            capture_output=True, text=True, timeout=60,
        )
        lines = [l for l in out.stdout.splitlines() if l.strip().startswith("{")]
        parsed = [json.loads(l) for l in lines] if lines else out.stdout
        return {"available": True, "raw": parsed}
    except Exception as e:
        return {"available": True, "error": str(e)}


def main():
    ap = argparse.ArgumentParser(description="Fingerprint tech stack (thủ công + WhatWeb)")
    ap.add_argument("url")
    ap.add_argument("--json", help="Ghi kết quả JSON ra file")
    ap.add_argument("--skip-whatweb", action="store_true")
    args = ap.parse_args()

    print(f"[*] Đang request {args.url} ...")
    try:
        r = requests.get(args.url, headers=HEADERS, timeout=15, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] Không kết nối được: {e}", file=sys.stderr)
        sys.exit(1)

    manual = analyze_headers(r.headers)

    print("\n=== PHÂN TÍCH THỦ CÔNG (header/cookie) ===")
    print(f"Status: {r.status_code} | Final URL: {r.url}")
    if manual["tech_findings"]:
        for f in manual["tech_findings"]:
            print(f"  [+] {f['tech']}  <-  {f['source']}: {f['value'][:80]}")
    else:
        print("  (Không match signature nào trong danh sách hiện có — "
              "cần đọc thủ công raw headers bên dưới)")

    print("\n  Security headers CÓ:", manual["security_headers_present"] or "(none)")
    print("  Security headers THIẾU:", manual["security_headers_missing"] or "(none)")

    print("\n  Raw headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")

    whatweb_result = {}
    if not args.skip_whatweb:
        print("\n=== ĐỐI CHIẾU VỚI WHATWEB ===")
        whatweb_result = run_whatweb(args.url)
        if not whatweb_result.get("available"):
            print("  [!] " + whatweb_result.get("note", "whatweb không chạy được"))
        else:
            print("  [+] Xem raw output trong file JSON (--json) để đối chiếu chi tiết.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"manual_analysis": manual, "whatweb": whatweb_result}, f, indent=2)
        print(f"\n[+] Đã ghi report đầy đủ vào {args.json}")


if __name__ == "__main__":
    main()
