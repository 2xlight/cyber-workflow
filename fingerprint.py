#!/usr/bin/env python3

import argparse
import json
import re
import shutil
import subprocess
import sys

import requests

HEADERS = {"User-Agent": "Mozilla/5.0 (recon-toolkit; authorized-testing)"}

SIGNATURES = {
    "server": {
        r"nginx": "Nginx",
        r"openresty": "OpenResty",
        r"apache": "Apache HTTPD",
        r"cloudflare": "Cloudflare (proxy/CDN)",
        r"microsoft-iis": "IIS",
        r"gunicorn": "Gunicorn (Python WSGI)",
        r"werkzeug": "Flask dev server (Werkzeug)",
        r"uvicorn": "Uvicorn (Python ASGI)",
        r"kestrel": "Kestrel (.NET Core)",
        r"caddy": "Caddy Web Server",
        r"litespeed": "LiteSpeed",
        r"tomcat": "Apache Tomcat",
        r"jetty": "Eclipse Jetty",
        r"envoy": "Envoy Proxy",
        r"traefik": "Traefik Proxy",
        r"awselb": "AWS Elastic Load Balancer",
        r"istio": "Istio Service Mesh",
    },
    "x-powered-by": {
        r"express": "Express.js (Node)",
        r"php": "PHP",
        r"asp\.net": "ASP.NET",
        r"next\.js": "Next.js (React)",
        r"nuxt": "Nuxt.js (Vue)",
        r"nest": "NestJS (Node)",
        r"ruby": "Ruby on Rails",
        r"flask": "Flask (Python)",
        r"django": "Django (Python)",
        r"phalcon": "Phalcon (PHP)",
        r"sails": "Sails.js (Node)",
        r"strapi": "Strapi CMS",
        r"wordpress": "WordPress",
        r"spring": "Spring Boot (Java)",
        r"svelte": "SvelteKit",
    },
    "set-cookie": {
        r"laravel_session": "Laravel (PHP)",
        r"phpsessid": "PHP",
        r"jsessionid": "Java (Servlet/Spring)",
        r"connect\.sid": "Express.js session",
        r"django": "Django (Python)",
        r"csrftoken": "Django CSRF cookie",
        r"wordpress_logged_in": "WordPress",
        r"wp-settings": "WordPress",
        r"rails_session": "Ruby on Rails",
        r"_session_id": "Ruby on Rails",
        r"asp\.net_sessionid": "ASP.NET",
        r"fleet_session": "Elixir/Phoenix",
        r"remember_token": "Laravel/Auth system",
        r"sessionid": "Generic Python/Django",
        r"next-auth": "NextAuth.js (Node)",
        r"__session": "Firebase Hosting / Google Cloud",
        r"torin_session": "Go framework",
    },
    "x-generator": {
        r"wordpress": "WordPress",
        r"drupal": "Drupal",
        r"joomla": "Joomla",
        r"ghost": "Ghost CMS",
        r"hugo": "Hugo SSG",
        r"jekyll": "Jekyll SSG",
        r"gatsby": "Gatsby (React)",
        r"magento": "Magento",
        r"shopify": "Shopify",
        r"strapi": "Strapi CMS",
    },
    "via": {
        r"cloudflare": "Cloudflare",
        r"google": "Google Frontend",
        r"kong": "Kong API Gateway",
        r"varnish": "Varnish Cache",
        r"fastly": "Fastly CDN",
        r"akamai": "Akamai CDN",
        r"cloudfront": "AWS CloudFront",
        r"traefik": "Traefik",
        r"envoy": "Envoy",
        r"vegur": "Heroku Router",
    },
    "x-aspnet-version": {
        r".*": "ASP.NET Framework",
    },
    "x-runtime": {
        r".*": "Ruby on Rails / Rack application",
    }
}

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
    "x-permitted-cross-domain-policies",
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
