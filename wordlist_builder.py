#!/usr/bin/env python3
"""
wordlist_builder.py
--------------------
Mục đích: tự build wordlist RIÊNG cho từng target thay vì chỉ dùng
SecLists mặc định. Ý tưởng: một wordlist "sinh ra" từ chính target sẽ
bắt được các path/tên biến đặc thù (vd: tên nội bộ công ty, prefix
module, tên file JS) mà wordlist chung không có.

Nguồn dữ liệu:
  1. HTML của các trang seed (link nội bộ, form action, comment HTML)
  2. File JavaScript được load (endpoint string, tên biến, route)
  3. robots.txt / sitemap.xml (nếu có)
  4. Danh sách "biến thể" tự sinh (số nhiều/ít, số, năm, đuôi file)

Cài đặt:
  pip install requests beautifulsoup4

Dùng:
  python3 wordlist_builder.py https://target.example --out wordlist.txt
"""

import argparse
import re
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

HEADERS = {"User-Agent": "Mozilla/5.0 (recon-toolkit; authorized-testing)"}

# Từ khoá thường gặp trong path web app hiện đại — điểm khởi đầu để
# tự sinh biến thể, KHÔNG thay thế cho việc thu thập thực tế.
COMMON_STEMS = [
    "api", "admin", "user", "users", "account", "accounts", "auth",
    "login", "logout", "config", "settings", "upload", "uploads",
    "file", "files", "export", "import", "backup", "test", "dev",
    "staging", "internal", "v1", "v2", "v3",
]

JS_STRING_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-/{}.]{2,60})["'`]""")
JS_IDENT_RE = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\s*[:=]\s*(?:function|\(|\{|\[)")


def fetch(url: str, timeout: int = 10):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        return r
    except requests.RequestException as e:
        print(f"[!] Lỗi khi fetch {url}: {e}", file=sys.stderr)
        return None


def extract_from_html(base_url: str, html: str, words: set):
    soup = BeautifulSoup(html, "html.parser")

    # Link nội bộ (href/src)
    for tag in soup.find_all(["a", "link", "script", "img", "form"]):
        for attr in ("href", "src", "action"):
            val = tag.get(attr)
            if not val:
                continue
            path = urlparse(urljoin(base_url, val)).path
            for seg in path.split("/"):
                seg = seg.strip()
                if 2 <= len(seg) <= 40 and not seg.startswith("."):
                    words.add(seg)

    # Comment HTML — hay lộ path debug/test bị quên
    for comment in soup.find_all(string=lambda s: isinstance(s, str)):
        pass  # BeautifulSoup Comment xử lý riêng nếu cần sâu hơn

    return soup


def extract_js_links(base_url: str, soup: BeautifulSoup):
    js_urls = []
    for tag in soup.find_all("script", src=True):
        js_urls.append(urljoin(base_url, tag["src"]))
    return js_urls


def extract_from_js(js_text: str, words: set):
    for m in JS_STRING_RE.finditer(js_text):
        path = m.group(1)
        for seg in path.split("/"):
            seg = seg.strip()
            if 2 <= len(seg) <= 40:
                words.add(seg)
    for m in JS_IDENT_RE.finditer(js_text):
        ident = m.group(1)
        if 3 <= len(ident) <= 30:
            words.add(ident)


def extract_from_robots_sitemap(base_url: str, words: set):
    for path in ("/robots.txt", "/sitemap.xml"):
        r = fetch(urljoin(base_url, path))
        if not r or r.status_code != 200:
            continue
        for line in r.text.splitlines():
            for token in re.split(r"[\s/<>]+", line):
                token = token.strip()
                if 2 <= len(token) <= 40 and re.match(r"^[a-zA-Z0-9_\-.]+$", token):
                    words.add(token)


def gen_variants(words: set) -> set:
    """Sinh biến thể đơn giản: số ít/nhiều, thêm số, thêm đuôi phổ biến."""
    variants = set(words)
    suffixes = ["s", "_bak", ".bak", ".old", ".zip", ".tar.gz", "_v1", "_v2"]
    for w in list(words):
        for suf in suffixes:
            variants.add(w + suf)
    return variants


def main():
    ap = argparse.ArgumentParser(description="Tự build wordlist từ target thực tế")
    ap.add_argument("url", help="URL gốc của target (chỉ chạy với scope đã được phép)")
    ap.add_argument("--out", default="custom_wordlist.txt")
    ap.add_argument("--no-variants", action="store_true", help="Không sinh biến thể tự động")
    ap.add_argument("--seed-common", action="store_true",
                     help="Thêm các stem phổ biến (api, admin, ...) vào kết quả")
    args = ap.parse_args()

    base_url = args.url.rstrip("/")
    words = set()

    print(f"[*] Fetch trang chủ: {base_url}")
    r = fetch(base_url)
    if r and r.status_code == 200:
        soup = extract_from_html(base_url, r.text, words)
        js_urls = extract_js_links(base_url, soup)
        print(f"[*] Tìm thấy {len(js_urls)} file JS, đang phân tích...")
        for js_url in js_urls[:30]:  # giới hạn để tránh spam quá nhiều request
            jr = fetch(js_url)
            if jr and jr.status_code == 200:
                extract_from_js(jr.text, words)

    print("[*] Đọc robots.txt / sitemap.xml...")
    extract_from_robots_sitemap(base_url, words)

    if args.seed_common:
        words.update(COMMON_STEMS)

    if not args.no_variants:
        words = gen_variants(words)

    words = {w for w in words if w and not w.isdigit()}
    result = sorted(words)

    with open(args.out, "w") as f:
        f.write("\n".join(result) + "\n")

    print(f"[+] Đã ghi {len(result)} từ vào {args.out}")
    print("[!] Nhắc nhở: dùng chung với SecLists (kết hợp, không thay thế hoàn toàn), "
          "và luôn review thủ công trước khi đưa vào gobuster/ffuf.")


if __name__ == "__main__":
    main()
