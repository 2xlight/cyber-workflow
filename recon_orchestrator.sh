#!/usr/bin/env bash
#
# recon_orchestrator.sh
# -----------------------
# Gộp toàn bộ luồng Web Recon của WEEK-I thành 1 lệnh:
#   1) build wordlist riêng cho target (wordlist_builder.py)
#   2) directory bruteforce với gobuster VÀ ffuf (đối chiếu 2 tool)
#   3) tech stack fingerprinting (fingerprint.py)
#   4) robots.txt / sitemap.xml + parameter discovery (arjun, ParamSpider)
#
# Yêu cầu cài sẵn (không tự cài trong script để tránh chạy sudo ẩn):
#   gobuster, ffuf, arjun, paramspider (hoặc python module), curl, jq (tuỳ chọn)
#
# CHỈ chạy với target đã được phép test (DVWA/Juice Shop nội bộ,
# hoặc target nằm trong scope bug bounty hợp lệ).
#
# Dùng:
#   ./recon_orchestrator.sh https://target.example ./results
#
set -euo pipefail

TARGET="${1:?Thiếu target. Dùng: $0 <url> [output_dir]}"
OUTDIR="${2:-./recon_results_$(date +%Y%m%d_%H%M%S)}"
THREADS="${THREADS:-40}"

mkdir -p "$OUTDIR"
echo "[*] Target : $TARGET"
echo "[*] Output : $OUTDIR"
echo

# ---------- 1) Build wordlist riêng ----------
echo "[1/4] Build wordlist riêng từ target..."
CUSTOM_WL="$OUTDIR/custom_wordlist.txt"
if python3 wordlist_builder.py "$TARGET" --out "$CUSTOM_WL" --seed-common; then
  echo "  [+] Wordlist riêng: $CUSTOM_WL"
else
  echo "  [!] wordlist_builder.py lỗi, dùng fallback SecLists"
fi

# Gộp wordlist riêng với SecLists common.txt nếu có sẵn trên máy
SECLISTS_COMMON="/usr/share/seclists/Discovery/Web-Content/common.txt"
COMBINED_WL="$OUTDIR/combined_wordlist.txt"
if [ -f "$SECLISTS_COMMON" ]; then
  cat "$CUSTOM_WL" "$SECLISTS_COMMON" 2>/dev/null | sort -u > "$COMBINED_WL"
else
  cp "$CUSTOM_WL" "$COMBINED_WL"
fi
echo "  [+] Wordlist tổng hợp: $COMBINED_WL ($(wc -l < "$COMBINED_WL") dòng)"
echo

# ---------- 2) Directory bruteforce: gobuster + ffuf ----------
echo "[2/4] Directory bruteforce (gobuster + ffuf, để đối chiếu kết quả)..."
if command -v gobuster >/dev/null; then
  gobuster dir -u "$TARGET" -w "$COMBINED_WL" -t "$THREADS" \
    -o "$OUTDIR/gobuster.txt" -q || echo "  [!] gobuster kết thúc với lỗi/không tìm thấy gì"
  echo "  [+] gobuster -> $OUTDIR/gobuster.txt"
else
  echo "  [!] gobuster chưa cài, bỏ qua"
fi

if command -v ffuf >/dev/null; then
  ffuf -u "${TARGET%/}/FUZZ" -w "$COMBINED_WL" -t "$THREADS" \
    -mc 200,204,301,302,307,401,403 \
    -o "$OUTDIR/ffuf.json" -of json -s || echo "  [!] ffuf kết thúc với lỗi"
  echo "  [+] ffuf -> $OUTDIR/ffuf.json"
else
  echo "  [!] ffuf chưa cài, bỏ qua"
fi
echo "  [i] So sánh gobuster.txt vs ffuf.json thủ công: endpoint nào chỉ 1 tool thấy" \
     "thường là do khác biệt wordlist hoặc status-code filter — đáng để đào sâu."
echo

# ---------- 3) Tech stack fingerprinting ----------
echo "[3/4] Tech stack fingerprinting..."
python3 fingerprint.py "$TARGET" --json "$OUTDIR/fingerprint.json" \
  | tee "$OUTDIR/fingerprint.txt"
echo

# ---------- 4) robots/sitemap + parameter discovery ----------
echo "[4/4] robots.txt / sitemap.xml + parameter discovery..."
curl -s "${TARGET%/}/robots.txt" -o "$OUTDIR/robots.txt" || true
curl -s "${TARGET%/}/sitemap.xml" -o "$OUTDIR/sitemap.xml" || true
echo "  [+] Đã lưu robots.txt / sitemap.xml (nếu tồn tại) vào $OUTDIR"

if command -v arjun >/dev/null; then
  arjun -u "$TARGET" -o "$OUTDIR/arjun.json" || echo "  [!] arjun lỗi"
  echo "  [+] arjun -> $OUTDIR/arjun.json"
else
  echo "  [!] arjun chưa cài (pip install arjun), bỏ qua"
fi

if command -v paramspider >/dev/null; then
  DOMAIN="$(echo "$TARGET" | sed -E 's#https?://##' | cut -d/ -f1)"
  paramspider -d "$DOMAIN" -o "$OUTDIR/paramspider_output" || echo "  [!] paramspider lỗi"
  echo "  [+] paramspider -> $OUTDIR/paramspider_output"
else
  echo "  [!] paramspider chưa cài, bỏ qua (git clone + pip install -r requirements.txt)"
fi

echo
echo "=== XONG. Toàn bộ kết quả nằm trong: $OUTDIR ==="
echo "Bước tiếp theo (thủ công, không tự động hoá):"
echo "  - Đọc từng endpoint mới tìm được, đặc biệt status 403/401/500"
echo "  - Đối chiếu param từ arjun/paramspider với endpoint từ gobuster/ffuf"
echo "  - Ghi lại vào note: endpoint nào bất thường, đáng nghi vấn IDOR/auth bypass"
