#!/usr/bin/env bash
#
# vuln_scan_workflow.sh
# ------------------------
# Luồng WEEK-II: chạy Nikto + SQLMap trên target, output có cấu trúc
# rõ ràng để sau đó ĐỐI CHIẾU với kiểm tra tay (mục tiêu là hiểu false
# positive, không phải chỉ lấy kết quả tool rồi tin luôn).
#
# CHỈ chạy trên DVWA/bWAPP local hoặc target trong scope hợp lệ.
#
# Dùng:
#   ./vuln_scan_workflow.sh http://dvwa.local/vulnerabilities/sqli/?id=1
#
set -euo pipefail

TARGET="${1:?Thiếu target URL (nên có tham số, vd ?id=1). Dùng: $0 <url>}"
OUTDIR="${2:-./vulnscan_results_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

echo "[*] Target : $TARGET"
echo "[*] Output : $OUTDIR"
echo

# ---------- Nikto ----------
echo "[1/2] Chạy Nikto..."
if command -v nikto >/dev/null; then
  nikto -h "$TARGET" -output "$OUTDIR/nikto.txt" -Format txt || \
    echo "  [!] Nikto kết thúc với warning/lỗi, vẫn xem output"
  echo "  [+] Nikto -> $OUTDIR/nikto.txt"
else
  echo "  [!] nikto chưa cài, bỏ qua"
fi
echo

# ---------- SQLMap ----------
# Mức risk/level thấp trước (an toàn hơn, ít request hơn), tăng dần
# sau khi đã xác nhận đây là target được phép test kỹ.
echo "[2/2] Chạy SQLMap (level=1 risk=1, batch mode)..."
if command -v sqlmap >/dev/null; then
  sqlmap -u "$TARGET" \
    --batch \
    --level=1 --risk=1 \
    --output-dir="$OUTDIR/sqlmap" \
    2>&1 | tee "$OUTDIR/sqlmap_console.txt"
  echo "  [+] SQLMap -> $OUTDIR/sqlmap/ (chi tiết) + $OUTDIR/sqlmap_console.txt (log console)"
else
  echo "  [!] sqlmap chưa cài, bỏ qua"
fi
echo

# ---------- Checklist đối chiếu thủ công ----------
cat > "$OUTDIR/manual_verification_checklist.md" << 'EOF'
# Checklist đối chiếu thủ công sau khi chạy tool

Với MỖI finding mà Nikto/SQLMap báo cáo, trả lời các câu hỏi sau
trước khi coi đó là true positive:

- [ ] Tool báo lỗi gì cụ thể? (path, parameter, payload dùng để phát hiện)
- [ ] Tự tay replay request đó (curl/Burp Repeater) — response có thực
      sự khác biệt như tool mô tả không?
- [ ] Nếu là SQLi: response time-based có ổn định qua 3 lần thử lại
      không, hay chỉ là network jitter?
- [ ] Nếu là lỗi từ Nikto (thường nhiều false positive theo version
      banner): version banner đó có đúng là version đang chạy không,
      hay là banner giả/đã bị che (server che version thật)?
- [ ] Có thể chứng minh impact thực tế không (đọc được data, bypass
      auth...) hay chỉ là "tool nói vậy"?

Ghi lại vào report_template.md: mỗi finding => true positive /
false positive / cần kiểm tra thêm, kèm lý do.
EOF

echo "=== XONG. Checklist đối chiếu: $OUTDIR/manual_verification_checklist.md ==="
