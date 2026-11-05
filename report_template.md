# Report: Tool tự động vs Kiểm tra tay

**Target:** <tên/URL target — ghi rõ đây là DVWA/bWAPP/Juice Shop hay scope bug bounty>
**Ngày thực hiện:** <YYYY-MM-DD>
**Tool đã dùng:** Nuclei (custom templates), Nikto, SQLMap, XSStrike

---

## 1. Tổng quan số liệu

- Tổng số finding do tool báo cáo: <n>
- Số finding xác nhận true positive sau kiểm tra tay: <n>
- Số finding false positive: <n>
- Số finding cần theo dõi thêm (chưa kết luận được): <n>

---

## 2. Chi tiết từng finding

### Finding #1: <tên lỗi, vd "Reflected XSS tại /search?q=">

- **Phát hiện bằng tool nào:** <Nuclei custom-reflected-xss.yaml / XSStrike / ...>
- **Payload/request tool dùng:** <copy request thực tế>
- **Kết quả kiểm tra tay:**
  - Cách tự tay verify: <mô tả bước làm, dùng Burp Repeater/curl>
  - Response thực tế: <mô tả hoặc trích ngắn>
- **Kết luận:** True positive / False positive / Cần theo dõi thêm
- **Lý do false positive (nếu có):** <vd: input bị encode ở tầng khác
  mà tool không thấy, hoặc WAF chặn payload thật nhưng response vẫn
  200 nên tool tưởng thành công>
- **Thời gian tool phát hiện vs thời gian bạn tự tìm tay (nếu đã tìm
  trước đó):** <so sánh, ví dụ tool nhanh hơn nhưng bỏ sót context>

*(Lặp lại mục 2 cho từng finding quan trọng — không cần liệt kê hết
finding nhiễu/informational không đáng chú ý.)*

---

## 3. So sánh XSStrike vs XSS tự tay tìm được

- XSS bạn tự tay tìm trước đó (từ tuần Nuclei/OWASP trước): <mô tả>
- XSStrike có phát hiện lại được lỗi này không? <có/không, vì sao>
- XSStrike có tìm thêm được lỗi nào mới không? <liệt kê, đã verify tay chưa>

---

## 4. Nhận xét chung về false positive

- Loại false positive gặp nhiều nhất với tool nào: <Nikto banner-based /
  SQLMap time-based trên network chậm / ...>
- Điều chỉnh gì cho lần scan sau (level/risk của sqlmap, filter status
  code của nuclei, v.v.): <ghi lại để lần sau scan hiệu quả hơn>

---

## 5. Custom Nuclei Templates đã viết

- Template 1: <tên file> — lỗi gì, verify thế nào, link PoC nội bộ
- Template 2: <tên file> — ...
- Template 3: <tên file> — ...
