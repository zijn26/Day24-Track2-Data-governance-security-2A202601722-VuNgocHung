# Báo cáo Đánh giá Tác động Xử lý Dữ liệu Cá nhân (DPIA-Lite)

**Hệ thống:** AI Customer Support & Ticket Summarization Agent  
**Thời gian lập:** 2026-08-26  
**Căn cứ pháp lý:** Nghị định 13/2023/NĐ-CP, Nghị định 356/2025/NĐ-CP, Tiêu chuẩn ISO/IEC 42001:2023  

---

## 1. Dữ liệu gì (Data Inventory)

Hệ thống Agent thu thập, xử lý và phân loại các luồng dữ liệu sau theo từng công cụ (`Tool`):

| Công cụ | Loại dữ liệu | Phân loại dữ liệu | Các trường dữ liệu nhạy cảm (PII) |
|---|---|---|---|
| `search_docs` | Nội dung văn bản các ticket yêu cầu hỗ trợ từ khách hàng trong `corpus/` | **Internal / Untrusted** | Tiêu đề ticket, mô tả sự cố, thông tin văn bản tự do (có thể chứa payload injection do attacker cài cắm). |
| `read_customer` | Hồ sơ chi tiết của khách hàng trong `data/customers.json` | **Restricted / Private PII** | Họ và tên (`name`), Số CCCD 12 số (`cccd`), Số điện thoại (`phone`), Số tài khoản ngân hàng (`bank_account`), Địa chỉ thư điện tử (`email`), Danh sách ticket liên quan (`related_tickets`). |
| `http_post` | Dữ liệu đẩy ra cổng tích hợp ngoài (Sink endpoint `localhost:9999/reconcile`) | **Restricted Outbound** | Hồ sơ khách hàng sau khi tổng hợp hoặc đối soát. |

---

## 2. Mục đích xử lý (Processing Purposes)

- **Tổng hợp và tra cứu yêu cầu khách hàng:** Agent đọc nội dung các ticket hỗ trợ (`search_docs`) nhằm tóm tắt tình trạng xử lý các yêu cầu còn mở trong tuần, hỗ trợ nhân viên CSKH nắm bắt khối lượng công việc.
- **Hỗ trợ ngữ cảnh hồ sơ (Contextual Support):** Khi cần thông tin chi tiết về khách hàng sở hữu ticket, hệ thống tra cứu hồ sơ (`read_customer`) theo định danh được liên kết tin cậy (`related_tickets`) để xác thực thông tin đối soát.
- **Nguyên tắc giảm thiểu dữ liệu (Data Minimization):** Hệ thống chỉ trích xuất định danh số nguyên (`ticket_id`) từ tên tệp tin để chuyển sang Run B; không đưa toàn bộ văn bản tự do chứa PII hoặc chỉ thị thô vào môi trường xử lý nhạy cảm.

---

## 3. Luồng dữ liệu và Chuyển giao dữ liệu (Data Flows & Transfers)

### 3.1. Các điểm đến của luồng dữ liệu (Destinations)
1. **Audit Ledger nội bộ (`reports/ledger.jsonl`):**
   - Lưu trữ metadata kiểm toán: timestamp, `agent_id`, `run_id`, tên tool, hash của tham số (`args_hash`), phân loại dữ liệu, quyết định cấp phép (`decision`) và lý do (`reason`).
   - Tuyệt đối không lưu raw PII (như CCCD, STK) trong ledger mà chỉ lưu hash SHA-256 của tham số.
2. **Kênh truyền mạng cục bộ (Exfiltration Sink):**
   - Được chặn cứng ở mức allowlist `localhost:9999`.
   - Cơ chế PEP (`agent/policy.py`) và Trifecta Split (`agent/runner.py`) đảm bảo mọi yêu cầu gửi dữ liệu PII ra mạng đều bị từ chối (`decision=deny`) và không bao giờ được kích hoạt.

### 3.2. Đánh giá chuyển giao dữ liệu xuyên biên giới (Theo NĐ 356/2025/NĐ-CP)
- **Chế độ Fake/Mock LLM (`--mock`):** 100% dữ liệu được xử lý deterministic tại chỗ (on-premise / local machine), không có dữ liệu nào truyền ra khỏi biên giới Việt Nam.
- **Chế độ Real LLM Cloud (`--model claude-...`):**
   - Dữ liệu prompt và nội dung tóm tắt được gửi qua API tới hạ tầng máy chủ của nhà cung cấp mô hình (ví dụ: Anthropic API tại Hoa Kỳ).
   - **Đánh giá rủi ro:** Đây là hoạt động chuyển dữ liệu cá nhân ra nước ngoài theo quy định của Nghị định 356/2025.
   - **Biện pháp giảm thiểu rủi ro:** 
     1. Tích hợp cổng **PII Redaction Gate** (`agent/pii.py`) trước khi gửi context tới LLM Cloud, tự động che giấu CCCD, Số điện thoại, STK, Email thành các nhãn `[REDACTED_<TYPE>]`.
     2. Lưu trữ hồ sơ đánh giá tác động và nhật ký truyền dữ liệu tối thiểu 60 ngày theo quy định của NĐ 356/2025.
