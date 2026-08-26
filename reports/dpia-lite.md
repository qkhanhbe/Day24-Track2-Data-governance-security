# DPIA Lite — Data Privacy Impact Assessment

## §1 Mô tả dòng dữ liệu
Dữ liệu khách hàng (bao gồm PII như CCCD, số điện thoại, số tài khoản, email) từ `data/customers.json` được trích xuất khi người dùng hoặc agent thực hiện tìm kiếm ticket và yêu cầu tra cứu thông tin khách hàng.

## §2 Data-flow Inventory cho LLM API call
Theo Nghị định 356/2025 về hồ sơ xuyên biên giới:
- Khi chạy agent với `--mock`, dữ liệu chỉ lưu chuyển nội bộ trên `localhost`.
- Khi dùng `--model` (ví dụ `claude-haiku-4-5`), các văn bản ticket sẽ được gửi ra Anthropic API thông qua mạng Internet. Mặc dù ở Bước 3c, `read_customer` trả dữ liệu cục bộ, nội dung trả về có thể được ghép vào prompt để tạo `summary`. Do đó, dòng dữ liệu PII đã bị lộ ra ngoài biên giới quốc gia tới máy chủ Anthropic.
- Control hiện tại: PII Detection & Redaction (agent/pii.py) đảm bảo các dữ liệu nhạy cảm được redacted trước khi đi vào context của LLM hoặc ghi ra ngoài.
