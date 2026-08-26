"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations
import re

# Gợi ý định dạng
REGEXES = {
    "VN_CCCD": r"\b\d{12}\b",
    "VN_PHONE": r"\b0(?:\s*[-.]?\s*\d){9}\b|\b0(?:\s*[-.]?\s*\d){10}\b",
    "VN_BANK_ACCOUNT": r"(?i)(?:stk|số tài khoản|sotaikhoan|so tk)[\s:.\-]*(\d{8,16})\b",
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
}

def detect(text: str) -> list[dict]:
    entities = []
    
    # CCCD
    for m in re.finditer(REGEXES["VN_CCCD"], text):
        entities.append({"type": "VN_CCCD", "start": m.start(), "end": m.end()})
    
    # Phone
    for m in re.finditer(REGEXES["VN_PHONE"], text):
        # ensure it's not actually CCCD (12 digits straight)
        s = m.group(0).replace(" ", "").replace("-", "").replace(".", "")
        if len(s) in [10, 11]:
            entities.append({"type": "VN_PHONE", "start": m.start(), "end": m.end()})
            
    # Bank Account
    for m in re.finditer(REGEXES["VN_BANK_ACCOUNT"], text):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})
        
    # Email
    for m in re.finditer(REGEXES["EMAIL"], text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        
    # Remove overlapping entities, keep the longer ones or just sort by start
    # To be safe, sort by start and resolve overlaps
    entities.sort(key=lambda x: (x["start"], -x["end"]))
    filtered = []
    last_end = -1
    for e in entities:
        if e["start"] >= last_end:
            filtered.append(e)
            last_end = e["end"]
            
    return filtered

def redact(text: str) -> str:
    entities = detect(text)
    # reverse sort by start to replace from end to beginning
    entities.sort(key=lambda x: x["start"], reverse=True)
    for e in entities:
        text = text[:e["start"]] + f"[REDACTED_{e['type']}]" + text[e["end"]:]
    return text
