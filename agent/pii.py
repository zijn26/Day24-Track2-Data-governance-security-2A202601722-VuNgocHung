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


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong chuỗi text.
    
    Hỗ trợ: EMAIL, VN_BANK_ACCOUNT, VN_CCCD, VN_PHONE.
    """
    entities: list[dict] = []

    # 1. EMAIL
    for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})

    # 2. VN_BANK_ACCOUNT (thường đi kèm tiền tố STK/số tài khoản/TK và có từ 8-19 số)
    for m in re.finditer(
        r"(?:STK|số tài khoản|so tai khoan|tài khoản|tai khoan|TK)\s*[:.]?\s*(\d{8,19})\b",
        text,
        re.IGNORECASE,
    ):
        entities.append({"type": "VN_BANK_ACCOUNT", "start": m.start(1), "end": m.end(1)})

    # 3. VN_CCCD (12 chữ số liên tiếp)
    for m in re.finditer(r"\b\d{12}\b", text):
        start, end = m.start(), m.end()
        # Tránh trùng lặp với entity đã phát hiện (ví dụ số tài khoản)
        if not any(e["start"] <= start < e["end"] or e["start"] < end <= e["end"] for e in entities):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # 4. VN_PHONE (10 chữ số bắt đầu bằng số 0)
    for m in re.finditer(r"\b0\d{9}\b", text):
        start, end = m.start(), m.end()
        if not any(e["start"] <= start < e["end"] or e["start"] < end <= e["end"] for e in entities):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế các entity PII phát hiện được bằng [REDACTED_<TYPE>]."""
    entities = detect(text)
    # Thay thế từ cuối văn bản lên đầu để không làm lệch offset ký tự
    sorted_entities = sorted(entities, key=lambda x: x["start"], reverse=True)
    result = text
    for entity in sorted_entities:
        start = entity["start"]
        end = entity["end"]
        etype = entity["type"]
        result = result[:start] + f"[REDACTED_{etype}]" + result[end:]
    return result
