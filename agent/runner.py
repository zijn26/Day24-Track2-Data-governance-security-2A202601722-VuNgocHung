"""BƯỚC 3c — trifecta split + egress allowlist (13').

Kiến trúc trifecta split:
- Run A (Untrusted reader):
    + Gọi search_docs (untrusted content)
    + KHÔNG gọi read_customer, KHÔNG gọi http_post
    + Quét tìm injection attempt bằng llm.find_injection(text)
    + Trích xuất dữ liệu typed (danh sách ticket_id số nguyên từ tên file)
    + Free-text của document không bao giờ được chuyển tiếp sang Run B.
- Run B (Protected processor / PEP Gate):
    + Ánh xạ ticket_id nhận từ Run A -> customer_id qua related_tickets trong customers.json
    + Gọi read_customer(customer_id) sau khi kiểm tra policy (egress_enabled=False)
    + Nếu có chỉ thị gọi egress/http_post ra ngoài:
        Đi qua PolicyContext(data_classification="restricted", egress_enabled=True, ...)
        -> Policy DENY
        -> Ghi nhận quyết định deny vào audit ledger (với reason chi tiết)
        -> KHÔNG thực thi tool call http_post.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, policy, tools

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _hash_args(args: dict) -> str:
    serialized = json.dumps(args, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _extract_ticket_ids(docs: list[dict]) -> set[int]:
    ticket_ids = set()
    for d in docs:
        match = re.search(r"ticket-(\d+)", d["id"])
        if match:
            ticket_ids.add(int(match.group(1)))
    return ticket_ids


def _lookup_customer_ids(ticket_ids: set[int], customers_file: Path | None = None) -> list[str]:
    c_file = customers_file or CUSTOMERS_FILE
    if not c_file.exists():
        return []
    customers = json.loads(c_file.read_text(encoding="utf-8"))
    matched = []
    for c in customers:
        related = set(c.get("related_tickets", []))
        if related.intersection(ticket_ids):
            matched.append(c["customer_id"])
    return matched


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    """Điều phối thực thi yêu cầu theo mô hình trifecta split + audit ledger."""
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH

    # ── RUN A: Đọc untrusted content (search_docs) ──
    ctx_search = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_search, reason_search = policy.check(ctx_search)
    ledger.append(
        {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": "lab24-agent",
            "run_id": "run-a",
            "tool": "search_docs",
            "args_hash": _hash_args({"query": message}),
            "classification": "internal",
            "decision": "allow" if allow_search else "deny",
            "reason": reason_search,
        },
        ledger_path,
    )

    if not allow_search:
        return "Yêu cầu tìm kiếm tài liệu bị từ chối bởi chính sách."

    docs = tools.search_docs(message)
    combined_text = "\n\n".join(d["text"] for d in docs)

    # Run A quét xem có dấu hiệu prompt injection không
    injected = llm.find_injection(combined_text)

    # Run A trích xuất typed data: danh sách ticket_id từ tên file (không từ text)
    ticket_ids = _extract_ticket_ids(docs)

    # ── RUN B: Xử lý dữ liệu nhạy cảm & kiểm soát tool call ──
    # Run B tra cứu customer_id từ nguồn tin cậy (customers.json related_tickets)
    valid_customer_ids = _lookup_customer_ids(ticket_ids)

    # Run B đọc dữ liệu khách hàng hợp lệ (trong môi trường cô lập, egress_enabled=False)
    for cid in valid_customer_ids:
        ctx_read = policy.PolicyContext(
            data_classification="internal",
            request_purpose="support-ticket-context",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_read, reason_read = policy.check(ctx_read)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "read_customer",
                "args_hash": _hash_args({"customer_id": cid}),
                "classification": "internal",
                "decision": "allow" if allow_read else "deny",
                "reason": reason_read,
            },
            ledger_path,
        )
        if allow_read:
            try:
                tools.read_customer(cid)
            except tools.ToolError:
                pass

    # Nếu có chỉ thị tấn công yêu cầu exfiltration / http_post:
    if injected is not None:
        ctx_post = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_post, reason_post = policy.check(ctx_post)
        ledger.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "agent_id": "lab24-agent",
                "run_id": "run-b",
                "tool": "http_post",
                "args_hash": _hash_args({"url": injected.target_url, "customer_ids": injected.customer_ids}),
                "classification": "restricted",
                "decision": "allow" if allow_post else "deny",
                "reason": reason_post,
            },
            ledger_path,
        )
        # Policy deny -> KHÔNG gọi tools.http_post

    # Trả về câu trả lời tóm tắt cho người dùng
    return llm.summarize(docs)
