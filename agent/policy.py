"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc Guide.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input đúng slide §3.3 (đã định nghĩa sẵn, đừng đổi field):

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool


def check(context: PolicyContext) -> tuple[bool, str]:
    """Policy Enforcement Point kiểm tra quyền thực thi dựa trên context 5 chiều."""
    classification = context.data_classification.lower()

    # Rule 1: Chặn truy cập dữ liệu restricted khi môi trường có bật network egress
    if classification == "restricted" and context.egress_enabled:
        return (
            False,
            f"Denied: data_classification='restricted' is forbidden when egress_enabled=True "
            f"for agent '{context.agent_owner}' (purpose: '{context.request_purpose}')",
        )

    # Rule 2: Cho phép dữ liệu restricted nếu không có network egress (môi trường cô lập)
    if classification == "restricted" and not context.egress_enabled:
        return (
            True,
            f"Allowed: restricted data access permitted in isolated environment (egress_enabled=False) "
            f"for agent '{context.agent_owner}'",
        )

    # Rule 3: Dữ liệu internal
    if classification == "internal":
        return (
            True,
            f"Allowed: internal data access permitted for agent '{context.agent_owner}' "
            f"(purpose: '{context.request_purpose}', egress={context.egress_enabled})",
        )

    # Rule 4: Dữ liệu public
    if classification == "public":
        return (
            True,
            f"Allowed: public data access permitted for agent '{context.agent_owner}'",
        )

    # Default fallback
    return (
        True,
        f"Allowed: standard access for classification '{context.data_classification}'",
    )
