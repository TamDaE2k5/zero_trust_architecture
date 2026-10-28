"""
Mô-đun Thuật toán Kết hợp Chính sách (Policy Combining Algorithm - PDP Core).
Chức năng chính:
1. Đóng vai trò là Bộ Não Quyết Sách (PDP - Policy Decision Point) theo chuẩn kiến trúc ABAC/XACML.
2. Nhận danh sách kết quả thẩm định từng luật từ OPA Engine:
   - "Permit": Thỏa mãn điều kiện cho phép.
   - "Deny": Thỏa mãn điều kiện cấm.
   - "NotApplicable": Luật không liên quan đến tài nguyên/hành động này.
   - "Indeterminate": Lỗi kỹ thuật (thuộc tính hết hạn TTL, dữ liệu lỗi, OPA timeout).
3. Thực thi nguyên tắc an toàn tuyệt đối Fail-Closed:
   Chỉ cần có 1 luật trả về "Indeterminate" $\rightarrow$ Lập tức VETO toàn bộ và quyết định DENY!
4. Giải quyết xung đột (Policy Conflict) bằng thuật toán chuẩn hóa:
   - `deny-overrides`: Chỉ cần có ít nhất 1 luật DENY $\rightarrow$ Quyết định cuối cùng là DENY (Cấm luôn thắng Cho).
   - `permit-overrides`: Chỉ cần có ít nhất 1 luật PERMIT $\rightarrow$ Quyết định cuối cùng là ALLOW.
   - `priority-based`: Luật có mức ưu tiên cao hơn (priority lớn hơn) sẽ thắng thế; nếu ngang hàng, DENY thắng.
5. Mặc định từ chối (Default Deny): Nếu không có luật nào cho phép $\rightarrow$ DENY (`NO_APPLICABLE_PERMIT`).
"""


def combine(outcomes: list[dict], strategy: str) -> dict:
    """
    Kết hợp kết quả các luật thành 1 phán quyết duy nhất (ALLOW hoặc DENY):
    - outcomes: Danh sách kết quả đánh giá từng chính sách từ OPA.
    - strategy: Chiến lược kết hợp ('deny-overrides', 'permit-overrides', 'priority-based').
    """
    # 1. Thu thập các lỗi kỹ thuật (Indeterminate)
    errors = [p for p in outcomes if p["outcome"] == "Indeterminate"]
    
    # 2. Lọc ra các luật có hiệu lực (Permit hoặc Deny), sắp xếp theo thứ tự ưu tiên giảm dần
    effective = sorted(
        [p for p in outcomes if p["outcome"] in ("Permit", "Deny")],
        key=lambda p: (-p["priority"], p["id"]),
    )
    permits = [p for p in effective if p["outcome"] == "Permit"]
    denies = [p for p in effective if p["outcome"] == "Deny"]
    conflict = bool(permits and denies)  # Ghi nhận cờ xung đột nếu xuất hiện cả Cho và Cấm

    # 3. Phân xử phán quyết:
    if errors:
        # Triết lý Fail-Closed: Có lỗi kỹ thuật => Từ chối truy cập ngay lập tức!
        winners = sorted(errors, key=lambda p: p["id"])
        decision, status = "DENY", "DENIED_DUE_TO_TECHNICAL_FAILURE"
    elif not effective:
        # Default Deny: Không có bất kỳ luật nào cho phép => Từ chối truy cập
        winners = []
        decision, status = "DENY", "DENIED_BY_POLICY"
    else:
        # Áp dụng thuật toán kết hợp chính sách
        if strategy == "deny-overrides":
            # Chỉ cần 1 luật cấm xuất hiện => Cấm toàn bộ
            winners = denies or permits
        elif strategy == "permit-overrides":
            # Chỉ cần 1 luật cho phép xuất hiện => Cho phép
            winners = permits or denies
        elif strategy == "priority-based":
            # Lấy nhóm luật có điểm ưu tiên cao nhất; nếu điểm bằng nhau thì luật Cấm thắng
            top = [p for p in effective if p["priority"] == effective[0]["priority"]]
            winners = [p for p in top if p["outcome"] == "Deny"] or top
        else:
            raise ValueError("Unknown combining strategy")
            
        decision = "ALLOW" if winners[0]["outcome"] == "Permit" else "DENY"
        status = "PERMITTED" if decision == "ALLOW" else "DENIED_BY_POLICY"

    chosen = winners[0] if winners else None
    reason = chosen["reason_code"] if chosen else "NO_APPLICABLE_PERMIT"
    explanation = chosen["description"] if chosen else "No applicable Permit supports access."
    
    if errors:
        reason = "INDETERMINATE_POLICY"
        explanation = (
            f"Policy {chosen['id']} returned Indeterminate; a trustworthy decision is unavailable."
        )

    return {
        "decision": decision,
        "decision_status": status,
        "reason_code": reason,
        "explanation": explanation,
        "effective_policies": [p["id"] for p in effective],
        "winning_policies": [p["id"] for p in winners],
        "conflict": conflict,
        "combining_rule": "fail-closed-indeterminate" if errors else strategy,
    }
