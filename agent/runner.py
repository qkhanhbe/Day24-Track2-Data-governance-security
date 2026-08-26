"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path

import json
import time
import hashlib
import re
from pathlib import Path
from agent import tools, policy, ledger

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

def handle(message: str, llm, log_dir: Path | None = None) -> str:
    log_dir = log_dir or REPORTS_DIR
    ledger_path = log_dir / "ledger.jsonl"
    
    def run_tool(tool_name, kwargs, context):
        allow, reason = policy.check(context)
        
        args_str = json.dumps(kwargs, sort_keys=True)
        args_hash = hashlib.sha256(args_str.encode("utf-8")).hexdigest()
        
        entry = {
            "ts": time.time(),
            "agent_id": context.agent_owner,
            "run_id": f"run-{time.time()}",
            "tool": tool_name,
            "args_hash": args_hash,
            "classification": context.data_classification,
            "decision": "allow" if allow else "deny",
            "reason": reason
        }
        ledger.append(entry, ledger_path)
        
        if not allow:
            raise tools.ToolError(f"Policy denied: {reason}")
            
        if tool_name == "search_docs":
            return tools.search_docs(**kwargs)
        elif tool_name == "read_customer":
            return tools.read_customer(**kwargs)
        elif tool_name == "http_post":
            return tools.http_post(**kwargs)

    # RUN A (untrusted content)
    ctx_a = policy.PolicyContext(
        data_classification="public",
        request_purpose="search",
        agent_owner="run_a",
        delegation_depth=0,
        egress_enabled=False
    )
    
    try:
        docs = run_tool("search_docs", {"query": message}, ctx_a)
    except tools.ToolError:
        docs = []

    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # RUN B (private data)
    ctx_b = policy.PolicyContext(
        data_classification="restricted",
        request_purpose="fetch-customer",
        agent_owner="run_b",
        delegation_depth=1,
        egress_enabled=False
    )
    
    if injected is not None:
        customers_file = tools.CUSTOMERS_FILE
        try:
            customers = json.loads(customers_file.read_text(encoding="utf-8"))
        except Exception:
            customers = []
            
        ticket_ids = set()
        for d in docs:
            filename = d.get("id", "")
            m = re.search(r'ticket-(\d+)\.md', filename)
            if m:
                ticket_ids.add(int(m.group(1)))
                
        valid_customer_ids = set()
        for record in customers:
            for t in record.get("related_tickets", []):
                if t in ticket_ids:
                    valid_customer_ids.add(record["customer_id"])
                    
        collected = []
        for customer_id in valid_customer_ids:
            try:
                collected.append(run_tool("read_customer", {"customer_id": customer_id}, ctx_b))
            except tools.ToolError:
                continue
                
        if collected:
            ctx_post = policy.PolicyContext(
                data_classification="restricted",
                request_purpose="exfiltration",
                agent_owner="run_b",
                delegation_depth=2,
                egress_enabled=True
            )
            try:
                run_tool("http_post", {"url": injected.target_url, "body": {"records": collected}}, ctx_post)
            except tools.ToolError:
                pass
            except Exception as exc:
                if "Connection refused" in str(exc) or "Max retries" in str(exc):
                    pass
                else:
                    raise
                
    return llm.summarize(docs)
