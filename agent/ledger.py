"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

from pathlib import Path


import json
import hashlib
from typing import Any

def append(entry: dict, path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    
    prev_hash = "0" * 64
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            if lines:
                try:
                    last_entry = json.loads(lines[-1].strip())
                    if "hash" in last_entry:
                        prev_hash = last_entry["hash"]
                except json.JSONDecodeError:
                    pass

    # Copy entry to avoid mutating
    out = dict(entry)
    out["prev_hash"] = prev_hash
    
    if "hash" in out:
        del out["hash"]
        
    s = json.dumps(out, sort_keys=True, ensure_ascii=False)
    out["hash"] = hashlib.sha256(s.encode("utf-8")).hexdigest()
    
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(out, ensure_ascii=False) + "\n")
        
    return out


def verify(path: Path) -> bool:
    if not path.exists():
        return True
        
    prev_expected = "0" * 64
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False
                
            reason = entry.get("reason")
            if not reason or str(reason).strip() == "":
                return False
                
            if entry.get("prev_hash") != prev_expected:
                return False
                
            recorded_hash = entry.get("hash")
            if not recorded_hash:
                return False
                
            # Recompute hash
            copy_entry = dict(entry)
            del copy_entry["hash"]
            
            s = json.dumps(copy_entry, sort_keys=True, ensure_ascii=False)
            h = hashlib.sha256(s.encode("utf-8")).hexdigest()
            
            if h != recorded_hash:
                return False
                
            prev_expected = recorded_hash
            
    return True
