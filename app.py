import sqlite3
import json
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os

# 数据库文件路径
DB_FILE = "mcp_checker.db"

app = FastAPI(title="MCP Checker Web Management")

# 添加CORS支持
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 数据模型
class MaliciousHash(BaseModel):
    hash_value: str
    description: Optional[str] = ""

class DetectionRecord(BaseModel):
    id: int
    mcp_name: str
    hash: str
    description: Optional[str]
    security_issues: List[str]
    config: Optional[dict]
    args: Optional[dict]
    result: Optional[dict]
    detection_type: str
    detected_at: str

# 数据库操作函数
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# 病毒库管理API
@app.post("/api/virus-signatures")
async def add_malicious_hash(hash_data: MaliciousHash):
    """添加恶意hash到病毒库"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT OR IGNORE INTO virus_signatures (hash, description) VALUES (?, ?)",
            (hash_data.hash_value, hash_data.description)
        )
        conn.commit()
        return {"status": "success", "message": f"已将hash {hash_data.hash_value} 添加到病毒库"}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"添加时出错: {e}")
    finally:
        conn.close()

@app.delete("/api/virus-signatures/{hash_value}")
async def remove_malicious_hash(hash_value: str):
    """从病毒库中移除恶意hash"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM virus_signatures WHERE hash = ?", (hash_value,))
        conn.commit()
        deleted_count = cursor.rowcount
        if deleted_count > 0:
            return {"status": "success", "message": f"已从病毒库中移除hash {hash_value}"}
        else:
            raise HTTPException(status_code=404, detail=f"病毒库中未找到hash {hash_value}")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"删除时出错: {e}")
    finally:
        conn.close()

@app.get("/api/virus-signatures")
async def get_malicious_hashes(skip: int = 0, limit: int = Query(100, le=1000)):
    """获取所有恶意hash"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT hash, description, added_at FROM virus_signatures LIMIT ? OFFSET ?", (limit, skip))
        rows = cursor.fetchall()
        hashes = [{"hash": row[0], "description": row[1], "added_at": row[2]} for row in rows]
        return {"status": "success", "count": len(hashes), "hashes": hashes}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")
    finally:
        conn.close()

# 检测记录管理API
@app.get("/api/detection-records")
async def get_detection_records(skip: int = 0, limit: int = Query(100, le=1000)):
    """获取检测记录"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT id, mcp_name, hash, description, security_issues, config, args, result, detection_type, detected_at
            FROM detection_records
            ORDER BY detected_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, skip))
        rows = cursor.fetchall()
        
        records = []
        for row in rows:
            records.append({
                "id": row[0],
                "mcp_name": row[1],
                "hash": row[2],
                "description": row[3],
                "security_issues": json.loads(row[4]) if row[4] else [],
                "config": json.loads(row[5]) if row[5] else None,
                "args": json.loads(row[6]) if row[6] else None,
                "result": json.loads(row[7]) if row[7] else None,
                "detection_type": row[8],
                "detected_at": row[9]
            })
        
        return {"status": "success", "count": len(records), "records": records}
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")
    finally:
        conn.close()

@app.delete("/api/detection-records/{record_id}")
async def delete_detection_record(record_id: int):
    """删除检测记录"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM detection_records WHERE id = ?", (record_id,))
        conn.commit()
        deleted_count = cursor.rowcount
        if deleted_count > 0:
            return {"status": "success", "message": f"已删除记录 {record_id}"}
        else:
            raise HTTPException(status_code=404, detail=f"未找到记录 {record_id}")
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"删除时出错: {e}")
    finally:
        conn.close()

@app.get("/api/stats")
async def get_stats():
    """获取统计信息"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        # 获取病毒库数量
        cursor.execute("SELECT COUNT(*) FROM virus_signatures")
        virus_count = cursor.fetchone()[0]
        
        # 获取检测记录数量
        cursor.execute("SELECT COUNT(*) FROM detection_records")
        record_count = cursor.fetchone()[0]
        
        # 获取最近的检测记录
        cursor.execute('''
            SELECT id, mcp_name, hash, description, security_issues, detection_type, detected_at
            FROM detection_records
            ORDER BY detected_at DESC
            LIMIT 5
        ''')
        recent_rows = cursor.fetchall()
        recent_records = [
            {
                "id": row[0],
                "mcp_name": row[1],
                "hash": row[2],
                "description": row[3],
                "security_issues_count": len(json.loads(row[4])) if row[4] else 0,
                "detection_type": row[5],
                "detected_at": row[6]
            }
            for row in recent_rows
        ]
        
        return {
            "virus_signatures_count": virus_count,
            "detection_records_count": record_count,
            "recent_records": recent_records
        }
    except sqlite3.Error as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")
    finally:
        conn.close()

@app.get("/")
async def root():
    return {"message": "MCP Checker Web Management API"}

@app.get("/web_admin.html", response_class=FileResponse)
async def web_admin():
    return FileResponse("web_admin.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)