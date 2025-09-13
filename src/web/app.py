import sqlite3
import json
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional, List
import os
import sys
import pathlib

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from db.database import (
    get_stats, get_malicious_hashes, add_malicious_hash, 
    remove_malicious_hash, get_detection_records, delete_detection_record
)

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

@app.post("/api/virus-signatures")
async def add_malicious_hash_api(hash_data: MaliciousHash):
    """添加恶意hash到病毒库"""
    try:
        add_malicious_hash(hash_data.hash_value, hash_data.description)
        return {"status": "success", "message": f"已将hash {hash_data.hash_value} 添加到病毒库"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"添加时出错: {e}")

@app.delete("/api/virus-signatures/{hash_value}")
async def remove_malicious_hash_api(hash_value: str):
    """从病毒库中移除恶意hash"""
    try:
        success = remove_malicious_hash(hash_value)
        if success:
            return {"status": "success", "message": f"已从病毒库中移除hash {hash_value}"}
        else:
            raise HTTPException(status_code=404, detail=f"病毒库中未找到hash {hash_value}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除时出错: {e}")

@app.get("/api/virus-signatures")
async def get_malicious_hashes_api(skip: int = 0, limit: int = Query(100, le=1000)):
    """获取所有恶意hash"""
    try:
        all_hashes = get_malicious_hashes()
        # 实现分页
        paginated_hashes = all_hashes[skip:skip+limit]
        return {"status": "success", "count": len(paginated_hashes), "hashes": paginated_hashes}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")

@app.get("/api/detection-records")
async def get_detection_records_api(skip: int = 0, limit: int = Query(100, le=1000)):
    """获取检测记录"""
    try:
        all_records = get_detection_records()
        # 实现分页
        paginated_records = all_records[skip:skip+limit]
        return {"status": "success", "count": len(paginated_records), "records": paginated_records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")

@app.delete("/api/detection-records/{record_id}")
async def delete_detection_record_api(record_id: int):
    """删除检测记录"""
    try:
        success = delete_detection_record(record_id)
        if success:
            return {"status": "success", "message": f"已删除记录 {record_id}"}
        else:
            raise HTTPException(status_code=404, detail=f"未找到记录 {record_id}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"删除时出错: {e}")

@app.get("/api/stats")
async def get_stats_api():
    """获取统计信息"""
    try:
        stats = get_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询时出错: {e}")

@app.get("/")
async def root():
    return {"message": "MCP Checker Web Management API"}

@app.get("/web_admin.html", response_class=FileResponse)
async def web_admin():
    # 获取当前目录下的web_admin.html文件
    current_dir = pathlib.Path(__file__).parent
    web_admin_path = current_dir / "web_admin.html"
    if web_admin_path.exists():
        return FileResponse(str(web_admin_path))
    else:
        raise HTTPException(status_code=404, detail="web_admin.html file not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)