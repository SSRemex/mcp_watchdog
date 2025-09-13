from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import json
import os
from typing import List, Optional
import sys
import pathlib

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from db.database import (
    init_database, get_stats, get_malicious_hashes, add_malicious_hash,
    remove_malicious_hash, get_detection_records, delete_detection_record
)

app = FastAPI()

# 初始化数据库
init_database()

# 读取web_admin.html文件
def get_web_admin_html():
    """读取web管理界面HTML文件"""
    html_file_path = os.path.join(os.path.dirname(__file__), '..', '..', 'web_admin.html')
    try:
        with open(html_file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "<h1>Web管理界面文件未找到</h1>"

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """返回Web管理界面"""
    return get_web_admin_html()

@app.get("/web_admin.html", response_class=HTMLResponse)
async def read_web_admin():
    """返回Web管理界面"""
    return get_web_admin_html()

# API路由
@app.get("/api/stats")
async def api_stats():
    """获取统计信息"""
    return get_stats()

@app.get("/api/virus-signatures")
async def api_virus_signatures(page: int = 1, page_size: int = 20, search: Optional[str] = None):
    """获取病毒库列表"""
    all_signatures = get_malicious_hashes()
    
    # 搜索过滤
    if search:
        all_signatures = [s for s in all_signatures if search.lower() in s['hash'].lower() or 
                         (s['description'] and search.lower() in s['description'].lower())]
    
    # 分页处理
    total = len(all_signatures)
    start = (page - 1) * page_size
    end = start + page_size
    signatures = all_signatures[start:end]
    
    return {
        "signatures": signatures,
        "total": total,
        "page": page,
        "page_size": page_size
    }

@app.post("/api/virus-signatures")
async def api_add_virus_signature(hash: str, description: str = ""):
    """添加恶意hash到病毒库"""
    try:
        add_malicious_hash(hash, description)
        return {"message": f"已将hash {hash} 添加到病毒库"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/virus-signatures/{hash_value}")
async def api_remove_virus_signature(hash_value: str):
    """从病毒库中移除恶意hash"""
    try:
        success = remove_malicious_hash(hash_value)
        if success:
            return {"message": f"已从病毒库中移除hash {hash_value}"}
        else:
            raise HTTPException(status_code=404, detail="未找到指定的hash")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/detection-records")
async def api_detection_records(
    page: int = 1, 
    page_size: int = 20, 
    search: Optional[str] = None,
    detection_type: Optional[str] = None
):
    """获取检测记录列表"""
    all_records = get_detection_records(limit=1000)  # 获取足够多的记录用于过滤
    
    # 搜索过滤
    if search:
        all_records = [r for r in all_records if search.lower() in r['mcp_name'].lower() or 
                      search.lower() in r['hash'].lower()]
    
    # 类型过滤
    if detection_type:
        all_records = [r for r in all_records if r['detection_type'] == detection_type]
    
    # 分页处理
    total = len(all_records)
    start = (page - 1) * page_size
    end = start + page_size
    records = all_records[start:end]
    
    # 为每条记录添加源代码信息（如果有的话）
    for record in records:
        # 如果是静态检测且有配置信息，尝试获取源代码路径
        if record['detection_type'] == 'static' and record['config']:
            args = record['config'].get('args', [])
            for arg in args:
                if isinstance(arg, str) and arg.endswith('.py'):
                    # 尝试读取源代码文件
                    try:
                        with open(arg, 'r', encoding='utf-8') as f:
                            record['source_code'] = f.read()
                        break
                    except:
                        record['source_code'] = None
        # 如果是动态检测且有参数信息，添加参数信息
        elif record['detection_type'] == 'dynamic' and record['args']:
            record['execution_args'] = record['args']
    
    return {
        "records": records,
        "total": total,
        "page": page,
        "page_size": page_size
    }

@app.delete("/api/detection-records/{record_id}")
async def api_delete_detection_record(record_id: int):
    """删除检测记录"""
    try:
        success = delete_detection_record(record_id)
        if success:
            return {"message": f"已删除检测记录 {record_id}"}
        else:
            raise HTTPException(status_code=404, detail="未找到指定的检测记录")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))