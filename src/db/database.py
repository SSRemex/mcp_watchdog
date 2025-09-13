import sqlite3
import json
import datetime
import hashlib
from typing import Optional, Dict, Any, List
import os

# 数据库文件路径
DB_FILE = os.path.join(os.path.dirname(__file__), "mcp_checker.db")

def get_db_connection():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """初始化数据库表"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 创建病毒库表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS virus_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            description TEXT,
            added_at TIMESTAMP
        )
    ''')
    
    # 创建检测记录表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mcp_name TEXT NOT NULL,
            hash TEXT NOT NULL,
            description TEXT,
            security_issues TEXT,
            config TEXT,
            args TEXT,
            result TEXT,
            detection_type TEXT,  -- 'static' or 'dynamic'
            detected_at TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# 检查hash是否在病毒库中
def is_malicious_hash(code_hash: str) -> bool:
    """检查给定的hash是否在病毒库中"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM virus_signatures WHERE hash = ?", (code_hash,))
    count = cursor.fetchone()[0]
    
    conn.close()
    return count > 0

# 添加恶意hash到病毒库
def add_malicious_hash(code_hash: str, description: str = ""):
    """添加恶意hash到病毒库"""
    
    # 在程序中生成当前时间戳
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    current_time = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO virus_signatures (hash, description, added_at) VALUES (?, ?, ?)",
            (code_hash, description, current_time)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"添加恶意hash时出错: {e}")
    finally:
        conn.close()

# 获取所有恶意hash
def get_malicious_hashes() -> list:
    """获取所有恶意hash"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT hash, description, added_at FROM virus_signatures")
    results = cursor.fetchall()
    
    conn.close()
    return [{"hash": row[0], "description": row[1], "added_at": row[2]} for row in results]

# 获取检测记录
def get_detection_records(limit: int = 100) -> list:
    """从数据库获取检测记录"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, mcp_name, hash, description, security_issues, config, args, result, detection_type, detected_at
        FROM detection_records
        ORDER BY detected_at DESC
        LIMIT ?
    ''', (limit,))
    
    results = cursor.fetchall()
    conn.close()
    
    records = []
    for row in results:
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
    
    return records

# 记录静态检测结果
def record_static_detection(mcp_name: str, code_hash: str, description: str, security_issues: List[str], config: Optional[Dict[str, Any]] = None):
    """记录静态检测结果"""
    
    # 在程序中生成当前时间戳
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    current_time = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO detection_records 
            (mcp_name, hash, description, security_issues, config, detection_type, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            mcp_name, 
            code_hash, 
            description, 
            json.dumps(security_issues), 
            json.dumps(config) if config else None,
            "static",
            current_time
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"记录检测结果时出错: {e}")
    finally:
        conn.close()

# 记录动态检测结果
def record_dynamic_detection(mcp_name: str, code_hash: str, description: str, security_issues: List[str], 
                           config: Optional[Dict[str, Any]] = None, args: Optional[Dict[str, Any]] = None, 
                           result: Optional[Any] = None):
    """记录动态检测结果"""

    # 在程序中生成当前时间戳
    tz_utc_8 = datetime.timezone(datetime.timedelta(hours=8))
    current_time = datetime.datetime.now(tz_utc_8).strftime("%Y-%m-%d %H:%M:%S")
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO detection_records 
            (mcp_name, hash, description, security_issues, config, args, result, detection_type, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            mcp_name, 
            code_hash, 
            description, 
            json.dumps(security_issues), 
            json.dumps(config) if config else None,
            json.dumps(args) if args else None,
            json.dumps(result) if result else None,
            "dynamic",
            current_time
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"记录检测结果时出错: {e}")
    finally:
        conn.close()

# 删除恶意hash
def remove_malicious_hash(hash_value: str) -> bool:
    """从病毒库中移除恶意hash"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM virus_signatures WHERE hash = ?", (hash_value,))
        conn.commit()
        deleted_count = cursor.rowcount
        return deleted_count > 0
    except sqlite3.Error as e:
        print(f"删除时出错: {e}")
        return False
    finally:
        conn.close()

# 删除检测记录
def delete_detection_record(record_id: int) -> bool:
    """删除检测记录"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM detection_records WHERE id = ?", (record_id,))
        conn.commit()
        deleted_count = cursor.rowcount
        return deleted_count > 0
    except sqlite3.Error as e:
        print(f"删除时出错: {e}")
        return False
    finally:
        conn.close()

# 获取统计信息
def get_stats():
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
        
        # 获取恶意文件数量
        cursor.execute("SELECT COUNT(*) FROM detection_records WHERE hash IN (SELECT hash FROM virus_signatures)")
        malicious_count = cursor.fetchone()[0]
        
        # 获取安全文件数量
        safe_count = record_count - malicious_count
        
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
        
        # 获取病毒库版本（最新添加的记录时间）
        cursor.execute("SELECT MAX(added_at) FROM virus_signatures")
        virus_db_version = cursor.fetchone()[0] or "-"
        
        return {
            "virus_signatures_count": virus_count,
            "detection_records_count": record_count,
            "malicious_count": malicious_count,
            "safe_count": safe_count,
            "total_detections": record_count,
            "virus_db_version": virus_db_version,
            "recent_records": recent_records
        }
    except sqlite3.Error as e:
        print(f"查询时出错: {e}")
        return {}
    finally:
        conn.close()