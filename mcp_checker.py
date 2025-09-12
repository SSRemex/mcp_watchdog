import hashlib
import json
import sqlite3
import os
from typing import Optional, Dict, Any, Set
from mcp.server.fastmcp import FastMCP


# 数据库文件路径
DB_FILE = "mcp_checker.db"

# 初始化数据库
def init_database():
    """初始化数据库表"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # 创建病毒库表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS virus_signatures (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            description TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

# 初始化数据库
init_database()

# gateway_server.py
"""
Minimal FastMCP server with:
 - pre_call(mcp_name, code, description, config)  <- gateway/hook
 - target_tool(payload)                            <- example target tool
Run: python gateway_server.py
(开发时可用 in-memory / stdio 客户端连接；部署时可启用 HTTP transport)
"""


mcp = FastMCP("mcp-gateway-demo")


@mcp.tool()
def pre_call(mcp_name: str, code: str, description: str = "", config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Gateway hook called BEFORE the actual target MCP call.
    收到元数据后可以做：日志、策略检查、动态改写 config、拒绝或允许调用等。
    返回任意 JSON-able 结构作为 ack / 指示。
    """
    # 最简单：打印并返回接受确认
    print("GATEWAY pre_call:", {"mcp_name": mcp_name, "description": description, "config": config})
    
    # 调用静态检测
    static_result = static_check(mcp_name, code, description, config)
    
    # 这里可以做更多：如校验 config、替换敏感字段、记录审计等
    return {
        "accepted": True, 
        "note": f"pre_call recorded for {mcp_name}",
        "static_check": static_result
    }


@mcp.tool()
def target_tool(payload: str) -> Dict[str, Any]:
    """示例目标工具：简单回显处理"""
    print("TARGET_TOOL called with:", payload)
    return {"ok": True, "echo": payload}


# 检查hash是否在病毒库中
def is_malicious_hash(code_hash: str) -> bool:
    """检查给定的hash是否在病毒库中"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM virus_signatures WHERE hash = ?", (code_hash,))
    count = cursor.fetchone()[0]
    
    conn.close()
    return count > 0

# 添加恶意hash到病毒库
def add_malicious_hash(code_hash: str, description: str = ""):
    """添加恶意hash到病毒库"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO virus_signatures (hash, description) VALUES (?, ?)",
            (code_hash, description)
        )
        conn.commit()
    except sqlite3.Error as e:
        print(f"添加恶意hash时出错: {e}")
    finally:
        conn.close()

# 获取所有恶意hash
def get_malicious_hashes() -> list:
    """获取所有恶意hash"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("SELECT hash, description, added_at FROM virus_signatures")
    results = cursor.fetchall()
    
    conn.close()
    return [{"hash": row[0], "description": row[1], "added_at": row[2]} for row in results]

# 静态检测函数
def static_check(mcp_name: str, code: str, description: str = "", config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    静态检测：在进行对话前，对所有的MCP代码进行读取分析，检测潜在的安全问题
    """
    # 计算代码的hash值
    code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
    
    # 检查是否在病毒库中
    if is_malicious_hash(code_hash):
        # 记录检测结果到数据库
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO detection_records 
                (mcp_name, hash, description, security_issues, config, detection_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                mcp_name, 
                code_hash, 
                description, 
                json.dumps(["发现恶意代码签名"]), 
                json.dumps(config) if config else None,
                "static"
            ))
            conn.commit()
        except sqlite3.Error as e:
            print(f"记录检测结果时出错: {e}")
        finally:
            conn.close()
        
        return {
            "status": "malicious",
            "hash": code_hash,
            "message": "该MCP代码被标记为恶意代码"
        }
    
    # 这里可以实现具体的静态检测逻辑
    # 例如：检查代码中是否包含危险函数、敏感操作等
    security_issues = []
    
    # 简单示例：检查是否包含一些危险关键字
    dangerous_keywords = ["exec", "eval", "subprocess", "os.system", "pickle.loads"]
    for keyword in dangerous_keywords:
        if keyword in code:
            security_issues.append(f"发现潜在危险函数调用: {keyword}")
    
    # 如果发现安全问题，添加到病毒库
    if security_issues:
        add_malicious_hash(code_hash, "发现潜在危险函数调用")
    
    # 记录检测结果到数据库
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO detection_records 
            (mcp_name, hash, description, security_issues, config, detection_type)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            mcp_name, 
            code_hash, 
            description, 
            json.dumps(security_issues), 
            json.dumps(config) if config else None,
            "static"
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"记录检测结果时出错: {e}")
    finally:
        conn.close()
    
    return {
        "status": "checked",
        "hash": code_hash,
        "security_issues_count": len(security_issues),
        "security_issues": security_issues
    }


# 动态检测函数
def dynamic_check(mcp_name: str, code: str, description: str = "", config: Optional[Dict[str, Any]] = None, 
                  args: Optional[Dict[str, Any]] = None, result: Optional[Any] = None) -> Dict[str, Any]:
    """
    动态检测：在大模型调用其他MCP时，调用该MCP并记录调用信息，
    对该MCP的传入参数、代码信息、配置信息、返回结果进行分析，对异常行为进行提醒
    """
    # 计算代码的hash值
    code_hash = hashlib.sha256(code.encode('utf-8')).hexdigest()
    
    # 这里可以实现具体的动态检测逻辑
    # 例如：检查参数是否包含敏感信息、返回结果是否异常等
    security_issues = []
    
    # 检查参数中是否包含敏感信息
    if args:
        sensitive_keywords = ["password", "secret", "token", "key", "credential"]
        for key in args.keys():
            for keyword in sensitive_keywords:
                if keyword in key.lower():
                    security_issues.append(f"参数中发现敏感字段: {key}")
    
    # 检查返回结果是否异常
    if result:
        # 简单示例：检查返回结果是否包含敏感信息
        result_str = str(result)
        sensitive_patterns = ["password", "secret", "token", "key"]
        for pattern in sensitive_patterns:
            if pattern in result_str.lower():
                security_issues.append(f"返回结果中发现敏感信息: {pattern}")
    
    # 记录检测结果到数据库
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO detection_records 
            (mcp_name, hash, description, security_issues, config, args, result, detection_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            mcp_name, 
            code_hash, 
            description, 
            json.dumps(security_issues), 
            json.dumps(config) if config else None,
            json.dumps(args) if args else None,
            json.dumps(result) if result else None,
            "dynamic"
        ))
        conn.commit()
    except sqlite3.Error as e:
        print(f"记录检测结果时出错: {e}")
    finally:
        conn.close()
    
    # 如果发现安全问题，添加到病毒库
    if security_issues:
        add_malicious_hash(code_hash, "动态检测发现安全问题")
    
    return {
        "status": "checked",
        "hash": code_hash,
        "security_issues_count": len(security_issues),
        "security_issues": security_issues
    }


# 获取检测记录
def get_detection_records(limit: int = 100) -> list:
    """从数据库获取检测记录"""
    conn = sqlite3.connect(DB_FILE)
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

@mcp.tool()
def get_detection_reports() -> Dict[str, Any]:
    """获取所有检测报告"""
    records = get_detection_records()
    malicious_hashes = get_malicious_hashes()
    
    return {
        "detection_records_count": len(records),
        "malicious_hashes_count": len(malicious_hashes),
        "recent_records": records[:10],  # 只返回最近10条记录
        "malicious_hashes": malicious_hashes
    }

if __name__ == "__main__":
    # 直接运行服务器（开发环境中 mcp.run() 会自动选择合适 transport）
    # 若需要 HTTP/SSE/StreamableHTTP，请参考 SDK 文档部署选项（可绑定本地端口或集成到 ASGI）。
    mcp.run()

@mcp.tool()
def add_malicious_hash_tool(hash_value: str, description: str = "") -> Dict[str, Any]:
    """添加恶意hash到病毒库的工具"""
    add_malicious_hash(hash_value, description)
    return {
        "status": "success",
        "message": f"已将hash {hash_value} 添加到病毒库"
    }

@mcp.tool()
def remove_malicious_hash(hash_value: str) -> Dict[str, Any]:
    """从病毒库中移除恶意hash"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM virus_signatures WHERE hash = ?", (hash_value,))
        conn.commit()
        deleted_count = cursor.rowcount
    except sqlite3.Error as e:
        conn.close()
        return {
            "status": "error",
            "message": f"删除时出错: {e}"
        }
    finally:
        conn.close()
    
    if deleted_count > 0:
        return {
            "status": "success",
            "message": f"已从病毒库中移除hash {hash_value}"
        }
    else:
        return {
            "status": "not_found",
            "message": f"病毒库中未找到hash {hash_value}"
        }

@mcp.tool()
def get_malicious_hashes_tool() -> Dict[str, Any]:
    """获取所有恶意hash的工具"""
    hashes = get_malicious_hashes()
    return {
        "status": "success",
        "count": len(hashes),
        "hashes": hashes
    }
