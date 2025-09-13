import hashlib
import json
import os
from typing import Optional, Dict, Any
import sys
import pathlib

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from db.database import (
    get_malicious_hashes, get_detection_records
)
from check_core.detector import static_check, dynamic_check

def register_tools(mcp):
    """注册所有工具到MCP实例"""
    
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

    @mcp.tool()
    def add_malicious_hash_tool(hash_value: str, description: str = "") -> Dict[str, Any]:
        """添加恶意hash到病毒库的工具"""
        from db.database import add_malicious_hash
        add_malicious_hash(hash_value, description)
        return {
            "status": "success",
            "message": f"已将hash {hash_value} 添加到病毒库"
        }

    @mcp.tool()
    def remove_malicious_hash_tool(hash_value: str) -> Dict[str, Any]:
        """从病毒库中移除恶意hash"""
        # 实现删除逻辑
        from src.db.database import remove_malicious_hash
        success = remove_malicious_hash(hash_value)
        
        if success:
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

# 保持向后兼容性
if __name__ == "__main__":
    # 直接运行服务器（开发环境中 mcp.run() 会自动选择合适 transport）
    # 若需要 HTTP/SSE/StreamableHTTP，请参考 SDK 文档部署选项（可绑定本地端口或集成到 ASGI）。
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("mcp-gateway-demo")
    register_tools(mcp)
    mcp.run()