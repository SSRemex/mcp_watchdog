import hashlib
from typing import Optional, Dict, Any, List
import sys
import pathlib

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from db.database import (
    is_malicious_hash, add_malicious_hash, record_static_detection, record_dynamic_detection
)

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
        record_static_detection(
            mcp_name=mcp_name,
            code_hash=code_hash,
            description=description,
            security_issues=["发现恶意代码签名"],
            config=config
        )
        
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
    record_static_detection(
        mcp_name=mcp_name,
        code_hash=code_hash,
        description=description,
        security_issues=security_issues,
        config=config
    )
    
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
    record_dynamic_detection(
        mcp_name=mcp_name,
        code_hash=code_hash,
        description=description,
        security_issues=security_issues,
        config=config,
        args=args,
        result=result
    )
    
    # 如果发现安全问题，添加到病毒库
    if security_issues:
        add_malicious_hash(code_hash, "动态检测发现安全问题")
    
    return {
        "status": "checked",
        "hash": code_hash,
        "security_issues_count": len(security_issues),
        "security_issues": security_issues
    }