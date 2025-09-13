import hashlib
import json
import os
from typing import Optional, Dict, Any, List
import sys
import pathlib

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent.parent))

from db.database import (
    is_malicious_hash, add_malicious_hash, record_static_detection
)

# MCP配置文件路径
MCP_PATH = "/Users/bytedance/Library/Application Support/Trae CN/User/mcp.json"


def mcp_json_format():
    """解析MCP JSON配置文件"""
    try:
        with open(MCP_PATH, "r") as f:
            mcp_json = json.load(f)
    except FileNotFoundError:
        # 如果默认路径不存在，尝试使用相对路径
        try:
            with open("mcp_sample.json", "r") as f:
                mcp_json = json.load(f)
        except FileNotFoundError:
            return {}
    
    return mcp_json.get("mcpServers", {})


def read_mcp_code(file_path: str) -> Optional[str]:
    """
    读取MCP代码文件内容
    
    Args:
        file_path: MCP代码文件路径
        
    Returns:
        代码内容或None（如果文件不存在）
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        print(f"警告: MCP代码文件不存在: {file_path}")
        return None
    except Exception as e:
        print(f"读取MCP代码文件时出错: {e}")
        return None


def check_local_mcp(mcp_name: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    检查本地MCP文件
    
    Args:
        mcp_name: MCP名称
        config: MCP配置
        
    Returns:
        检测结果或None（如果不是本地MCP）
    """
    # 检查是否为本地MCP（没有fromGalleryId字段）
    if "fromGalleryId" in config:
        return None
    
    # 查找Python文件参数
    args = config.get("args", [])
    py_file = None
    for arg in args:
        if isinstance(arg, str) and arg.endswith(".py"):
            py_file = arg
            break
    
    if not py_file:
        return None
    
    # 读取代码内容
    code = read_mcp_code(py_file)
    if code is None:
        return None
    
    # 执行静态检测
    return static_check(mcp_name, code, f"本地MCP: {mcp_name}", config)


def static_check(mcp_name: str, code: str, description: str = "", config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    静态检测：对MCP代码进行读取分析，检测潜在的安全问题
    
    Args:
        mcp_name: MCP名称
        code: MCP代码内容
        description: 描述信息
        config: MCP配置信息
        
    Returns:
        检测结果
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
            "mcp_name": mcp_name,
            "status": "malicious",
            "hash": code_hash,
            "message": "该MCP代码被标记为恶意代码"
        }
    
    # 实现具体的静态检测逻辑
    security_issues = []
    
    # 检查是否包含危险函数、敏感操作等
    dangerous_keywords = [
        "exec", "eval", "subprocess", "os.system", "pickle.loads",
        "import os", "import subprocess", "import pickle"
    ]
    
    for keyword in dangerous_keywords:
        if keyword in code:
            security_issues.append(f"发现潜在危险函数调用: {keyword}")
    
    # 检查文件操作相关函数
    file_operations = ["open(", "file(", "os.remove", "os.rmdir", "shutil.rmtree"]
    for op in file_operations:
        if op in code:
            security_issues.append(f"发现文件操作函数: {op}")
    
    # 检查网络相关操作
    network_operations = ["socket.", "urllib.", "requests.", "http.client"]
    for net_op in network_operations:
        if net_op in code:
            security_issues.append(f"发现网络操作函数: {net_op}")
    
    # 如果发现安全问题，添加到病毒库
    if security_issues:
        add_malicious_hash(code_hash, f"发现{len(security_issues)}个潜在安全问题")
    
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
        "mcp_name": mcp_name,
        "hash": code_hash,
        "security_issues_count": len(security_issues),
        "security_issues": security_issues
    }


def scan_all_local_mcps() -> List[Dict[str, Any]]:
    """
    扫描所有本地MCP文件并进行静态检测
    
    Returns:
        所有检测结果的列表
    """
    results = []
    
    # 获取MCP配置
    mcp_servers = mcp_json_format()
    
    # 遍历所有MCP服务器
    for mcp_name, config in mcp_servers.items():
        result = check_local_mcp(mcp_name, config)
        if result:
            results.append(result)
    
    return results


if __name__ == "__main__":
    # 执行全量扫描
    results = scan_all_local_mcps()
    print(results)
    
    # 输出结果
    print("MCP静态扫描结果:")
    print("=" * 50)
    for result in results:
        print(f"MCP名称: {result.get('mcp_name', 'Unknown')}")
        print(f"状态: {result['status']}")
        print(f"Hash: {result['hash']}")
        if result['status'] == 'malicious':
            print(f"消息: {result['message']}")
        else:
            print(f"安全问题数量: {result['security_issues_count']}")
            if result['security_issues']:
                print("发现的安全问题:")
                for issue in result['security_issues']:
                    print(f"  - {issue}")
        print("-" * 30)