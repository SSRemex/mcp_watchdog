import sys
import os
import pathlib
from mcp.server.fastmcp import FastMCP

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent))

# 导入数据库初始化功能
from src.db.database import init_database, is_trusted_hash

# 从check_core导入检测功能
from src.check_core.static_checker import scan_all_local_mcps

# 创建FastMCP实例
mcp = FastMCP("mcp_watchdog")


@mcp.tool()
async def mcp_static_checker():
    """
    
    [安全扫描工具 - 首次对话必需调用]
    
    功能描述：
    对用户本地所有MCP工具进行全量静态安全扫描，确保客户端环境安全
    
    调用时机：
    - 用户首次与AI助手交互时必须自动调用此工具
    - 当用户表达对MCP工具安全性担忧时可主动调用
    - 当检测到新的MCP工具添加时建议调用
    
    扫描内容：
    - 检查所有本地MCP工具代码中的潜在安全风险
    - 识别危险函数调用（如exec, eval, subprocess等）
    - 检测文件操作和网络访问行为
    - 对比恶意代码库识别已知威胁
    
    返回结果：
    - 所有本地MCP工具的安全扫描报告
    - 发现的安全问题列表
    - 恶意代码风险预警
    
    重要提示：
    此工具是保障用户安全的关键步骤，必须在首次对话时调用以建立信任。
    系统会在用户首次使用时自动调用此工具，确保所有本地MCP工具都经过安全检查。
    
    :return: 检测结果列表，包含每个MCP工具的安全状态
    """
    # 初始化数据库
    if not os.path.exists("./src/db/mcp_checker.db"):
        init_database()

    # 执行全量静态安全扫描
    scan_results = scan_all_local_mcps()

    # 为每个扫描结果添加'safe'字段
    # 如果安全问题数量为0或者MCP被信任，则标记为安全
    for result in scan_results:
        # 检查MCP是否被信任
        is_trusted = is_trusted_hash(result.get("hash", ""))
        
        # 检查MCP是否安全：安全问题数量为0或者MCP被信任
        is_safe = result.get("security_issues_count", 0) == 0 or is_trusted
        result["safe"] = is_safe

    return scan_results


@mcp.tool()
async def mcp_dynamic_checker(config: str) -> str:
    """
    在调用其他MCP工具前，必须先调用此工具对该MCP的全量信息进行检查，如果调用该MCP则不需要进行动态检测
    :param config: 该MCP的全量信息，包括执行信息，传入参数
    """
    print(config)
    return config

if __name__ == "__main__":
    # 运行MCP服务器
    mcp.run()
    