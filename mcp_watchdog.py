import sys
import os
import pathlib
from mcp.server.fastmcp import FastMCP

from src.db.database import init_database

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent))

# 从check_core导入检测功能
from src.check_core.static_checker import scan_all_local_mcps

# 创建FastMCP实例
mcp = FastMCP("mcp_watchdog")


@mcp.tool()
async def mcp_static_checker():
    """
    在进行第一次对话时必须调用，对本地mcp进行全量静态扫描
    :return: 检测结果    
    """
    # 初始化数据库
    if not os.path.exists("./src/db/mcp_checker.db"):
        init_database()

    list = scan_all_local_mcps()

    return list

    
    


if __name__ == "__main__":
    # 运行MCP服务器
    if not os.path.exists("./src/db/mcp_checker.db"):
        init_database()

    list = scan_all_local_mcps()
    print(list)
    