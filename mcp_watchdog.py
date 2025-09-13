import sys
import os
import pathlib
from mcp.server.fastmcp import FastMCP

# 添加src目录到Python路径
sys.path.append(str(pathlib.Path(__file__).parent))

# 从check_core导入检测功能
from src.check_core.mcp_checker import register_tools
from db.database import init_database

# 初始化数据库
init_database()

# 创建FastMCP实例
mcp = FastMCP("mcp-gateway-demo")

# 注册工具
register_tools(mcp)

if __name__ == "__main__":
    # 运行MCP服务器
    mcp.run()