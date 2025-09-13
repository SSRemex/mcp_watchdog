#!/usr/bin/env python3
"""
简单的MCP工具测试脚本
"""

import json
import sys
import os

# 添加当前目录到Python路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def create_test_files():
    """创建测试用的文件"""
    # 市场下载的MCP配置（无路径）
    market_mcp = {
        "name": "TestMarketMCP",
        "version": "1.0.0",
        "description": "A test MCP from market",
        "capabilities": ["tools"]
    }
    
    # 本地MCP配置（有路径）
    local_mcp = {
        "name": "TestLocalMCP",
        "version": "1.0.0",
        "description": "A test local MCP",
        "path": "/tmp/test_mcp.py",
        "capabilities": ["tools"]
    }
    
    # 创建测试MCP代码文件
    test_code = """
def hello_world():
    print("Hello, World!")
    return "Hello, World!"
"""
    
    with open("/tmp/test_mcp.py", "w") as f:
        f.write(test_code)
    
    # 保存配置文件
    with open("/tmp/market_mcp.json", "w") as f:
        json.dump(market_mcp, f, indent=2)
    
    with open("/tmp/local_mcp.json", "w") as f:
        json.dump(local_mcp, f, indent=2)
    
    print("测试文件已创建:")
    print("- /tmp/market_mcp.json (市场下载的MCP)")
    print("- /tmp/local_mcp.json (本地MCP)")
    print("- /tmp/test_mcp.py (本地MCP代码)")

def test_database_functions():
    """测试数据库功能"""
    try:
        # 导入数据库函数
        from src.db.database import init_database, is_malicious_hash, add_malicious_hash
        
        # 初始化数据库
        init_database()
        print("数据库初始化成功")
        
        # 测试添加恶意hash
        test_hash = "test_hash_value"
        add_malicious_hash(test_hash, "测试恶意hash")
        print(f"添加恶意hash: {test_hash}")
        
        # 测试检查恶意hash
        is_malicious = is_malicious_hash(test_hash)
        print(f"检查hash是否恶意: {is_malicious}")
        
        print("数据库功能测试完成")
        
    except Exception as e:
        print(f"数据库测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    print("创建测试文件...")
    create_test_files()
    
    print("\n测试数据库功能...")
    test_database_functions()