import subprocess
import sys
import os

def main():
    """Web管理界面"""
    print("正在启动MCP Checker服务...")
    
    # 获取当前目录
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 启动Web管理界面
    web_process = subprocess.Popen([
        "python3", 
        os.path.join(current_dir, "src", "web", "app.py")
    ], cwd=current_dir)
    
    print(f"Web管理界面已启动 (PID: {web_process.pid})")
    print("请在浏览器中打开以下地址访问管理界面:")
    print("http://localhost:8000/web_admin.html")
    print("\n按 Ctrl+C 停止所有服务")
    
    try:
        # 等待任一进程结束
        web_process.wait()
    except KeyboardInterrupt:
        print("\n正在停止所有服务...")
        web_process.terminate()
        web_process.wait()
        print("所有服务已停止")

if __name__ == "__main__":
    main()