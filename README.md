# MCP Watchdog

MCP Watchdog 是一个用于监控和检查 MCP (Model Context Protocol) 工具安全性的系统。它提供静态扫描、动态监控和 Web 管理界面，确保 MCP 工具在使用过程中的安全性。

## 项目结构

```
mcp_watchdog/
├── src/
│   ├── check_core/              # 核心检测逻辑
│   │   ├── detector.py          # 静态和动态检测实现
│   │   ├── mcp_checker.py       # MCP工具定义和注册
│   │   └── static_checker.py    # 静态代码扫描核心逻辑
│   ├── db/                      # 数据库操作
│   │   └── database.py          # 数据库操作实现
│   └── web/                     # Web管理界面
│       ├── app.py               # Web API接口
│       ├── web_admin.html       # Web管理界面HTML
│       └── web_admin.py         # Web管理界面实现
├── start_all.py                 # 启动所有服务
├── mcp_watchdog.py              # 程序入口文件，创建MCP实例
├── requirements.txt             # 项目依赖
└── .gitignore                   # Git忽略文件配置
```

## 功能特性

### 1. 静态扫描
- 对 MCP 工具进行静态代码分析，从市场导入的默认可信，仅对本地新增的 MCP 工具进行扫描
- 检查潜在的恶意代码模式
- 维护恶意代码 hash 库
- 支持全量扫描所有本地 MCP 工具

### 2. 动态监控
- 监控 MCP 工具的运行时行为
- 检查参数和返回值中的敏感信息
- 记录所有检测结果

### 3. Web 管理界面
- 提供友好的 Web 界面管理恶意代码库
- 查看和分析检测记录
- 实时监控 MCP 工具状态

### 4. 架构优化
- 入口文件 (`mcp_watchdog.py`) 负责创建MCP实例
- 核心逻辑 (`mcp_checker.py`) 负责工具定义和注册
- 检测实现 (`detector.py`) 负责具体的静态和动态检测
- 静态扫描核心逻辑 (`static_checker.py`) 负责MCP代码的静态分析
- 数据库操作 (`database.py`) 负责数据持久化

## 安装和使用

### 安装依赖
```bash
pip install -r requirements.txt
```

### 启动服务
```bash
python start_all.py
```

启动后，可以通过以下地址访问 Web 管理界面：
http://localhost:8000/web_admin.html

## 核心模块说明

### static_checker.py
这是静态检查的核心逻辑模块，主要功能包括：
- 解析MCP配置文件
- 读取本地MCP代码文件
- 执行静态代码分析
- 检测潜在的安全问题（危险函数调用、文件操作、网络操作等）
- 扫描所有本地MCP工具

### detector.py
包含静态和动态检测的实现：
- `static_check()`: 静态检测函数
- `dynamic_check()`: 动态检测函数

### mcp_checker.py
负责MCP工具的定义和注册，包含各种安全检查工具。

### database.py
负责数据库操作，包括恶意代码哈希的存储和检测记录的管理。

## 数据库结构

### 恶意代码哈希表 (malicious_hashes)
| 字段名 | 类型 | 描述 |
|--------|------|------|
| id | INTEGER | 主键 |
| hash_value | TEXT | 恶意代码的SHA256哈希值 |
| description | TEXT | 描述信息 |

### 检测记录表 (detection_records)
| 字段名 | 类型 | 描述 |
|--------|------|------|
| id | INTEGER | 主键 |
| timestamp | DATETIME | 检测时间 |
| mcp_name | TEXT | MCP工具名称 |
| code_hash | TEXT | 代码哈希值 |
| description | TEXT | 检测描述 |
| security_issues | TEXT | 安全问题（JSON格式） |
| config | TEXT | MCP配置（JSON格式） |

## API 接口

### 病毒库管理
- `GET /api/malicious-hashes` - 获取所有恶意代码哈希
- `POST /api/malicious-hashes` - 添加恶意代码哈希
- `DELETE /api/malicious-hashes/{hash_value}` - 删除恶意代码哈希

### 检测记录管理
- `GET /api/detection-records` - 获取所有检测记录
- `DELETE /api/detection-records/{id}` - 删除检测记录

### 统计信息
- `GET /api/stats` - 获取统计信息

## 安全检查流程

### 市场下载的 MCP
1. 对 MCP 配置信息计算 hash
2. 检查 hash 是否在病毒库中
3. 记录检测结果

### 本地 MCP
1. 对 MCP 代码文件计算 hash
2. 检查 hash 是否在病毒库中
3. 使用大模型对代码进行深度审计（预留功能）
4. 记录检测结果