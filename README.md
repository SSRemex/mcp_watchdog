# MCP Watchdog
安全是任何领域都绕不开的话题。随着MCP的发展，各种针对MCP用户的投毒、数据窃取等攻击行为，如同PC的木马病毒一样日益见长，潜在巨大的安全风险，当前仍属于安全真空。

MCP Watchdog 是一个用于检查代码安全性的静态扫描系统。它提供静态代码分析和 Web 管理界面，帮助识别和管理潜在的安全风险。通过静态检测进行事前防御，并记录检测日志实现事后追溯复盘，配备病毒库用于常态化防护管理，从而实现用户本地MCP全方位检测防护。

## 项目结构

```
mcp_watchdog/
├── src/
│   ├── check_core/              # 核心检测逻辑
│   │   └── static_checker.py    # 静态代码扫描核心逻辑
│   ├── db/                      # 数据库操作
│   │   └── database.py          # 数据库操作实现
│   └── web/                     # Web管理界面
│       ├── app.py               # Web API接口
│       └── web.html             # Web管理界面HTML
├── start_all.py                 # 启动所有服务
├── mcp_watchdog.py              # 程序入口文件
├── requirements.txt             # 项目依赖
└── .gitignore                   # Git忽略文件配置
```

## 功能特性

### 1. 静态扫描
- 对代码进行静态分析
- 检查潜在的恶意代码模式
- 维护恶意代码 hash 库
- 支持全量扫描
- 避免重复检测，提高效率

### 2. Web 管理界面
- 提供友好的 Web 界面管理恶意代码库
- 查看和分析检测记录
- 每个代码哈希只显示最新的检测记录，保持界面整洁
- 支持查看安全问题详情

### 3. 架构优化
- 入口文件 (`mcp_watchdog.py`) 负责创建系统实例
- 静态扫描核心逻辑 (`static_checker.py`) 负责代码的静态分析
- 数据库操作 (`database.py`) 负责数据持久化
- 统一东八区时间显示

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
http://localhost:8000/

## 核心模块说明

### static_checker.py
这是静态检查的核心逻辑模块，主要功能包括：
- 解析配置文件
- 读取代码文件
- 执行静态代码分析
- 检测潜在的安全问题（危险函数调用、文件操作、网络操作等）
- 避免重复检测相同哈希的代码

### database.py
负责数据库操作，包括：
- 恶意代码哈希的存储和管理
- 检测记录的存储和查询
- 支持按哈希值查询检测记录
- 统一使用东八区时间戳

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
| timestamp | DATETIME | 检测时间（东八区） |
| code_hash | TEXT | 代码哈希值 |
| description | TEXT | 检测描述 |
| security_issues | TEXT | 安全问题（JSON格式） |
| config | TEXT | 配置（JSON格式） |
| from_cache | BOOLEAN | 是否来自缓存 |

## API 接口

### 病毒库管理
- `GET /api/malicious-hashes` - 获取所有恶意代码哈希
- `POST /api/malicious-hashes` - 添加恶意代码哈希
- `DELETE /api/malicious-hashes/{hash_value}` - 删除恶意代码哈希

### 检测记录管理
- `GET /api/detection-records` - 获取所有检测记录
- `GET /api/detection-records?unique_hash=true` - 获取每个哈希的最新检测记录
- `DELETE /api/detection-records/{id}` - 删除检测记录

### 统计信息
- `GET /api/stats` - 获取统计信息

## 安全检查流程

1. 对代码文件计算 hash
2. 检查数据库中是否已有该 hash 的检测记录
3. 如有记录，直接返回缓存结果
4. 如无记录，检查 hash 是否在病毒库中
5. 执行静态代码分析
6. 记录检测结果