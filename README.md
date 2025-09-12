MCP Checker
工具描述：
实现一个python mcp工具，用于检测MCP静态&动态场景下的安全性
功能：
1. 静态检测：在进行对话前，对所有的MCP代码进行读取分析，检测潜在的安全问题，记录hash值并打标（静态场景），已打标的代码不再进行检测，并返回检测报告
2. 动态检测：在大模型调用其他MCP时，调用该MCP并记录调用信息，对该MCP的传入参数、代码信息、配置信息、返回结果进行分析，对异常行为进行提醒，记录hash值并打标（动态场景），已打标的MCP不再进行分析
3. 要有病毒库管理，记录恶意hash值，用于静态检测（WEB管理，操作同一个数据库）
4. 检测记录管理，记录所有检测信息（WEB管理，操作同一个数据库）

使用方法：
1. 运行MCP服务器：`python mcp_checker.py`
2. 该工具会自动拦截所有MCP调用并进行静态检测
3. 可通过`get_detection_reports`工具获取所有检测报告
4. 运行Web管理界面：`python app.py`，然后在浏览器中打开 http://localhost:8000/web_admin.html
5. 或者使用启动脚本同时启动所有服务：`python start_all.py`

API接口：
- `pre_call(mcp_name, code, description, config)`: 网关钩子，在实际MCP调用前触发，执行静态检测
- `static_check(mcp_name, code, description, config)`: 静态检测函数
- `dynamic_check(mcp_name, code, description, config, args, result)`: 动态检测函数
- `get_detection_reports()`: 获取所有检测报告
- `add_malicious_hash_tool(hash_value, description)`: 添加恶意hash到病毒库
- `remove_malicious_hash(hash_value)`: 从病毒库中移除恶意hash
- `get_malicious_hashes_tool()`: 获取所有恶意hash

Web管理API接口：
- `POST /api/virus-signatures`: 添加恶意hash到病毒库
- `DELETE /api/virus-signatures/{hash_value}`: 从病毒库中移除恶意hash
- `GET /api/virus-signatures`: 获取所有恶意hash
- `GET /api/detection-records`: 获取检测记录
- `DELETE /api/detection-records/{record_id}`: 删除检测记录
- `GET /api/stats`: 获取统计信息

检测内容：
- 静态检测：检查代码中是否包含危险函数调用（如exec, eval等），并与病毒库中的恶意hash进行比对
- 动态检测：检查参数和返回结果中是否包含敏感信息（如password, token等）

数据库说明：
- 使用SQLite数据库存储病毒库和检测记录
- 病毒库表(virus_signatures)：存储已知的恶意代码hash值
- 检测记录表(detection_records)：存储所有检测历史记录

参考链接：https://github.com/modelcontextprotocol/python-sdk



---
MCP WatchDog 是一款专为 Model Context Protocol (MCP) 设计的安全检测工具，旨在帮助开发者和安全研究人员识别和防范潜在的安全威胁。该工具具备以下核心功能：

1. 静态检测 在MCP代码执行前，全面分析代码内容，检测潜在的安全风险，如危险函数调用（exec, eval等），并与内置病毒库中的恶意hash进行比对，确保代码安全。

2. 动态检测 在MCP运行时，实时监控其调用参数、配置信息和返回结果，识别异常行为并及时提醒，有效防范动态攻击。

3. 病毒库管理 提供完善的病毒库管理功能，支持添加、删除和查询恶意hash值，构建个性化的安全防护体系。

4. 检测记录管理 详细记录所有检测历史，便于追溯和分析安全事件，为安全审计提供可靠数据支持。

MCP Checker 还配备了直观的Web管理界面，用户可以通过浏览器轻松管理病毒库和查看检测记录。同时，它提供了丰富的API接口，方便与其他系统集成。使用MCP Checker，让您的MCP应用更加安全可靠。