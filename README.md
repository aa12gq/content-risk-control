# 内容审核风控系统

基于 Golang 实现的具备上下文语义理解能力的内容审核风控系统，提供高性能 HTTP/gRPC 接口。

## 技术亮点

- 支持本地部署开源大语言模型，无需云服务，降低成本
- 使用 Ollama 作为本地模型服务，支持 Llama 3 系列模型
- 集成上下文审核能力，能够检测对话中的骚扰、威胁等不良行为
- 完善的降级机制确保系统稳定性，即使模型服务不可用也能基于规则继续工作

## 为什么选择 Llama 3

本系统使用 Llama 3 作为核心模型，而不是更新的 Llama 3.1，主要基于以下考虑：

1. **资源效率**：Llama 3 在内容审核任务上已提供足够的性能，同时资源消耗更少
2. **更广泛的部署兼容性**：更低的资源需求使其能在更多环境中部署
3. **社区支持**：Llama 3 拥有更成熟的社区支持和丰富的优化方案
4. **模型稳定性**：经过更充分验证的模型，在生产环境中更稳定可靠
5. **性能权衡**：针对内容审核场景，Llama 3 的效率/性能比更优

在实际部署中，您也可以根据硬件条件和性能需求，灵活选择使用 Llama 3.1 或其他模型。修改配置文件中的 `model_name` 参数即可切换不同模型。

## 特点

1. **智能语义理解**：

   - 使用本地 LLM 模型（Llama 3）进行语义理解
   - 敏感内容检测，支持多种有害内容类型识别
   - 多种检测维度：侮辱、威胁、骚扰、仇恨言论等

2. **上下文分析**：

   - 支持对话历史分析，检测对话中的骚扰行为
   - 能够识别用户在对方拒绝后继续发送消息的行为

3. **多模块架构**：

   - 规则引擎（支持 JSON 格式灵活配置）
   - 内容检测服务（支持多种检测器）
   - 本地语义 NLP 分析（无需依赖云服务）
   - 多种专用检测器（敏感词、垃圾信息、骚扰内容等）

4. **高性能接口**：
   - 提供 gRPC 和 HTTP REST 接口
   - 支持单条检测和批量检测
   - 支持上下文检测

## 核心功能

1. **内容检测**

   - 敏感词检测：内置词库，可动态更新
   - 语义分析：基于本地 LLM 模型
   - 上下文审核：分析对话历史，识别骚扰行为
   - 垃圾信息过滤：识别广告、诈骗等内容

2. **系统架构**
   - 灵活的规则引擎
   - Redis 缓存支持（可选）
   - 完善的降级处理
   - 健康检查和监控

## 技术架构

- **语言**：Go 1.23+
- **接口**：gRPC、HTTP REST API
- **缓存**：Redis（可选）
- **NLP**：Ollama + Llama 3 模型

## 部署

### 环境要求

- Go 1.23 或更高版本
- Ollama（用于本地部署语言模型）
- Redis（可选，用于缓存）

### 安装步骤

1. 安装 Ollama

```bash
# macOS / Linux
curl -fsSL https://ollama.com/install.sh | sh

# 启动Ollama服务
ollama serve
```

2. 下载所需模型

```bash
# 下载Llama 3模型
ollama pull llama3
```

3. 配置系统

```yaml
# config/config.yaml
nlp_service:
  enabled: false # 关闭OpenAI云服务
  model_path: ./models/nlp_model
  server_port: 8010
  threshold: 0.6
  context_size: 5
  # 本地大语言模型配置
  use_local_llm: true
  local_llm_type: ollama
  local_llm_api: http://localhost:11434/api/chat
  model_name: llama3
```

4. 启动服务

```bash
# 启动主服务
go run cmd/server/main.go
```

5. 测试服务

```bash
# 使用测试脚本测试服务
./test_mac.sh
```

## 系统结构

```
.
├── api/            # 接口定义
│   └── proto/      # gRPC协议文件
├── cmd/            # 命令行工具
│   ├── server/     # 服务器入口
│   └── client/     # 客户端工具
├── config/         # 配置文件
├── internal/       # 内部包
│   ├── app/        # 应用层
│   │   ├── config/ # 配置加载
│   │   ├── model/  # 数据模型
│   │   └── service/# 服务实现
│   └── pkg/        # 工具包
│       └── detector/# 内容检测器
└── test_mac.sh     # 测试脚本
```

## 功能测试

系统提供了测试脚本用于验证功能：

```bash
# 运行测试脚本
./test_mac.sh
```

测试内容包括：

- 健康检查
- 正常内容检测
- 敏感内容检测
- 上下文骚扰行为检测

## 贡献

欢迎提交 PR 和 Issue！

## 许可证

MIT
