package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// SemanticNLPDetector 基于本地部署的语义NLP检测器
type SemanticNLPDetector struct {
	mutex        sync.RWMutex // 读写锁
	httpClient   *http.Client // HTTP客户端
	apiEndpoint  string       // 本地模型API端点
	threshold    float32      // 阈值
	contextSize  int          // 上下文大小
	categories   []string     // 分类类别
	fallbackMode bool         // 降级模式标志
}

// OllamaChatRequest 结构定义Ollama模型输入
type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream,omitempty"`
	Options  OllamaOption    `json:"options,omitempty"`
}

// OllamaMessage 定义Ollama对话消息
type OllamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OllamaOption 提供Ollama请求选项
type OllamaOption struct {
	Temperature float32 `json:"temperature,omitempty"`
	MaxTokens   int     `json:"max_tokens,omitempty"`
}

// OllamaChatResponse 定义Ollama模型输出
type OllamaChatResponse struct {
	Model     string        `json:"model"`
	CreatedAt string        `json:"created_at"`
	Message   OllamaMessage `json:"message"`
	Done      bool          `json:"done"`
	Error     string        `json:"error,omitempty"`
}

// SemanticAnalysisResult 语义分析结果结构
type SemanticAnalysisResult struct {
	IsToxic     bool               `json:"is_toxic"`
	Categories  map[string]float32 `json:"categories"`
	Explanation string             `json:"explanation"`
	Intent      string             `json:"intent"`
	Sentiment   string             `json:"sentiment"`
	Risk        float32            `json:"risk_score"`
}

// NewSemanticNLPDetector 创建语义NLP检测器
func NewSemanticNLPDetector(apiEndpoint string, threshold float32, contextSize int) (*SemanticNLPDetector, error) {
	if apiEndpoint == "" {
		// 默认本地Ollama端点
		apiEndpoint = "http://localhost:11434/api/chat"
	}

	transport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	detector := &SemanticNLPDetector{
		apiEndpoint: apiEndpoint,
		httpClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		threshold:   threshold,
		contextSize: contextSize,
		categories: []string{
			"insult",
			"threat",
			"harassment",
			"hate_speech",
			"self_harm",
			"sexual",
			"violence",
		},
	}

	// 测试API连接
	err := detector.testConnection()
	if err != nil {
		// 连接失败时启用降级模式
		detector.fallbackMode = true
		return detector, fmt.Errorf("本地NLP模型服务连接测试失败，启用降级模式: %w", err)
	}

	return detector, nil
}

// testConnection 测试与本地模型服务的连接
func (d *SemanticNLPDetector) testConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", strings.Replace(d.apiEndpoint, "/api/chat", "/api/tags", 1), nil)
	if err != nil {
		return fmt.Errorf("创建测试请求失败: %w", err)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("连接本地模型服务失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("模型服务返回非200状态码: %d", resp.StatusCode)
	}

	return nil
}

// Detect 执行NLP检测
func (d *SemanticNLPDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	// 如果处于降级模式，使用基本的规则检测
	if d.fallbackMode {
		return d.fallbackDetect(ctx)
	}

	// 构建上下文
	userContent := ctx.Content
	contextContent := make([]string, 0, len(ctx.ContextItems))
	for _, item := range ctx.ContextItems {
		contextContent = append(contextContent, item.Content)
	}

	// 分析内容
	result, err := d.analyzeContent(userContent, contextContent)
	if err != nil {
		// 如果API调用失败，切换到降级模式
		d.fallbackMode = true
		return d.fallbackDetect(ctx)
	}

	// 将分析结果转换为风险项
	var risks []*model.RiskItem
	if result.IsToxic && result.Risk > d.threshold {
		riskItem := model.NewRiskItem(
			model.RiskTypeHarassment,
			result.Risk*100,
			result.Explanation,
		)

		// 添加分类详情
		for category, score := range result.Categories {
			if score > d.threshold {
				riskItem.Details[category] = fmt.Sprintf("%.2f", score)
			}
		}

		risks = append(risks, riskItem)
	}

	// 分析意图和情感
	if result.Intent != "" && result.Intent != "neutral" && result.Risk > d.threshold {
		intentRisk := model.NewRiskItem(
			d.getIntentRiskType(result.Intent),
			result.Risk*80,
			fmt.Sprintf("检测到%s意图", d.getIntentDescription(result.Intent)),
		)
		risks = append(risks, intentRisk)
	}

	// 检查上下文模式
	if len(contextContent) > 0 && d.hasContextualRisk(result, contextContent) {
		contextRisk := model.NewRiskItem(
			model.RiskTypeContextViolation,
			result.Risk*90,
			"检测到上下文相关的风险行为",
		)
		risks = append(risks, contextRisk)
	}

	return risks, nil
}

// analyzeContent 使用本地模型分析内容
func (d *SemanticNLPDetector) analyzeContent(content string, contexts []string) (*SemanticAnalysisResult, error) {
	systemPrompt := `你是一个内容安全分析专家，你需要分析用户输入的文本是否包含不安全内容，如侮辱、骚扰、威胁、仇恨言论等。
请分析用户提供的文本，并返回JSON格式的分析结果，包括：
- 是否有害（is_toxic）: true或false
- 分类（categories）: 可能的类别包括"insult", "threat", "harassment", "hate_speech", "self_harm", "sexual", "violence"，为每个相关类别提供0-1之间的分数
- 解释（explanation）: 简要解释判断理由
- 意图（intent）: "harmful", "neutral", "friendly"中的一个
- 情感（sentiment）: "negative", "neutral", "positive"中的一个
- 风险分数（risk_score）: 0-1之间的总体风险分数

必须严格按照JSON格式输出，不要输出任何其他内容！`

	var userInput string
	if len(contexts) > 0 {
		contextStr := strings.Join(contexts, "\n")
		userInput = fmt.Sprintf("上下文信息:\n%s\n\n待分析文本:\n%s", contextStr, content)
	} else {
		userInput = fmt.Sprintf("待分析文本:\n%s", content)
	}

	// 准备与本地模型的对话
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	chatReq := OllamaChatRequest{
		Model: "llama3", // 根据实际部署的模型调整
		Messages: []OllamaMessage{
			{
				Role:    "system",
				Content: systemPrompt,
			},
			{
				Role:    "user",
				Content: userInput,
			},
		},
		Options: OllamaOption{
			Temperature: 0.1,
			MaxTokens:   2048,
		},
	}

	reqBody, err := json.Marshal(chatReq)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.apiEndpoint, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("调用本地模型API失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return nil, fmt.Errorf("API返回错误状态码 %d: %s", resp.StatusCode, string(body))
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var chatResp OllamaChatResponse
	if err := json.Unmarshal(body, &chatResp); err != nil {
		return nil, fmt.Errorf("解析模型响应失败: %w", err)
	}

	if chatResp.Error != "" {
		return nil, fmt.Errorf("模型返回错误: %s", chatResp.Error)
	}

	// 解析分析结果
	var result SemanticAnalysisResult
	content = chatResp.Message.Content
	// 从文本中提取JSON部分
	if strings.Contains(content, "```json") && strings.Contains(content, "```") {
		parts := strings.Split(content, "```json")
		if len(parts) > 1 {
			jsonPart := strings.Split(parts[1], "```")[0]
			content = strings.TrimSpace(jsonPart)
		}
	}

	if err := json.Unmarshal([]byte(content), &result); err != nil {
		return nil, fmt.Errorf("解析分析结果失败: %w, 原始内容: %s", err, content)
	}

	return &result, nil
}

// fallbackDetect 在API不可用时的降级检测
func (d *SemanticNLPDetector) fallbackDetect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	// 使用简单的关键词匹配和规则
	content := ctx.Content
	var risks []*model.RiskItem

	// 定义简单的有害词列表
	harmfulWords := []string{
		"傻逼", "混蛋", "垃圾", "白痴", "废物", "贱人",
		"去死", "杀了你", "打死你", "灭了你", "弄死你",
	}

	// 检查敏感词
	for _, word := range harmfulWords {
		if strings.Contains(content, word) {
			risks = append(risks, model.NewRiskItem(
				model.RiskTypeHarassment,
				80.0,
				fmt.Sprintf("检测到敏感词: %s", word),
			))
			break
		}
	}

	// 检查威胁模式
	threatPatterns := []string{
		"小心", "当心", "威胁", "后果", "找你", "报复",
	}
	for _, pattern := range threatPatterns {
		if strings.Contains(content, pattern) {
			risks = append(risks, model.NewRiskItem(
				model.RiskTypeHarassment,
				75.0,
				"检测到潜在威胁性语言",
			))
			break
		}
	}

	// 检查上下文
	if len(ctx.ContextItems) > 0 {
		// 检查是否有上下文拒绝后继续骚扰的情况
		hasRejection := false
		for _, item := range ctx.ContextItems {
			if item.UserID != ctx.UserID {
				if d.containsRejection(item.Content) {
					hasRejection = true
					break
				}
			}
		}

		if hasRejection {
			risks = append(risks, model.NewRiskItem(
				model.RiskTypeContextViolation,
				70.0,
				"检测到可能在对方拒绝后继续发送消息",
			))
		}
	}

	return risks, nil
}

// containsRejection 检查内容是否包含拒绝表达
func (d *SemanticNLPDetector) containsRejection(text string) bool {
	rejectionWords := []string{
		"不要", "别", "停止", "别再", "不想", "拒绝",
		"别来", "讨厌", "烦人", "骚扰", "别发",
	}

	for _, word := range rejectionWords {
		if strings.Contains(text, word) {
			return true
		}
	}

	return false
}

// hasContextualRisk 检查是否存在上下文相关的风险
func (d *SemanticNLPDetector) hasContextualRisk(result *SemanticAnalysisResult, context []string) bool {
	// 如果有拒绝表达后仍继续发送相似内容
	for _, text := range context {
		if d.containsRejection(text) {
			return true
		}
	}
	return false
}

// getIntentRiskType 将意图映射到风险类型
func (d *SemanticNLPDetector) getIntentRiskType(intent string) model.RiskType {
	switch intent {
	case "harmful":
		return model.RiskTypeHarassment
	default:
		return model.RiskTypeUnknown
	}
}

// getIntentDescription 获取意图描述
func (d *SemanticNLPDetector) getIntentDescription(intent string) string {
	switch intent {
	case "harmful":
		return "有害"
	default:
		return intent
	}
}
