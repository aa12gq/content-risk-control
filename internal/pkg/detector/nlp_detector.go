package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aa12gq/content-risk-control/internal/app/model"
	openai "github.com/sashabaranov/go-openai"
)

// NLPDetector 基于OpenAI的NLP检测器
type NLPDetector struct {
	apiKey       string         // OpenAI API密钥
	client       *openai.Client // OpenAI客户端
	mutex        sync.RWMutex   // 读写锁
	httpClient   *http.Client   // HTTP客户端
	model        string         // 使用的模型
	threshold    float32        // 阈值
	contextSize  int            // 上下文大小
	categories   []string       // 分类类别
	fallbackMode bool           // 降级模式标志
}

// ChatRequest 结构定义了系统提示和用户输入
type ChatRequest struct {
	SystemPrompt string
	UserInput    string
	Context      []string
}

// AnalysisResult 分析结果结构
type AnalysisResult struct {
	IsToxic     bool               `json:"is_toxic"`
	Categories  map[string]float32 `json:"categories"`
	Explanation string             `json:"explanation"`
	Intent      string             `json:"intent"`
	Sentiment   string             `json:"sentiment"`
	Risk        float32            `json:"risk_score"`
}

// NewNLPDetector 创建NLP检测器
func NewNLPDetector(apiKey string, threshold float32, contextSize int) (*NLPDetector, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("OpenAI API密钥不能为空")
	}

	client := openai.NewClient(apiKey)
	transport := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
	}

	detector := &NLPDetector{
		apiKey:      apiKey,
		client:      client,
		httpClient:  &http.Client{Transport: transport, Timeout: 30 * time.Second},
		model:       openai.GPT3Dot5Turbo, // 默认使用GPT-3.5 Turbo
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
		return detector, fmt.Errorf("OpenAI API连接测试失败，启用降级模式: %w", err)
	}

	return detector, nil
}

// testConnection 测试与OpenAI API的连接
func (d *NLPDetector) testConnection() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 创建一个简单的模型列表请求来测试连接
	_, err := d.client.ListModels(ctx)
	if err != nil {
		return fmt.Errorf("OpenAI API连接失败: %w", err)
	}

	return nil
}

// Detect 执行NLP检测
func (d *NLPDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
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

// analyzeContent 使用OpenAI API分析内容
func (d *NLPDetector) analyzeContent(content string, contextItems []string) (*AnalysisResult, error) {
	systemPrompt := `你是一个内容安全分析专家，你需要分析用户输入的文本是否包含不安全内容，如侮辱、骚扰、威胁、仇恨言论等。
请分析用户提供的文本，并返回JSON格式的分析结果，包括：
- 是否有害（is_toxic）: true或false
- 分类（categories）: 可能的类别包括"insult", "threat", "harassment", "hate_speech", "self_harm", "sexual", "violence"，为每个相关类别提供0-1之间的分数
- 解释（explanation）: 简要解释判断理由
- 意图（intent）: "harmful", "neutral", "friendly"中的一个
- 情感（sentiment）: "negative", "neutral", "positive"中的一个
- 风险分数（risk_score）: 0-1之间的总体风险分数`

	var userInput string
	if len(contextItems) > 0 {
		contextStr := strings.Join(contextItems, "\n")
		userInput = fmt.Sprintf("上下文信息:\n%s\n\n待分析文本:\n%s", contextStr, content)
	} else {
		userInput = fmt.Sprintf("待分析文本:\n%s", content)
	}

	// 准备与OpenAI的对话
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 创建聊天完成请求
	resp, err := d.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model: d.model,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleSystem,
					Content: systemPrompt,
				},
				{
					Role:    openai.ChatMessageRoleUser,
					Content: userInput,
				},
			},
			Temperature: 0.1, // 低温度以获得更一致的结果
			MaxTokens:   500,
			// 请求JSON格式响应
			ResponseFormat: &openai.ChatCompletionResponseFormat{
				Type: openai.ChatCompletionResponseFormatTypeJSONObject,
			},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("OpenAI API调用失败: %w", err)
	}

	// 解析响应
	resultContent := resp.Choices[0].Message.Content
	var result AnalysisResult
	if err := json.Unmarshal([]byte(resultContent), &result); err != nil {
		return nil, fmt.Errorf("解析OpenAI响应失败: %w", err)
	}

	return &result, nil
}

// fallbackDetect 在API不可用时的降级检测
func (d *NLPDetector) fallbackDetect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
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
func (d *NLPDetector) containsRejection(text string) bool {
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
func (d *NLPDetector) hasContextualRisk(result *AnalysisResult, contextItems []string) bool {
	// 如果有拒绝表达后仍继续发送相似内容
	for _, text := range contextItems {
		if d.containsRejection(text) {
			return true
		}
	}
	return false
}

// getIntentRiskType 将意图映射到风险类型
func (d *NLPDetector) getIntentRiskType(intent string) model.RiskType {
	switch intent {
	case "harmful":
		return model.RiskTypeHarassment
	default:
		return model.RiskTypeUnknown
	}
}

// getIntentDescription 获取意图描述
func (d *NLPDetector) getIntentDescription(intent string) string {
	switch intent {
	case "harmful":
		return "有害"
	default:
		return intent
	}
}
