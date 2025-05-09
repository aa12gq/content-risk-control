package detector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// AIDetector AI内容检测器
type AIDetector struct {
	url     string
	apiKey  string
	client  *http.Client
	timeout time.Duration
}

// AIRequestBody AI请求体
type AIRequestBody struct {
	Content     string            `json:"content"`
	UserID      string            `json:"user_id,omitempty"`
	Context     []*AIContextItem  `json:"context,omitempty"`
	ExtraParams map[string]string `json:"extra_params,omitempty"`
}

// AIContextItem AI上下文项
type AIContextItem struct {
	Content   string `json:"content"`
	UserID    string `json:"user_id,omitempty"`
	Timestamp int64  `json:"timestamp,omitempty"`
}

// AIResponseBody AI响应体
type AIResponseBody struct {
	Success bool          `json:"success"`
	Risks   []*AIRiskItem `json:"risks"`
	Score   float32       `json:"score"`
	Error   string        `json:"error,omitempty"`
}

// AIRiskItem AI风险项
type AIRiskItem struct {
	Type        string            `json:"type"`
	Score       float32           `json:"score"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}

// NewAIDetector 创建AI检测器
func NewAIDetector(url, apiKey string, timeout time.Duration) (*AIDetector, error) {
	if url == "" {
		return nil, fmt.Errorf("AI service URL cannot be empty")
	}

	client := &http.Client{
		Timeout: timeout,
	}

	return &AIDetector{
		url:     url,
		apiKey:  apiKey,
		client:  client,
		timeout: timeout,
	}, nil
}

// Detect 使用AI检测内容风险
func (d *AIDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	if ctx.Content == "" {
		return nil, nil
	}

	// 准备请求体
	reqBody := AIRequestBody{
		Content:     ctx.Content,
		UserID:      ctx.UserID,
		ExtraParams: ctx.ExtraData,
	}

	// 添加上下文
	if len(ctx.ContextItems) > 0 {
		reqBody.Context = make([]*AIContextItem, 0, len(ctx.ContextItems))
		for _, item := range ctx.ContextItems {
			reqBody.Context = append(reqBody.Context, &AIContextItem{
				Content:   item.Content,
				UserID:    item.UserID,
				Timestamp: item.Timestamp,
			})
		}
	}

	// 序列化请求
	reqData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AI request: %w", err)
	}

	// 创建请求
	req, err := http.NewRequest("POST", d.url, bytes.NewBuffer(reqData))
	if err != nil {
		return nil, fmt.Errorf("failed to create AI request: %w", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	if d.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+d.apiKey)
	}

	// 发送请求
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send AI request: %w", err)
	}
	defer resp.Body.Close()

	// 检查状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AI service returned non-OK status: %d", resp.StatusCode)
	}

	// 解析响应
	var respBody AIResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		return nil, fmt.Errorf("failed to decode AI response: %w", err)
	}

	// 检查响应结果
	if !respBody.Success {
		if respBody.Error != "" {
			return nil, fmt.Errorf("AI service error: %s", respBody.Error)
		}
		return nil, fmt.Errorf("AI service failed without specific error")
	}

	// 转换AI风险项到模型风险项
	risks := make([]*model.RiskItem, 0, len(respBody.Risks))
	for _, aiRisk := range respBody.Risks {
		riskType := d.mapRiskType(aiRisk.Type)
		risks = append(risks, &model.RiskItem{
			Type:        riskType,
			Score:       aiRisk.Score,
			Description: aiRisk.Description,
			Details:     aiRisk.Details,
		})
	}

	return risks, nil
}

// mapRiskType 映射AI风险类型到模型风险类型
func (d *AIDetector) mapRiskType(aiRiskType string) model.RiskType {
	switch aiRiskType {
	case "sensitive_word":
		return model.RiskTypeSensitiveWord
	case "spam":
		return model.RiskTypeSpam
	case "harassment":
		return model.RiskTypeHarassment
	case "hate_speech":
		return model.RiskTypeHateSpeech
	case "violence":
		return model.RiskTypeViolence
	case "adult":
		return model.RiskTypeAdult
	case "context_violation":
		return model.RiskTypeContextViolation
	case "suspicious_behavior":
		return model.RiskTypeSuspiciousBehavior
	default:
		return model.RiskTypeUnknown
	}
}
