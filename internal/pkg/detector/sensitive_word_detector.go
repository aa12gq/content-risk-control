package detector

import (
	"fmt"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// SensitiveWordChecker 敏感词检查接口
type SensitiveWordChecker interface {
	// ContainsWord 检查内容是否包含敏感词
	ContainsWord(content string) (bool, string)
}

// SensitiveWordDetector 敏感词检测器
type SensitiveWordDetector struct {
	sensitiveWords SensitiveWordChecker
}

// NewSensitiveWordDetector 创建敏感词检测器
func NewSensitiveWordDetector(sensitiveWords SensitiveWordChecker) *SensitiveWordDetector {
	return &SensitiveWordDetector{
		sensitiveWords: sensitiveWords,
	}
}

// Detect 检测内容是否包含敏感词
func (d *SensitiveWordDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	if ctx.Content == "" {
		return nil, nil
	}

	// 检测是否包含敏感词
	containsSensitive, word := d.sensitiveWords.ContainsWord(ctx.Content)
	if !containsSensitive {
		return nil, nil
	}

	// 创建风险项
	riskItem := &model.RiskItem{
		Type:        model.RiskTypeSensitiveWord,
		Score:       80.0, // 默认分数
		Description: fmt.Sprintf("内容包含敏感词: %s", word),
		Details: map[string]string{
			"word": word,
		},
	}

	return []*model.RiskItem{riskItem}, nil
}
