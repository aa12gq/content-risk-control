package detector

import (
	"regexp"
	"strings"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

var (
	// 常见垃圾信息特征
	urlPattern         = regexp.MustCompile(`https?://\S+`)
	phonePattern       = regexp.MustCompile(`(?i)\d{3}[-\.\s]??\d{3}[-\.\s]??\d{4}|\(\d{3}\)\s*\d{3}[-\.\s]??\d{4}|\d{3}[-\.\s]??\d{4}`)
	moneyPattern       = regexp.MustCompile(`(?i)[\$¥€£](\d+)`)
	spamKeywordsLower  = []string{"退款", "贷款", "免费", "优惠", "促销", "中奖", "赚钱", "兼职", "发财", "暴富", "官方认证"}
	spamKeywordsRegexp = regexp.MustCompile(`(?i)(click here|buy now|free|discount|offer|promotion|win|earn|money|cheap)`)
)

// SpamDetector 垃圾信息检测器
type SpamDetector struct{}

// NewSpamDetector 创建垃圾信息检测器
func NewSpamDetector() *SpamDetector {
	return &SpamDetector{}
}

// Detect 检测内容是否为垃圾信息
func (d *SpamDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	if ctx.Content == "" {
		return nil, nil
	}

	content := ctx.Content
	contentLower := strings.ToLower(content)
	var risks []*model.RiskItem

	// 检测URL密度
	urlCount := len(urlPattern.FindAllString(content, -1))
	if urlCount > 0 && float32(urlCount) > float32(len(content))/100 {
		risks = append(risks, &model.RiskItem{
			Type:        model.RiskTypeSpam,
			Score:       60.0,
			Description: "内容包含过多URL链接",
			Details: map[string]string{
				"url_count": string(rune(urlCount)),
			},
		})
	}

	// 检测电话号码
	phoneMatches := phonePattern.FindAllString(content, -1)
	if len(phoneMatches) > 0 {
		risks = append(risks, &model.RiskItem{
			Type:        model.RiskTypeSpam,
			Score:       50.0,
			Description: "内容包含电话号码",
			Details: map[string]string{
				"phone_count": string(rune(len(phoneMatches))),
			},
		})
	}

	// 检测金钱相关
	moneyMatches := moneyPattern.FindAllString(content, -1)
	if len(moneyMatches) > 0 {
		risks = append(risks, &model.RiskItem{
			Type:        model.RiskTypeSpam,
			Score:       40.0,
			Description: "内容包含金钱相关信息",
			Details: map[string]string{
				"money_count": string(rune(len(moneyMatches))),
			},
		})
	}

	// 检测中文垃圾关键词
	for _, keyword := range spamKeywordsLower {
		if strings.Contains(contentLower, keyword) {
			risks = append(risks, &model.RiskItem{
				Type:        model.RiskTypeSpam,
				Score:       65.0,
				Description: "内容包含垃圾信息关键词",
				Details: map[string]string{
					"keyword": keyword,
				},
			})
			break
		}
	}

	// 检测英文垃圾关键词
	if spamKeywordsRegexp.MatchString(contentLower) {
		matches := spamKeywordsRegexp.FindAllString(contentLower, -1)
		if len(matches) > 0 {
			risks = append(risks, &model.RiskItem{
				Type:        model.RiskTypeSpam,
				Score:       55.0,
				Description: "内容包含垃圾信息关键词",
				Details: map[string]string{
					"keyword": matches[0],
				},
			})
		}
	}

	return risks, nil
}
