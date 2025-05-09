package detector

import (
	"strings"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

var (
	// 骚扰内容关键词
	harassmentKeywords = []string{
		"骚扰", "威胁", "欺凌", "攻击", "人身攻击", "侮辱", "歧视",
		"性骚扰", "跟踪", "恐吓", "霸凌", "黑料", "隐私", "私人信息",
	}

	// 上下文骚扰模式 - 同一用户反复发送内容
	repeatMessageThreshold = 3 // 短时间内重复消息阈值
)

// HarassmentDetector 骚扰内容检测器
type HarassmentDetector struct{}

// NewHarassmentDetector 创建骚扰内容检测器
func NewHarassmentDetector() *HarassmentDetector {
	return &HarassmentDetector{}
}

// Detect 检测内容是否为骚扰内容
func (d *HarassmentDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	if ctx.Content == "" {
		return nil, nil
	}

	var risks []*model.RiskItem
	content := strings.ToLower(ctx.Content)

	// 1. 检查是否包含骚扰关键词
	for _, keyword := range harassmentKeywords {
		if strings.Contains(content, keyword) {
			risks = append(risks, &model.RiskItem{
				Type:        model.RiskTypeHarassment,
				Score:       70.0,
				Description: "内容包含骚扰相关关键词",
				Details: map[string]string{
					"keyword": keyword,
				},
			})
			break
		}
	}

	// 2. 检查上下文中是否有骚扰模式
	if len(ctx.ContextItems) > 0 {
		// 检查是否有重复消息模式
		if sameUserRepeatCount := d.countSameUserRepeatMessages(ctx); sameUserRepeatCount >= repeatMessageThreshold {
			risks = append(risks, &model.RiskItem{
				Type:        model.RiskTypeHarassment,
				Score:       65.0,
				Description: "检测到重复发送消息的骚扰模式",
				Details: map[string]string{
					"repeat_count": string(rune(sameUserRepeatCount)),
				},
			})
		}

		// 检查是否针对特定用户频繁发送消息
		if isTargeting, targetUser := d.isTargetingUser(ctx); isTargeting {
			risks = append(risks, &model.RiskItem{
				Type:        model.RiskTypeHarassment,
				Score:       60.0,
				Description: "检测到针对特定用户的频繁消息",
				Details: map[string]string{
					"target_user": targetUser,
				},
			})
		}
	}

	return risks, nil
}

// countSameUserRepeatMessages 统计同一用户在上下文中的重复消息数量
func (d *HarassmentDetector) countSameUserRepeatMessages(ctx *model.CheckContext) int {
	if len(ctx.ContextItems) == 0 {
		return 0
	}

	// 统计用户发送的消息数量
	userMessageCount := 0
	for _, item := range ctx.ContextItems {
		if item.UserID == ctx.UserID {
			userMessageCount++
		}
	}

	// 加上当前消息
	return userMessageCount + 1
}

// isTargetingUser 检查是否针对特定用户
func (d *HarassmentDetector) isTargetingUser(ctx *model.CheckContext) (bool, string) {
	if len(ctx.ContextItems) < 2 {
		return false, ""
	}

	// 统计针对不同用户的消息数量
	targetCounts := make(map[string]int)

	// 首先分析上下文中的回复模式
	for _, item := range ctx.ContextItems {
		if item.UserID != ctx.UserID {
			targetCounts[item.UserID]++
		}
	}

	// 分析当前消息是否针对特定用户
	for targetUserID, count := range targetCounts {
		// 如果针对某个用户的回复次数超过阈值，判定为可能的骚扰
		if count >= 2 {
			return true, targetUserID
		}
	}

	return false, ""
}
