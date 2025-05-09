package detector

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

var (
	// 敬语模式匹配
	respectfulPattern = regexp.MustCompile(`(?i)(您好|请问|麻烦|谢谢|感谢|劳驾|打扰了|不好意思)`)
	// 问候语匹配
	greetingPattern = regexp.MustCompile(`(?i)(早上好|上午好|中午好|下午好|晚上好|晚安|早安|嗨|喂|你好)`)
	// 亲属称呼正常用法匹配
	familyPattern = regexp.MustCompile(`(?i)(你妈妈|你爸爸|你爷爷|你奶奶|你哥哥|你姐姐)(?:怎么样|好吗|还好吗|身体好吗)`)
	// 侮辱性语言匹配
	insultPattern = regexp.MustCompile(`(?i)(滚蛋|傻逼|废物|混蛋|白痴|笨蛋|蠢货|智障|垃圾|贱人|去死)`)
	// 命令句式匹配
	commandPattern = regexp.MustCompile(`(?i)(必须|一定要|给我|立刻|马上|快点)(.{0,15})(否则|不然|不许|不准|要不然)`)
	// 威胁模式匹配
	threatPattern = regexp.MustCompile(`(?i)(小心|当心|后果|威胁|找你|等着|报复)`)
)

// 文本分类结果
type textCategory struct {
	category    string
	confidence  float32
	description string
}

// SemanticDetector 语义检测器
type SemanticDetector struct {
	contextSize int
	threshold   float32
}

// NewSemanticDetector 创建语义检测器
func NewSemanticDetector(contextSize int, threshold float32) *SemanticDetector {
	return &SemanticDetector{
		contextSize: contextSize,
		threshold:   threshold,
	}
}

// Detect 执行语义分析检测
func (d *SemanticDetector) Detect(ctx *model.CheckContext) ([]*model.RiskItem, error) {
	content := ctx.Content
	if content == "" {
		return nil, nil
	}

	// 风险项列表
	var risks []*model.RiskItem

	// 1. 模式匹配检测
	if d.patternBasedDetection(content, &risks) {
		return risks, nil
	}

	// 2. 基于亲属词的上下文分析
	if d.familyTermAnalysis(content, ctx.ContextItems, &risks) {
		return risks, nil
	}

	// 3. 简单文本分类
	category := d.classifyText(content)
	if category.category != "normal" && category.confidence > d.threshold {
		risks = append(risks, model.NewRiskItem(
			d.getCategoryRiskType(category.category),
			category.confidence*100,
			category.description,
		))
	}

	// 4. 上下文对话模式分析
	if len(ctx.ContextItems) > 0 {
		d.analyzeConversationPattern(ctx, &risks)
	}

	return risks, nil
}

// getCategoryRiskType 获取类别对应的风险类型
func (d *SemanticDetector) getCategoryRiskType(category string) model.RiskType {
	switch category {
	case "insult":
		return model.RiskTypeHarassment
	case "command":
		return model.RiskTypeHarassment
	case "threat":
		return model.RiskTypeHarassment
	case "spam":
		return model.RiskTypeSpam
	default:
		return model.RiskTypeUnknown
	}
}

// patternBasedDetection 基于模式的检测
func (d *SemanticDetector) patternBasedDetection(content string, risks *[]*model.RiskItem) bool {
	// 检测侮辱性语言
	if insultPattern.MatchString(content) {
		*risks = append(*risks, model.NewRiskItem(
			model.RiskTypeHarassment,
			85.0,
			"检测到直接侮辱性语言",
		))
		return true
	}

	// 检测威胁语言
	if threatPattern.MatchString(content) {
		*risks = append(*risks, model.NewRiskItem(
			model.RiskTypeHarassment,
			75.0,
			"检测到潜在威胁性语言",
		))
		return true
	}

	// 如果同时包含命令模式和亲属词，但不是问候模式，可能是侮辱
	if commandPattern.MatchString(content) &&
		strings.Contains(content, "你妈") &&
		!familyPattern.MatchString(content) &&
		!greetingPattern.MatchString(content) {
		*risks = append(*risks, model.NewRiskItem(
			model.RiskTypeHarassment,
			80.0,
			"检测到针对家人的负面表达",
		))
		return true
	}

	return false
}

// familyTermAnalysis 亲属词语上下文分析
func (d *SemanticDetector) familyTermAnalysis(content string, contextItems []*model.ContextItem, risks *[]*model.RiskItem) bool {
	// 如果包含"你妈"等亲属词
	if strings.Contains(content, "你妈") ||
		strings.Contains(content, "你爸") ||
		strings.Contains(content, "你爷") {

		// 检查是否是正常问候语
		if familyPattern.MatchString(content) ||
			respectfulPattern.MatchString(content) ||
			greetingPattern.MatchString(content) {
			// 正常问候，不作处理
			return false
		}

		// 检查上下文是否有拒绝或反感表达
		hasRejection := false
		for _, item := range contextItems {
			if strings.Contains(item.Content, "不要") ||
				strings.Contains(item.Content, "别") ||
				strings.Contains(item.Content, "停止") ||
				strings.Contains(item.Content, "讨厌") {
				hasRejection = true
				break
			}
		}

		// 如果上下文有拒绝表达，且当前消息包含亲属词，可能是骚扰
		if hasRejection {
			*risks = append(*risks, model.NewRiskItem(
				model.RiskTypeHarassment,
				75.0,
				"检测到在对方反感后使用带有亲属词的可能冒犯内容",
			))
			return true
		}
	}

	return false
}

// classifyText 简单文本分类
func (d *SemanticDetector) classifyText(text string) textCategory {
	// 定义各类文本的关键词
	categories := map[string][]string{
		"insult":  {"废物", "垃圾", "蠢货", "白痴", "傻逼", "混蛋", "笨蛋", "去死", "滚蛋"},
		"command": {"必须", "一定", "马上", "立刻", "给我", "快点"},
		"threat":  {"小心", "当心", "威胁", "后果", "找你", "报复"},
		"spam":    {"优惠", "打折", "促销", "免费", "赚钱", "发财", "中奖", "红包"},
	}

	// 计算每个类别的匹配度
	var maxCategory string
	var maxScore float32
	var maxDesc string

	for category, keywords := range categories {
		var score float32
		var matchedWords []string

		for _, keyword := range keywords {
			if strings.Contains(text, keyword) {
				score += 0.2
				matchedWords = append(matchedWords, keyword)
			}
		}

		// 如果这个类别得分较高，更新最高得分类别
		if score > maxScore {
			maxScore = score
			maxCategory = category
			if len(matchedWords) > 0 {
				maxDesc = fmt.Sprintf("检测到%s内容，包含关键词: %s",
					d.getCategoryDescription(category),
					strings.Join(matchedWords[:min(3, len(matchedWords))], "、"))
			}
		}
	}

	// 如果没有明显的分类特征
	if maxScore < 0.3 {
		return textCategory{
			category:    "normal",
			confidence:  0,
			description: "",
		}
	}

	return textCategory{
		category:    maxCategory,
		confidence:  maxScore,
		description: maxDesc,
	}
}

// getCategoryDescription 获取类别描述
func (d *SemanticDetector) getCategoryDescription(category string) string {
	switch category {
	case "insult":
		return "侮辱性"
	case "command":
		return "命令性"
	case "threat":
		return "威胁性"
	case "spam":
		return "垃圾信息"
	default:
		return "未知"
	}
}

// analyzeConversationPattern 分析对话模式
func (d *SemanticDetector) analyzeConversationPattern(ctx *model.CheckContext, risks *[]*model.RiskItem) {
	// 如果上下文项太少，无法进行有效分析
	if len(ctx.ContextItems) < 2 {
		return
	}

	// 获取当前用户ID
	currentUserID := ctx.UserID

	// 计算针对其他用户的消息频率
	userMessageCount := make(map[string]int)
	otherUserReplyCount := make(map[string]int)

	for _, item := range ctx.ContextItems {
		if item.UserID == currentUserID {
			// 当前用户的消息
			for _, otherItem := range ctx.ContextItems {
				if otherItem.UserID != currentUserID {
					userMessageCount[otherItem.UserID]++
				}
			}
		} else {
			// 其他用户的回复
			otherUserReplyCount[item.UserID]++
		}
	}

	// 检查是否有不平衡的对话模式
	for otherUserID, msgCount := range userMessageCount {
		replyCount := otherUserReplyCount[otherUserID]

		// 如果当前用户发送的消息明显多于对方的回复，可能是骚扰
		if msgCount > replyCount*2 && msgCount > 2 {
			*risks = append(*risks, model.NewRiskItem(
				model.RiskTypeHarassment,
				60.0,
				"检测到不平衡的对话模式，可能是骚扰",
			))
			(*risks)[len(*risks)-1].Details = map[string]string{
				"message_ratio": fmt.Sprintf("%.1f", float64(msgCount)/max(1.0, float64(replyCount))),
				"target_user":   otherUserID,
			}
			break
		}
	}

	// 检测对话中的情绪变化
	var negativeResponses int
	for i, item := range ctx.ContextItems {
		if item.UserID != currentUserID {
			// 检查其他用户的回复是否表达负面情绪
			if strings.Contains(item.Content, "别") ||
				strings.Contains(item.Content, "不要") ||
				strings.Contains(item.Content, "停止") ||
				strings.Contains(item.Content, "烦") {
				negativeResponses++

				// 检查负面回复后当前用户是否继续发送类似消息
				if i+1 < len(ctx.ContextItems) && ctx.ContextItems[i+1].UserID == currentUserID {
					category := d.classifyText(ctx.ContextItems[i+1].Content)
					if category.category == "command" || category.category == "insult" {
						contentType := "侮辱性"
						if category.category == "command" {
							contentType = "命令型"
						}

						*risks = append(*risks, model.NewRiskItem(
							model.RiskTypeContextViolation,
							70.0,
							fmt.Sprintf("检测到在对方表达不满后继续发送%s内容", contentType),
						))
						break
					}
				}
			}
		}
	}

	// 如果有多次负面回应但用户仍继续发送消息
	if negativeResponses >= 2 {
		*risks = append(*risks, model.NewRiskItem(
			model.RiskTypeSuspiciousBehavior,
			65.0,
			"检测到在多次负面回应后继续发送消息",
		))
		(*risks)[len(*risks)-1].Details = map[string]string{
			"negative_responses": fmt.Sprintf("%d", negativeResponses),
		}
	}
}

// min 返回两个数的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max 返回两个数的较大值
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
