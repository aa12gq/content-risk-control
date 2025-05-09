package service

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"go.uber.org/zap"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// Rule 规则定义
type Rule struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Enabled     bool                   `json:"enabled"`
	Priority    int                    `json:"priority"`
	Action      string                 `json:"action"`
	Score       float32                `json:"score"`
	Config      map[string]interface{} `json:"config"`
}

// RuleSet 规则集
type RuleSet struct {
	Rules      map[string]*Rule      `json:"rules"`
	Actions    map[string]RuleAction `json:"actions"`
	Categories map[string]string     `json:"categories"`
}

// RuleAction 规则动作
type RuleAction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RuleEngineResult 规则引擎评估结果
type RuleEngineResult struct {
	Result            model.ResultType
	Score             float32
	Risks             []*model.RiskItem
	Suggestion        string
	HasExplicitResult bool
}

// RuleEngine 规则引擎
type RuleEngine struct {
	ruleSet     *RuleSet
	logger      *zap.SugaredLogger
	ruleFile    string
	initialized bool
	mu          sync.RWMutex
}

// NewRuleEngine 创建规则引擎
func NewRuleEngine(ruleFile string, logger *zap.SugaredLogger) (*RuleEngine, error) {
	engine := &RuleEngine{
		ruleFile: ruleFile,
		logger:   logger,
	}

	if err := engine.loadRules(); err != nil {
		return nil, err
	}

	return engine, nil
}

// loadRules 加载规则
func (e *RuleEngine) loadRules() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := ioutil.ReadFile(e.ruleFile)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %w", err)
	}

	var ruleData struct {
		Rules      []*Rule               `json:"rules"`
		Actions    map[string]RuleAction `json:"actions"`
		Categories map[string]string     `json:"categories"`
	}

	if err := json.Unmarshal(data, &ruleData); err != nil {
		return fmt.Errorf("failed to unmarshal rule data: %w", err)
	}

	ruleSet := &RuleSet{
		Rules:      make(map[string]*Rule),
		Actions:    ruleData.Actions,
		Categories: ruleData.Categories,
	}

	for _, rule := range ruleData.Rules {
		ruleSet.Rules[rule.ID] = rule
	}

	e.ruleSet = ruleSet
	e.initialized = true

	e.logger.Infof("Loaded %d rules from %s", len(ruleSet.Rules), e.ruleFile)
	return nil
}

// Evaluate 评估内容
func (e *RuleEngine) Evaluate(ctx *model.CheckContext, existingRisks []*model.RiskItem) (*RuleEngineResult, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.initialized {
		return nil, fmt.Errorf("rule engine not initialized")
	}

	result := &RuleEngineResult{
		Result: model.ResultTypePass,
		Risks:  make([]*model.RiskItem, 0),
	}

	// 按优先级排序规则（高优先级先处理）
	sortedRules := e.sortRulesByPriority()

	// 评估每条规则
	var highestScore float32
	var highestScoreResult model.ResultType

	// 创建已存在风险类型的映射，用于快速查找
	existingRiskTypes := make(map[model.RiskType]bool)
	for _, risk := range existingRisks {
		existingRiskTypes[risk.Type] = true
	}

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}

		// 评估规则
		matched, riskItem := e.evaluateRule(rule, ctx, existingRiskTypes)
		if matched {
			// 添加新的风险项
			if riskItem != nil {
				result.Risks = append(result.Risks, riskItem)
			}

			// 如果规则要求立即拒绝，提前返回结果
			actionType := e.getActionType(rule.Action)
			score := rule.Score

			if score > highestScore {
				highestScore = score
				highestScoreResult = actionType
			}

			// 如果是阻止操作，提前结束
			if actionType == model.ResultTypeReject {
				result.Result = model.ResultTypeReject
				result.Score = score
				result.HasExplicitResult = true
				result.Suggestion = e.generateSuggestion(rule)
				return result, nil
			}
		}
	}

	// 设置最高分数和对应结果
	result.Score = highestScore
	if highestScore > 0 {
		result.Result = highestScoreResult
		result.HasExplicitResult = true
	}

	return result, nil
}

// getActionType 获取动作类型
func (e *RuleEngine) getActionType(action string) model.ResultType {
	switch action {
	case "block":
		return model.ResultTypeReject
	case "review":
		return model.ResultTypeReview
	case "mark":
		return model.ResultTypeWarning
	default:
		return model.ResultTypePass
	}
}

// evaluateRule 评估单条规则
func (e *RuleEngine) evaluateRule(rule *Rule, ctx *model.CheckContext, existingRiskTypes map[model.RiskType]bool) (bool, *model.RiskItem) {
	var riskType model.RiskType

	// 根据规则类型处理
	switch rule.ID {
	case "sensitive_words":
		// 敏感词检测已经由detector完成，这里只需处理未被检测到的情况
		categoryStr, ok := rule.Config["category"].(string)
		if !ok {
			return false, nil
		}

		riskType = e.getRiskTypeFromCategory(categoryStr)
		if existingRiskTypes[riskType] {
			return false, nil // 已经被检测到了
		}

		// 这里可以添加额外的检测逻辑

	case "spam_detection":
		// 垃圾信息检测
		riskType = model.RiskTypeSpam
		if existingRiskTypes[riskType] {
			return false, nil
		}

		// 这里可以添加额外的检测逻辑

	case "context_analysis":
		// 上下文分析
		if len(ctx.ContextItems) == 0 {
			return false, nil // 没有上下文
		}

		riskType = model.RiskTypeContextViolation
		if existingRiskTypes[riskType] {
			return false, nil
		}

		// 根据上下文进行额外检测
		// 这里可以实现更复杂的上下文分析逻辑

	case "user_reputation":
		// 用户信誉度分析
		riskType = model.RiskTypeSuspiciousBehavior
		if existingRiskTypes[riskType] {
			return false, nil
		}

		// 这里可以添加用户信誉度分析逻辑
	}

	// 在实际项目中，这里应该有更复杂的规则匹配逻辑
	// 简化版本中，我们直接返回未匹配
	return false, nil
}

// 生成建议信息
func (e *RuleEngine) generateSuggestion(rule *Rule) string {
	return fmt.Sprintf("内容违反了\"%s\"规则，原因：%s", rule.Name, rule.Description)
}

// 获取风险类型
func (e *RuleEngine) getRiskTypeFromCategory(category string) model.RiskType {
	switch category {
	case "sensitive":
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
	default:
		return model.RiskTypeUnknown
	}
}

// 按优先级排序规则
func (e *RuleEngine) sortRulesByPriority() []*Rule {
	rules := make([]*Rule, 0, len(e.ruleSet.Rules))
	for _, rule := range e.ruleSet.Rules {
		rules = append(rules, rule)
	}

	// 按优先级排序（降序）
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	return rules
}
