package model

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"time"
)

// ResultType 审核结果类型
type ResultType int

const (
	// ResultTypePass 通过
	ResultTypePass ResultType = iota
	// ResultTypeReview 需要人工审核
	ResultTypeReview
	// ResultTypeReject 拒绝
	ResultTypeReject
	// ResultTypeWarning 警告
	ResultTypeWarning
)

// RiskType 风险类型
type RiskType int

const (
	// RiskTypeUnknown 未知风险
	RiskTypeUnknown RiskType = iota
	// RiskTypeSensitiveWord 敏感词
	RiskTypeSensitiveWord
	// RiskTypeSpam 垃圾信息
	RiskTypeSpam
	// RiskTypeHarassment 骚扰
	RiskTypeHarassment
	// RiskTypeHateSpeech 仇恨言论
	RiskTypeHateSpeech
	// RiskTypeViolence 暴力内容
	RiskTypeViolence
	// RiskTypeAdult 成人内容
	RiskTypeAdult
	// RiskTypeContextViolation 上下文违规
	RiskTypeContextViolation
	// RiskTypeSuspiciousBehavior 可疑行为
	RiskTypeSuspiciousBehavior
)

// CheckContext 检查上下文
type CheckContext struct {
	Content      string
	UserID       string
	Scene        string
	ContextItems []*ContextItem
	ExtraData    map[string]string
}

// ContextItem 上下文内容项
type ContextItem struct {
	Content   string
	UserID    string
	Timestamp int64
	ContentID string
}

// CheckRequest 检查请求
type CheckRequest struct {
	Content   string
	UserID    string
	Scene     string
	RequestID string
	ExtraData map[string]string
}

// RiskItem 风险项
type RiskItem struct {
	Type        RiskType
	Score       float32
	Description string
	Details     map[string]string
}

// CheckResult 检查结果
type CheckResult struct {
	Result     ResultType
	RiskScore  float32
	Risks      []*RiskItem
	RequestID  string
	Suggestion string
	CostTime   int64
	Extra      map[string]string
}

// BatchCheckResult 批量检查结果
type BatchCheckResult struct {
	BatchID       string
	Results       []*CheckResult
	TotalCostTime int64
}

// ContentCheckStream 内容检查流接口
type ContentCheckStream interface {
	Send(*CheckResult) error
	Recv() (*CheckRequest, error)
	Context() context.Context
}

// HashString 计算字符串哈希值
func HashString(s string) string {
	hash := md5.Sum([]byte(s))
	return hex.EncodeToString(hash[:])
}

// NewContextItem 创建上下文项
func NewContextItem(content, userID, contentID string) *ContextItem {
	return &ContextItem{
		Content:   content,
		UserID:    userID,
		Timestamp: time.Now().Unix(),
		ContentID: contentID,
	}
}

// NewRiskItem 创建风险项
func NewRiskItem(riskType RiskType, score float32, description string) *RiskItem {
	return &RiskItem{
		Type:        riskType,
		Score:       score,
		Description: description,
		Details:     make(map[string]string),
	}
}
