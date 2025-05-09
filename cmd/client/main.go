package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	serverURL = "http://localhost:8080"
)

// 检查请求结构
type CheckRequest struct {
	Content   string            `json:"content"`
	UserID    string            `json:"user_id"`
	Scene     string            `json:"scene"`
	ExtraData map[string]string `json:"extra_data,omitempty"`
}

// 检查响应结构
type CheckResponse struct {
	Success    bool              `json:"success"`
	Result     int               `json:"result"`
	RiskScore  float32           `json:"risk_score"`
	Risks      []RiskItem        `json:"risks"`
	RequestID  string            `json:"request_id"`
	Suggestion string            `json:"suggestion"`
	CostTime   int64             `json:"cost_time"`
	Extra      map[string]string `json:"extra,omitempty"`
}

// 风险项结构
type RiskItem struct {
	Type        int               `json:"type"`
	Score       float32           `json:"score"`
	Description string            `json:"description"`
	Details     map[string]string `json:"details,omitempty"`
}

// 上下文项
type ContextItem struct {
	Content   string `json:"content"`
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp"`
	ContentID string `json:"content_id"`
}

// 上下文请求
type CheckWithContextRequest struct {
	Content      string            `json:"content"`
	UserID       string            `json:"user_id"`
	Scene        string            `json:"scene"`
	ContextItems []ContextItem     `json:"context_items"`
	ExtraData    map[string]string `json:"extra_data,omitempty"`
}

func main() {
	// 测试服务健康状态
	testHealthCheck()

	// 测试敏感词检测
	testContentCheck()

	// 测试上下文理解
	testContextCheck()

	// 测试语义理解NLP
	testSemanticNLP()
}

// 测试健康检查
func testHealthCheck() {
	fmt.Println("\n=== 测试健康检查 ===")

	resp, err := http.Get(serverURL + "/api/v1/health")
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("服务健康状态: 正常")
	} else {
		fmt.Printf("服务健康状态: 异常，状态码 %d\n", resp.StatusCode)
	}
}

// 测试内容检查
func testContentCheck() {
	fmt.Println("\n=== 测试内容检查 ===")

	// 测试用例列表
	testCases := []struct {
		name    string
		content string
		userID  string
		scene   string
	}{
		{
			name:    "正常内容",
			content: "这是一段正常的内容，不包含任何敏感词。",
			userID:  "user_001",
			scene:   "comment",
		},
		{
			name:    "包含敏感词",
			content: "这段内容包含敏感词1，应该被检测到。",
			userID:  "user_002",
			scene:   "post",
		},
		{
			name:    "垃圾内容",
			content: "免费领取优惠券，赚钱发财！点击链接 http://example.com 立即注册。",
			userID:  "user_003",
			scene:   "message",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n测试用例: %s\n", tc.name)

		// 构建请求
		req := CheckRequest{
			Content: tc.content,
			UserID:  tc.userID,
			Scene:   tc.scene,
		}

		// 发送请求
		response := doContentCheck(req)
		if response == nil {
			continue
		}

		// 输出结果
		printCheckResult(response)
	}
}

// 测试上下文检查
func testContextCheck() {
	fmt.Println("\n=== 测试上下文理解 ===")

	// 构建上下文
	contexts := []ContextItem{
		{
			Content:   "你好，请问怎么联系你？",
			UserID:    "user_harasser",
			Timestamp: time.Now().Add(-5 * time.Minute).Unix(),
			ContentID: "msg_001",
		},
		{
			Content:   "我不想告诉你。",
			UserID:    "user_normal",
			Timestamp: time.Now().Add(-4 * time.Minute).Unix(),
			ContentID: "msg_002",
		},
		{
			Content:   "告诉我吧，我想和你交朋友。",
			UserID:    "user_harasser",
			Timestamp: time.Now().Add(-3 * time.Minute).Unix(),
			ContentID: "msg_003",
		},
		{
			Content:   "请不要再打扰我。",
			UserID:    "user_normal",
			Timestamp: time.Now().Add(-2 * time.Minute).Unix(),
			ContentID: "msg_004",
		},
	}

	// 当前消息（可能是骚扰）
	req := CheckWithContextRequest{
		Content:      "你必须告诉我你的联系方式！",
		UserID:       "user_harasser",
		Scene:        "private_message",
		ContextItems: contexts,
	}

	fmt.Println("测试上下文骚扰行为检测")
	response := doContextCheck(req)
	if response == nil {
		return
	}

	// 输出结果
	printCheckResult(response)
}

// 测试语义理解NLP
func testSemanticNLP() {
	fmt.Println("\n=== 测试语义理解NLP ===")

	// 测试场景1: 问候中的家人提及（正常）
	testNormalGreeting()

	// 测试场景2: 侮辱性言论中的家人提及（违规）
	testInsultWithFamilyReference()

	// 测试场景3: 上下文中的骚扰行为（拒绝后继续）
	testHarassmentAfterRejection()

	// 测试场景4: 语境歧义理解（同样的词在不同语境）
	testAmbiguityResolution()

	// 测试场景5: 情感分析与上下文理解结合
	testSentimentWithContext()
}

// 测试正常问候
func testNormalGreeting() {
	fmt.Println("\n测试场景: 正常问候中的家人提及")

	// 1. 友好问候
	req := CheckRequest{
		Content: "你妈妈身体还好吗？上次听说她感冒了。",
		UserID:  "user_normal",
		Scene:   "private_message",
	}

	fmt.Println("请求内容: " + req.Content)
	response := doContentCheck(req)
	if response == nil {
		return
	}

	printCheckResult(response)
}

// 测试侮辱性言论
func testInsultWithFamilyReference() {
	fmt.Println("\n测试场景: 侮辱性言论中的家人提及")

	// 侮辱性表达
	req := CheckRequest{
		Content: "你妈妈是傻逼，滚开别烦我。",
		UserID:  "user_bad",
		Scene:   "private_message",
	}

	fmt.Println("请求内容: " + req.Content)
	response := doContentCheck(req)
	if response == nil {
		return
	}

	printCheckResult(response)
}

// 测试骚扰行为
func testHarassmentAfterRejection() {
	fmt.Println("\n测试场景: 上下文骚扰 - 拒绝后继续")

	// 构建上下文
	contexts := []ContextItem{
		{
			Content:   "嗨，你好，我想问一下你妈妈怎么样了？",
			UserID:    "user_harasser",
			Timestamp: time.Now().Add(-5 * time.Minute).Unix(),
			ContentID: "msg_001",
		},
		{
			Content:   "我不想谈论我的家人，请不要再问了。",
			UserID:    "user_normal",
			Timestamp: time.Now().Add(-4 * time.Minute).Unix(),
			ContentID: "msg_002",
		},
		{
			Content:   "别这样嘛，我就想知道你妈妈住哪里。",
			UserID:    "user_harasser",
			Timestamp: time.Now().Add(-3 * time.Minute).Unix(),
			ContentID: "msg_003",
		},
		{
			Content:   "请停止这个话题，不然我要举报你了。",
			UserID:    "user_normal",
			Timestamp: time.Now().Add(-2 * time.Minute).Unix(),
			ContentID: "msg_004",
		},
	}

	// 当前消息（继续骚扰）
	req := CheckWithContextRequest{
		Content:      "我不管，告诉我你妈妈的联系方式，否则后果自负！",
		UserID:       "user_harasser",
		Scene:        "private_message",
		ContextItems: contexts,
	}

	fmt.Println("请求内容: " + req.Content)
	fmt.Println("历史上下文:")
	for i, ctx := range contexts {
		fmt.Printf("  %d. %s: %s\n", i+1, ctx.UserID, ctx.Content)
	}

	response := doContextCheck(req)
	if response == nil {
		return
	}

	printCheckResult(response)
}

// 测试语境歧义理解
func testAmbiguityResolution() {
	fmt.Println("\n测试场景: 语境歧义理解（同样的词在不同语境）")

	// 测试用例列表
	testCases := []struct {
		name    string
		content string
		userID  string
		scene   string
	}{
		{
			name:    "你妈妈-关心问候",
			content: "你妈妈身体怎么样了？希望她感冒已经好了。",
			userID:  "user_001",
			scene:   "greeting",
		},
		{
			name:    "你妈妈-侮辱性表达",
			content: "你妈妈怎么生了你这样的废物，真是可悲。",
			userID:  "user_002",
			scene:   "conflict",
		},
		{
			name:    "你妈妈-中性引用",
			content: "关于教育问题，你妈妈有什么看法？我们需要家长的反馈。",
			userID:  "user_003",
			scene:   "discussion",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n测试用例: %s\n", tc.name)
		fmt.Printf("内容: %s\n", tc.content)

		// 构建请求
		req := CheckRequest{
			Content: tc.content,
			UserID:  tc.userID,
			Scene:   tc.scene,
		}

		// 发送请求
		response := doContentCheck(req)
		if response == nil {
			continue
		}

		// 输出结果
		printCheckResult(response)
	}
}

// 测试情感分析与上下文理解结合
func testSentimentWithContext() {
	fmt.Println("\n测试场景: 情感分析与上下文理解结合")

	// 构建上下文 - 情绪逐渐恶化的对话
	contexts := []ContextItem{
		{
			Content:   "你好，我想问一下关于退款的事情。",
			UserID:    "customer",
			Timestamp: time.Now().Add(-15 * time.Minute).Unix(),
			ContentID: "msg_001",
		},
		{
			Content:   "您好，很抱歉，根据我们的政策，该商品不支持退款。",
			UserID:    "service",
			Timestamp: time.Now().Add(-14 * time.Minute).Unix(),
			ContentID: "msg_002",
		},
		{
			Content:   "但是商品有质量问题，我认为应该可以退款。",
			UserID:    "customer",
			Timestamp: time.Now().Add(-13 * time.Minute).Unix(),
			ContentID: "msg_003",
		},
		{
			Content:   "非常抱歉，但我们的政策确实不支持此类情况的退款。",
			UserID:    "service",
			Timestamp: time.Now().Add(-12 * time.Minute).Unix(),
			ContentID: "msg_004",
		},
		{
			Content:   "这太荒谬了，你们的服务态度真差，我要投诉！",
			UserID:    "customer",
			Timestamp: time.Now().Add(-10 * time.Minute).Unix(),
			ContentID: "msg_005",
		},
	}

	// 测试情绪恶化后的负面表达
	req := CheckWithContextRequest{
		Content:      "你们这些骗子，垃圾公司，我一定会让你们付出代价！",
		UserID:       "customer",
		Scene:        "customer_service",
		ContextItems: contexts,
	}

	fmt.Println("请求内容: " + req.Content)
	fmt.Println("历史上下文:")
	for i, ctx := range contexts {
		fmt.Printf("  %d. %s: %s\n", i+1, ctx.UserID, ctx.Content)
	}

	response := doContextCheck(req)
	if response == nil {
		return
	}

	printCheckResult(response)
}

// 发送内容检查请求
func doContentCheck(req CheckRequest) *CheckResponse {
	reqBody, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("序列化请求失败: %v\n", err)
		return nil
	}

	resp, err := http.Post(serverURL+"/api/v1/check", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var response CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("解析响应失败: %v\n", err)
		return nil
	}

	return &response
}

// 发送上下文检查请求
func doContextCheck(req CheckWithContextRequest) *CheckResponse {
	reqBody, err := json.Marshal(req)
	if err != nil {
		fmt.Printf("序列化请求失败: %v\n", err)
		return nil
	}

	resp, err := http.Post(serverURL+"/api/v1/check_with_context", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Printf("请求失败: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var response CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		fmt.Printf("解析响应失败: %v\n", err)
		return nil
	}

	return &response
}

// 输出检查结果
func printCheckResult(resp *CheckResponse) {
	// 结果代码映射
	resultMapping := map[int]string{
		0: "通过",
		1: "人工审核",
		2: "拒绝",
		3: "警告",
	}

	// 风险类型映射
	riskTypeMapping := map[int]string{
		0: "未知风险",
		1: "敏感词",
		2: "垃圾信息",
		3: "骚扰",
		4: "仇恨言论",
		5: "暴力内容",
		6: "成人内容",
		7: "上下文违规",
		8: "可疑行为",
	}

	fmt.Printf("审核结果: %s\n", resultMapping[resp.Result])
	fmt.Printf("风险分数: %.2f\n", resp.RiskScore)
	fmt.Printf("建议: %s\n", resp.Suggestion)
	fmt.Printf("请求ID: %s\n", resp.RequestID)
	fmt.Printf("处理时间: %d ms\n", resp.CostTime)

	if len(resp.Risks) > 0 {
		fmt.Println("检测到的风险:")
		for i, risk := range resp.Risks {
			fmt.Printf("  %d. 类型: %s, 分数: %.2f, 描述: %s\n",
				i+1,
				riskTypeMapping[risk.Type],
				risk.Score,
				risk.Description)
			if len(risk.Details) > 0 {
				fmt.Println("     详细信息:")
				for k, v := range risk.Details {
					fmt.Printf("       %s: %s\n", k, v)
				}
			}
		}
	} else {
		fmt.Println("未检测到风险")
	}
}
