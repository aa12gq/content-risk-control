package service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ModelServer NLP模型服务器
type ModelServer struct {
	logger      *zap.SugaredLogger // 日志
	configPath  string             // 配置文件路径
	modelPath   string             // 模型路径
	serverPort  int                // 服务器端口
	ready       bool               // 服务是否就绪
	mutex       sync.RWMutex       // 锁
	httpServer  *http.Server       // HTTP服务器
	modelLoaded bool               // 模型是否加载
}

// NewModelServer 创建新的模型服务器
func NewModelServer(logger *zap.SugaredLogger, configPath, modelPath string, port int) *ModelServer {
	return &ModelServer{
		logger:     logger,
		configPath: configPath,
		modelPath:  modelPath,
		serverPort: port,
	}
}

// Start 启动模型服务器
func (s *ModelServer) Start() error {
	// 检查模型文件是否存在
	if _, err := os.Stat(s.modelPath); os.IsNotExist(err) {
		return fmt.Errorf("模型文件不存在: %s", err)
	}

	// 设置路由
	mux := http.NewServeMux()

	// 健康检查接口
	mux.HandleFunc("/health", s.healthCheckHandler)

	// 分析接口
	mux.HandleFunc("/analyze", s.analyzeHandler)

	// 创建服务器
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.serverPort),
		Handler: mux,
	}

	// 加载模型
	if err := s.loadModel(); err != nil {
		return fmt.Errorf("加载模型失败: %s", err)
	}

	// 准备就绪
	s.mutex.Lock()
	s.ready = true
	s.mutex.Unlock()

	// 启动服务器
	s.logger.Infof("NLP模型服务启动在端口 %d", s.serverPort)
	return s.httpServer.ListenAndServe()
}

// Stop 停止模型服务器
func (s *ModelServer) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.ready = false
	s.logger.Info("正在停止NLP模型服务...")
	return s.httpServer.Close()
}

// IsReady 检查服务是否就绪
func (s *ModelServer) IsReady() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.ready
}

// loadModel 加载模型
func (s *ModelServer) loadModel() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// 这里应该使用适当的深度学习框架加载模型
	// 例如，使用TensorFlow、PyTorch等
	// 为了简化，这里我们只是模拟加载过程
	s.logger.Info("正在加载NLP模型...")
	time.Sleep(2 * time.Second) // 模拟加载过程
	s.modelLoaded = true
	s.logger.Info("NLP模型加载完成")

	return nil
}

// healthCheckHandler 健康检查处理
func (s *ModelServer) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	s.mutex.RLock()
	ready := s.ready
	s.mutex.RUnlock()

	if !ready {
		http.Error(w, "服务未就绪", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "ok",
		"modelLoaded": s.modelLoaded,
		"timestamp":   time.Now().Unix(),
	})
}

// analyzeHandler 分析处理
func (s *ModelServer) analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "只支持POST请求", http.StatusMethodNotAllowed)
		return
	}

	// 解析请求
	var request struct {
		Text          string   `json:"text"`
		Contexts      []string `json:"contexts,omitempty"`
		AnalysisTypes []string `json:"analysis_types"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "无效的请求格式", http.StatusBadRequest)
		return
	}

	// 验证请求
	if request.Text == "" {
		http.Error(w, "文本不能为空", http.StatusBadRequest)
		return
	}

	// 进行分析
	// 这里应该使用加载的模型进行实际分析
	// 为了演示，我们返回模拟结果
	result := s.mockAnalysis(request.Text, request.Contexts, request.AnalysisTypes)

	// 返回结果
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		s.logger.Errorf("编码响应失败: %v", err)
		http.Error(w, "内部服务器错误", http.StatusInternalServerError)
		return
	}
}

// mockAnalysis 模拟分析过程（实际应用中应该使用真实模型）
func (s *ModelServer) mockAnalysis(text string, contexts []string, analysisTypes []string) map[string]interface{} {
	result := make(map[string]interface{})

	// 意图分析
	if contains(analysisTypes, "intent") {
		intent := s.mockIntentAnalysis(text)
		result["intent"] = intent
	}

	// 情感分析
	if contains(analysisTypes, "sentiment") {
		sentiment := s.mockSentimentAnalysis(text)
		result["sentiment"] = sentiment
	}

	// 有害内容分析
	if contains(analysisTypes, "toxicity") {
		toxicity := s.mockToxicityAnalysis(text)
		result["toxicity"] = toxicity
	}

	// 上下文相似度分析
	if contains(analysisTypes, "similarity") && len(contexts) > 0 {
		similarity := s.mockSimilarityAnalysis(text, contexts)
		result["similarity"] = similarity
	}

	return result
}

// mockIntentAnalysis 模拟意图分析
func (s *ModelServer) mockIntentAnalysis(text string) map[string]interface{} {
	// 这里应该使用实际的NLP模型进行分析
	// 以下是模拟的结果

	// 简单基于关键词的意图识别
	intent := "neutral"
	confidence := 0.5
	var subIntents []string

	// 检测侮辱意图
	insultWords := []string{"傻逼", "废物", "混蛋", "笨蛋", "蠢货", "垃圾"}
	for _, word := range insultWords {
		if contains([]string{text}, word) {
			intent = "insult"
			confidence = 0.85
			break
		}
	}

	// 检测威胁意图
	threatWords := []string{"警告", "小心", "威胁", "后果", "报复"}
	for _, word := range threatWords {
		if contains([]string{text}, word) {
			if intent != "insult" {
				intent = "threat"
				confidence = 0.8
			}
			subIntents = append(subIntents, "threat")
			break
		}
	}

	// 检测命令意图
	commandWords := []string{"必须", "一定要", "立刻", "马上"}
	for _, word := range commandWords {
		if contains([]string{text}, word) {
			if intent == "neutral" {
				intent = "command"
				confidence = 0.75
			}
			subIntents = append(subIntents, "command")
			break
		}
	}

	return map[string]interface{}{
		"label":       intent,
		"confidence":  confidence,
		"sub_intents": subIntents,
	}
}

// mockSentimentAnalysis 模拟情感分析
func (s *ModelServer) mockSentimentAnalysis(text string) map[string]interface{} {
	// 这里应该使用实际的情感分析模型
	// 以下是模拟的结果

	// 简单基于关键词的情感分析
	negativeWords := []string{"不好", "讨厌", "烦", "生气", "难过", "恨", "差劲", "糟糕"}
	positiveWords := []string{"好", "喜欢", "开心", "高兴", "棒", "赞", "优秀", "满意"}

	var negCount int
	var posCount int

	for _, word := range negativeWords {
		if contains([]string{text}, word) {
			negCount++
		}
	}

	for _, word := range positiveWords {
		if contains([]string{text}, word) {
			posCount++
		}
	}

	label := "neutral"
	score := 0.0
	intensity := 0.0

	totalWords := len(text) / 3 // 简单估计中文词数
	totalWords = max(1, totalWords)

	if negCount > posCount {
		label = "negative"
		score = -float64(negCount) / float64(totalWords) * 2
		intensity = float64(negCount) / float64(totalWords) * 2
	} else if posCount > negCount {
		label = "positive"
		score = float64(posCount) / float64(totalWords) * 2
		intensity = float64(posCount) / float64(totalWords) * 2
	}

	// 限制范围
	score = clamp(score, -1.0, 1.0)
	intensity = clamp(intensity, 0.0, 1.0)

	return map[string]interface{}{
		"label":     label,
		"score":     score,
		"intensity": intensity,
	}
}

// mockToxicityAnalysis 模拟有害内容分析
func (s *ModelServer) mockToxicityAnalysis(text string) map[string]interface{} {
	// 这里应该使用实际的有害内容检测模型
	// 以下是模拟的结果

	categories := make(map[string]float64)
	isToxic := false
	score := 0.0

	// 简单的关键词检测
	toxicCategories := map[string][]string{
		"profanity": {"操", "艹", "妈的", "fuck", "shit"},
		"insult":    {"傻逼", "白痴", "智障", "废物", "垃圾"},
		"threat":    {"杀", "打死", "打爆", "揍", "弄死"},
		"hate":      {"贱", "贱人", "死"},
	}

	for category, words := range toxicCategories {
		for _, word := range words {
			if contains([]string{text}, word) {
				categories[category] = 0.8
				isToxic = true
				score = maxFloat(score, 0.8)
			}
		}
	}

	return map[string]interface{}{
		"is_toxic":   isToxic,
		"score":      score,
		"categories": categories,
	}
}

// mockSimilarityAnalysis 模拟上下文相似度分析
func (s *ModelServer) mockSimilarityAnalysis(text string, contexts []string) map[string]interface{} {
	// 这里应该使用实际的文本相似度模型
	// 以下是模拟的结果

	scores := make([]float64, len(contexts))
	var totalScore float64

	for i, context := range contexts {
		// 简单的相似度计算（实际应该使用词嵌入或其他方法）
		commonChars := 0
		for _, c := range text {
			if contains([]string{context}, string(c)) {
				commonChars++
			}
		}

		// 计算相似度分数
		maxLen := max(len(text), len(context))
		if maxLen > 0 {
			scores[i] = float64(commonChars) / float64(maxLen)
		}
		totalScore += scores[i]
	}

	// 计算平均相似度
	avgScore := 0.0
	if len(contexts) > 0 {
		avgScore = totalScore / float64(len(contexts))
	}

	return map[string]interface{}{
		"scores":  scores,
		"average": avgScore,
	}
}

// contains 检查slice是否包含指定字符串
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// max 返回两个int的最大值
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// clamp 限制值在指定范围内
func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

// maxFloat 返回两个float64的最大值
func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
