package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/aa12gq/content-risk-control/internal/app/config"
	"github.com/aa12gq/content-risk-control/internal/app/model"
	"github.com/aa12gq/content-risk-control/internal/pkg/detector"
)

var (
	// ErrEmptyContent 内容为空错误
	ErrEmptyContent = errors.New("content is empty")
	// ErrInvalidRequest 无效请求错误
	ErrInvalidRequest = errors.New("invalid request")
	// ErrRuleNotFound 规则未找到错误
	ErrRuleNotFound = errors.New("rule not found")
	// ErrInternalServer 内部服务错误
	ErrInternalServer = errors.New("internal server error")
)

// ContentCheckService 内容审核服务
type ContentCheckService struct {
	cfg            *config.Config
	logger         *zap.SugaredLogger
	ruleEngine     *RuleEngine
	redisClient    *redis.Client
	sensitiveWords *SensitiveWords
	detectors      map[string]detector.Detector
	mu             sync.RWMutex
}

// NewContentCheckService 创建内容审核服务
func NewContentCheckService(cfg *config.Config, logger *zap.SugaredLogger) (*ContentCheckService, error) {
	// 创建Redis客户端
	var redisClient *redis.Client
	var err error

	// 尝试连接Redis，如果失败则记录警告并继续
	redisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// 测试Redis连接
	_, err = redisClient.Ping(context.Background()).Result()
	if err != nil {
		logger.Warnf("Failed to connect to Redis: %v, will proceed without cache", err)
		// 继续执行，但不使用缓存功能
	}

	// 加载规则引擎
	ruleEngine, err := NewRuleEngine(cfg.RuleEngine.DefaultRulesPath, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize rule engine: %w", err)
	}

	// 初始化敏感词检测器
	sensitiveWords := NewSensitiveWords(logger)

	// 初始化各种内容检测器
	detectors := make(map[string]detector.Detector)
	detectors["sensitive"] = detector.NewSensitiveWordDetector(sensitiveWords)
	detectors["spam"] = detector.NewSpamDetector()
	detectors["harassment"] = detector.NewHarassmentDetector()

	// 初始化语义检测器
	semanticDetector := detector.NewSemanticDetector(
		cfg.ContentCheck.ContextHistorySize,
		0.3, // 默认阈值
	)
	detectors["semantic"] = semanticDetector

	// 如果启用了NLP服务，初始化NLP检测器
	if cfg.NLPService.Enabled {
		nlpEndpoint := fmt.Sprintf("http://localhost:%d", cfg.NLPService.ServerPort)
		nlpDetector, err := detector.NewNLPDetector(
			nlpEndpoint,
			cfg.NLPService.Threshold,
			cfg.NLPService.ContextSize,
		)
		if err != nil {
			logger.Warnf("Failed to initialize NLP detector: %v", err)
		} else {
			logger.Info("NLP detector initialized successfully")
			detectors["nlp"] = nlpDetector
		}
	}

	// 如果配置了使用机器学习模型，则初始化AI检测器
	if cfg.ContentCheck.UseMLModel {
		aiDetector, err := detector.NewAIDetector(cfg.AIService.URL, cfg.AIService.APIKey, time.Duration(cfg.AIService.Timeout)*time.Millisecond)
		if err != nil {
			logger.Warnf("Failed to initialize AI detector: %v", err)
		} else {
			detectors["ai"] = aiDetector
		}
	}

	// 如果配置了使用本地大语言模型，则初始化语义NLP检测器
	if cfg.NLPService.UseLocalLLM {
		localLLMAPI := cfg.NLPService.LocalLLMAPI
		if localLLMAPI == "" {
			// 默认使用Ollama API地址
			localLLMAPI = "http://localhost:11434/api/chat"
		}

		semanticNLPDetector, err := detector.NewSemanticNLPDetector(
			localLLMAPI,
			cfg.NLPService.Threshold,
			cfg.NLPService.ContextSize,
		)
		if err != nil {
			logger.Warnf("Failed to initialize local semantic NLP detector: %v", err)
		} else {
			logger.Info("Local semantic NLP detector initialized successfully")
			detectors["semantic_nlp"] = semanticNLPDetector
		}
	}

	service := &ContentCheckService{
		cfg:            cfg,
		logger:         logger,
		ruleEngine:     ruleEngine,
		redisClient:    redisClient,
		sensitiveWords: sensitiveWords,
		detectors:      detectors,
	}

	// 启动敏感词定时更新
	go service.scheduleSensitiveWordUpdate(time.Duration(cfg.ContentCheck.SensitiveWordsUpdateInterval) * time.Second)

	return service, nil
}

// CheckContent 检查单条内容
func (s *ContentCheckService) CheckContent(ctx context.Context, content string, userID, scene string, extraData map[string]string) (*model.CheckResult, error) {
	if content == "" {
		return nil, ErrEmptyContent
	}

	// 生成请求ID
	requestID := fmt.Sprintf("req_%d_%s", time.Now().UnixNano(), userID)

	// 尝试从缓存获取结果
	cacheKey := fmt.Sprintf("content_check:%s", model.HashString(content))
	cachedResult, err := s.getCachedResult(ctx, cacheKey)
	if err == nil {
		s.logger.Debugf("Cache hit for content check: %s", cacheKey)
		cachedResult.RequestID = requestID
		cachedResult.CostTime = 0 // 从缓存获取，耗时为0
		return cachedResult, nil
	}

	startTime := time.Now()

	// 执行内容检查
	result, err := s.doContentCheck(content, userID, scene, nil, extraData)
	if err != nil {
		return nil, err
	}

	// 设置结果信息
	result.RequestID = requestID
	result.CostTime = time.Since(startTime).Milliseconds()

	// 缓存结果
	if result.Result != model.ResultTypeReject {
		s.cacheResult(ctx, cacheKey, result, time.Duration(s.cfg.ContentCheck.CacheTTL)*time.Second)
	}

	return result, nil
}

// CheckContentWithContext 基于上下文的内容检查
func (s *ContentCheckService) CheckContentWithContext(ctx context.Context, content string, userID, scene string, contextItems []*model.ContextItem, extraData map[string]string) (*model.CheckResult, error) {
	if content == "" {
		return nil, ErrEmptyContent
	}

	// 生成请求ID
	requestID := fmt.Sprintf("req_ctx_%d_%s", time.Now().UnixNano(), userID)

	startTime := time.Now()

	// 执行上下文内容检查
	result, err := s.doContentCheck(content, userID, scene, contextItems, extraData)
	if err != nil {
		return nil, err
	}

	// 设置结果信息
	result.RequestID = requestID
	result.CostTime = time.Since(startTime).Milliseconds()

	return result, nil
}

// BatchCheckContent 批量检查内容
func (s *ContentCheckService) BatchCheckContent(ctx context.Context, items []*model.CheckRequest, batchID string) (*model.BatchCheckResult, error) {
	if len(items) == 0 {
		return nil, ErrInvalidRequest
	}

	if len(items) > s.cfg.ContentCheck.BatchCheckMaxSize {
		items = items[:s.cfg.ContentCheck.BatchCheckMaxSize]
	}

	startTime := time.Now()
	results := make([]*model.CheckResult, 0, len(items))
	var wg sync.WaitGroup
	resultCh := make(chan *batchResult, len(items))

	// 并行处理每个内容项
	for i, item := range items {
		wg.Add(1)
		go func(idx int, req *model.CheckRequest) {
			defer wg.Done()
			result, err := s.CheckContent(ctx, req.Content, req.UserID, req.Scene, req.ExtraData)
			resultCh <- &batchResult{
				index:  idx,
				result: result,
				err:    err,
			}
		}(i, item)
	}

	// 等待所有处理完成
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	// 收集结果
	resultMap := make(map[int]*model.CheckResult)
	var lastError error
	for res := range resultCh {
		if res.err != nil {
			s.logger.Errorf("Batch check error at index %d: %v", res.index, res.err)
			lastError = res.err
			continue
		}
		resultMap[res.index] = res.result
	}

	// 按顺序整理结果
	for i := 0; i < len(items); i++ {
		if result, ok := resultMap[i]; ok {
			results = append(results, result)
		} else {
			// 对于处理失败的项，添加一个默认通过的结果
			results = append(results, &model.CheckResult{
				Result:    model.ResultTypePass,
				RiskScore: 0,
				RequestID: fmt.Sprintf("batch_%s_idx_%d", batchID, i),
				Risks:     nil,
				Extra:     map[string]string{"error": "处理失败"},
			})
		}
	}

	return &model.BatchCheckResult{
		BatchID:       batchID,
		Results:       results,
		TotalCostTime: time.Since(startTime).Milliseconds(),
	}, lastError
}

// StreamCheckContent 实时流式内容检查（实现流式gRPC接口）
func (s *ContentCheckService) StreamCheckContent(stream model.ContentCheckStream) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return status.Errorf(codes.Internal, "failed to receive request: %v", err)
		}

		result, err := s.CheckContent(stream.Context(), req.Content, req.UserID, req.Scene, req.ExtraData)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to check content: %v", err)
		}

		if err := stream.Send(result); err != nil {
			return status.Errorf(codes.Internal, "failed to send response: %v", err)
		}
	}
}

// doContentCheck 执行内容检查的核心逻辑
func (s *ContentCheckService) doContentCheck(content, userID, scene string, contextItems []*model.ContextItem, extraData map[string]string) (*model.CheckResult, error) {
	// 初始化检查上下文
	checkCtx := &model.CheckContext{
		Content:      content,
		UserID:       userID,
		Scene:        scene,
		ContextItems: contextItems,
		ExtraData:    extraData,
	}

	// 应用规则引擎
	var allRisks []*model.RiskItem
	var totalScore float32
	var maxScore float32

	// 1. 先应用各种检测器
	for name, detector := range s.detectors {
		risks, err := detector.Detect(checkCtx)
		if err != nil {
			s.logger.Warnf("Detector %s failed: %v", name, err)
			continue
		}

		for _, risk := range risks {
			allRisks = append(allRisks, risk)
			totalScore += risk.Score
			if risk.Score > maxScore {
				maxScore = risk.Score
			}
		}
	}

	// 2. 应用规则引擎
	engineResult, err := s.ruleEngine.Evaluate(checkCtx, allRisks)
	if err != nil {
		s.logger.Errorf("Rule engine evaluation failed: %v", err)
		// 即使规则引擎失败，我们仍然可以基于检测器的结果给出判断
	} else {
		// 合并规则引擎的结果
		for _, risk := range engineResult.Risks {
			found := false
			for _, existing := range allRisks {
				if existing.Type == risk.Type {
					found = true
					// 更新已有风险项的分数和描述
					if risk.Score > existing.Score {
						existing.Score = risk.Score
						existing.Description = risk.Description
					}
					break
				}
			}

			if !found {
				allRisks = append(allRisks, risk)
			}

			if risk.Score > maxScore {
				maxScore = risk.Score
			}
		}

		// 如果规则引擎明确给出了结果，则使用它的判断
		if engineResult.HasExplicitResult {
			return &model.CheckResult{
				Result:     engineResult.Result,
				RiskScore:  engineResult.Score,
				Risks:      allRisks,
				Suggestion: engineResult.Suggestion,
			}, nil
		}
	}

	// 3. 基于风险分数计算最终结果
	finalScore := maxScore
	var result model.ResultType

	// 根据配置的阈值判断结果
	if finalScore >= float32(s.cfg.ContentCheck.RiskScoreThreshold) {
		result = model.ResultTypeReject
	} else if finalScore >= float32(s.cfg.ContentCheck.RiskScoreThreshold)*0.7 {
		result = model.ResultTypeReview
	} else if finalScore >= float32(s.cfg.ContentCheck.RiskScoreThreshold)*0.5 {
		result = model.ResultTypeWarning
	} else {
		result = model.ResultTypePass
	}

	// 生成最终结果
	suggestion := s.generateSuggestion(result, allRisks)
	return &model.CheckResult{
		Result:     result,
		RiskScore:  finalScore,
		Risks:      allRisks,
		Suggestion: suggestion,
		Extra:      map[string]string{"total_score": fmt.Sprintf("%.2f", totalScore)},
	}, nil
}

// generateSuggestion 生成建议
func (s *ContentCheckService) generateSuggestion(result model.ResultType, risks []*model.RiskItem) string {
	switch result {
	case model.ResultTypeReject:
		if len(risks) > 0 {
			return fmt.Sprintf("内容包含违规信息，原因：%s", risks[0].Description)
		}
		return "内容未通过审核，请修改后重试"
	case model.ResultTypeReview:
		return "内容需要人工审核，请等待审核结果"
	case model.ResultTypeWarning:
		return "内容存在风险，建议修改"
	default:
		return "内容审核通过"
	}
}

// getCachedResult 从缓存获取审核结果
func (s *ContentCheckService) getCachedResult(ctx context.Context, key string) (*model.CheckResult, error) {
	if s.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	data, err := s.redisClient.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}

	var result model.CheckResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// cacheResult 缓存审核结果
func (s *ContentCheckService) cacheResult(ctx context.Context, key string, result *model.CheckResult, ttl time.Duration) {
	if s.redisClient == nil {
		s.logger.Debugf("Redis client not available, skipping cache")
		return
	}

	data, err := json.Marshal(result)
	if err != nil {
		s.logger.Errorf("Failed to marshal check result: %v", err)
		return
	}

	if err := s.redisClient.Set(ctx, key, data, ttl).Err(); err != nil {
		s.logger.Errorf("Failed to cache check result: %v", err)
	}
}

// scheduleSensitiveWordUpdate 定时更新敏感词库
func (s *ContentCheckService) scheduleSensitiveWordUpdate(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		err := s.sensitiveWords.Update()
		if err != nil {
			s.logger.Errorf("Failed to update sensitive words: %v", err)
		} else {
			s.logger.Infof("Sensitive words updated successfully")
		}
	}
}

// batchResult 批量处理的结果项
type batchResult struct {
	index  int
	result *model.CheckResult
	err    error
}
