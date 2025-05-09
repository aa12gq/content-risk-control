package service

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// HTTPServer HTTP服务
type HTTPServer struct {
	service *ContentCheckService
}

// RegisterHTTPHandlers 注册HTTP处理器
func RegisterHTTPHandlers(engine *gin.Engine, service *ContentCheckService) {
	httpServer := &HTTPServer{
		service: service,
	}

	// 设置路由
	api := engine.Group("/api/v1")
	{
		api.POST("/check", httpServer.CheckContent)
		api.POST("/batch_check", httpServer.BatchCheckContent)
		api.POST("/check_with_context", httpServer.CheckContentWithContext)
		api.GET("/health", httpServer.HealthCheck)
	}

	engine.Use(gin.Recovery())
	engine.Use(CORSMiddleware())
	engine.Use(RequestLoggerMiddleware())
}

// CORSMiddleware CORS中间件
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// RequestLoggerMiddleware 请求日志中间件
func RequestLoggerMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()

		c.Next()

		latency := time.Since(startTime)
		statusCode := c.Writer.Status()

		c.Set("latency", latency.String())
		c.Set("status_code", statusCode)
	}
}

// HTTPCheckRequest HTTP检查请求
type HTTPCheckRequest struct {
	Content   string            `json:"content" binding:"required"`
	UserID    string            `json:"user_id"`
	Scene     string            `json:"scene"`
	ExtraData map[string]string `json:"extra_data"`
}

// HTTPBatchCheckRequest HTTP批量检查请求
type HTTPBatchCheckRequest struct {
	Items   []*HTTPCheckRequest `json:"items" binding:"required"`
	BatchID string              `json:"batch_id"`
}

// HTTPContextItem HTTP上下文项
type HTTPContextItem struct {
	Content   string `json:"content" binding:"required"`
	UserID    string `json:"user_id"`
	Timestamp int64  `json:"timestamp"`
	ContentID string `json:"content_id"`
}

// HTTPCheckWithContextRequest 基于上下文的HTTP检查请求
type HTTPCheckWithContextRequest struct {
	Content      string             `json:"content" binding:"required"`
	UserID       string             `json:"user_id"`
	Scene        string             `json:"scene"`
	ContextItems []*HTTPContextItem `json:"context_items"`
	ExtraData    map[string]string  `json:"extra_data"`
}

// CheckContent 检查内容
func (s *HTTPServer) CheckContent(c *gin.Context) {
	var req HTTPCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request: " + err.Error(),
		})
		return
	}

	result, err := s.service.CheckContent(c.Request.Context(), req.Content, req.UserID, req.Scene, req.ExtraData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to check content: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"result":     result.Result,
		"risk_score": result.RiskScore,
		"risks":      result.Risks,
		"request_id": result.RequestID,
		"suggestion": result.Suggestion,
		"cost_time":  result.CostTime,
		"extra":      result.Extra,
	})
}

// BatchCheckContent 批量检查内容
func (s *HTTPServer) BatchCheckContent(c *gin.Context) {
	var req HTTPBatchCheckRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request: " + err.Error(),
		})
		return
	}

	items := make([]*model.CheckRequest, 0, len(req.Items))
	for _, item := range req.Items {
		items = append(items, &model.CheckRequest{
			Content:   item.Content,
			UserID:    item.UserID,
			Scene:     item.Scene,
			ExtraData: item.ExtraData,
		})
	}

	batchID := req.BatchID
	if batchID == "" {
		batchID = "batch_" + time.Now().Format("20060102150405")
	}

	result, err := s.service.BatchCheckContent(c.Request.Context(), items, batchID)
	if err != nil {
		// 即使有错误，我们也返回已处理的结果
	}

	c.JSON(http.StatusOK, gin.H{
		"success":         true,
		"batch_id":        result.BatchID,
		"results":         result.Results,
		"total_cost_time": result.TotalCostTime,
		"error":           err, // 可能为nil
	})
}

// CheckContentWithContext 基于上下文的内容检查
func (s *HTTPServer) CheckContentWithContext(c *gin.Context) {
	var req HTTPCheckWithContextRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Invalid request: " + err.Error(),
		})
		return
	}

	contextItems := make([]*model.ContextItem, 0, len(req.ContextItems))
	for _, item := range req.ContextItems {
		contextItems = append(contextItems, &model.ContextItem{
			Content:   item.Content,
			UserID:    item.UserID,
			Timestamp: item.Timestamp,
			ContentID: item.ContentID,
		})
	}

	result, err := s.service.CheckContentWithContext(c.Request.Context(), req.Content, req.UserID, req.Scene, contextItems, req.ExtraData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Failed to check content: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":    true,
		"result":     result.Result,
		"risk_score": result.RiskScore,
		"risks":      result.Risks,
		"request_id": result.RequestID,
		"suggestion": result.Suggestion,
		"cost_time":  result.CostTime,
		"extra":      result.Extra,
	})
}

// HealthCheck 健康检查
func (s *HTTPServer) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "content-risk-control",
		"time":    time.Now().Format(time.RFC3339),
	})
}
