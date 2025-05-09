package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"

	"github.com/aa12gq/content-risk-control/internal/app/config"
	"github.com/aa12gq/content-risk-control/internal/app/service"
)

func main() {
	cfg, err := config.Load("config/config.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	zapLogger := initLogger(cfg.Server.LogLevel)
	defer zapLogger.Sync()
	sugar := zapLogger.Sugar()

	sugar.Info("Starting content risk control service...")

	// 如果启用了NLP服务，启动模型服务器
	var modelServer *service.ModelServer
	if cfg.NLPService.Enabled {
		modelServer = service.NewModelServer(
			sugar,
			"config/config.yaml",
			cfg.NLPService.ModelPath,
			cfg.NLPService.ServerPort,
		)

		// 在后台启动模型服务
		go func() {
			if err := modelServer.Start(); err != nil {
				sugar.Errorf("Failed to start NLP model server: %v", err)
			}
		}()

		// 等待模型服务准备就绪
		time.Sleep(3 * time.Second)
		if !modelServer.IsReady() {
			sugar.Warn("NLP model server is not ready yet, proceeding without it")
		} else {
			sugar.Info("NLP model server is ready")
		}
	}

	contentService, err := service.NewContentCheckService(cfg, sugar)
	if err != nil {
		sugar.Fatalf("Failed to initialize content check service: %v", err)
	}

	grpcServer := grpc.NewServer()
	service.RegisterGRPCServer(grpcServer, contentService)

	ginEngine := gin.Default()
	service.RegisterHTTPHandlers(ginEngine, contentService)

	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Server.GRPCPort))
	if err != nil {
		sugar.Fatalf("Failed to listen on gRPC port: %v", err)
	}

	go func() {
		sugar.Infof("gRPC server started on port %d", cfg.Server.GRPCPort)
		if err := grpcServer.Serve(grpcListener); err != nil {
			sugar.Fatalf("Failed to serve gRPC: %v", err)
		}
	}()

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Server.Port),
		Handler: ginEngine,
	}

	go func() {
		sugar.Infof("HTTP server started on port %d", cfg.Server.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			sugar.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	sugar.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		sugar.Fatalf("Server forced to shutdown: %v", err)
	}

	grpcServer.GracefulStop()

	sugar.Info("Server exiting")
}

func initLogger(logLevel string) *zap.Logger {
	level := zap.InfoLevel
	switch logLevel {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "warn":
		level = zap.WarnLevel
	case "error":
		level = zap.ErrorLevel
	}

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Encoding:         "json",
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:   "message",
			LevelKey:     "level",
			TimeKey:      "time",
			CallerKey:    "caller",
			EncodeLevel:  zapcore.LowercaseLevelEncoder,
			EncodeTime:   zapcore.ISO8601TimeEncoder,
			EncodeCaller: zapcore.ShortCallerEncoder,
		},
	}

	logger, err := config.Build()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	return logger
}
