package service

import (
	"context"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/aa12gq/content-risk-control/api/proto"
	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// GRPCServer gRPC服务实现
type GRPCServer struct {
	pb.UnimplementedContentCheckServiceServer
	service *ContentCheckService
	logger  *zap.SugaredLogger
}

// RegisterGRPCServer 注册gRPC服务
func RegisterGRPCServer(server *grpc.Server, service *ContentCheckService) {
	grpcServer := &GRPCServer{
		service: service,
		logger:  service.logger,
	}
	pb.RegisterContentCheckServiceServer(server, grpcServer)
}

// CheckContent 检查单条内容
func (s *GRPCServer) CheckContent(ctx context.Context, req *pb.CheckContentRequest) (*pb.CheckContentResponse, error) {
	if req.Content == "" {
		return nil, status.Error(codes.InvalidArgument, "content cannot be empty")
	}

	extraData := make(map[string]string)
	if req.ExtraData != nil {
		extraData = req.ExtraData
	}

	result, err := s.service.CheckContent(ctx, req.Content, req.UserId, req.Scene, extraData)
	if err != nil {
		s.logger.Errorf("Failed to check content: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to check content: %v", err)
	}

	return convertToProtoResponse(result), nil
}

// BatchCheckContent 批量检查内容
func (s *GRPCServer) BatchCheckContent(ctx context.Context, req *pb.BatchCheckContentRequest) (*pb.BatchCheckContentResponse, error) {
	if len(req.Items) == 0 {
		return nil, status.Error(codes.InvalidArgument, "items cannot be empty")
	}

	items := make([]*model.CheckRequest, 0, len(req.Items))
	for _, item := range req.Items {
		extraData := make(map[string]string)
		if item.ExtraData != nil {
			extraData = item.ExtraData
		}

		items = append(items, &model.CheckRequest{
			Content:   item.Content,
			UserID:    item.UserId,
			Scene:     item.Scene,
			RequestID: item.RequestId,
			ExtraData: extraData,
		})
	}

	result, err := s.service.BatchCheckContent(ctx, items, req.BatchId)
	if err != nil {
		s.logger.Errorf("Failed to batch check content: %v", err)
		// 即使有错误，我们也返回已处理的结果
	}

	response := &pb.BatchCheckContentResponse{
		BatchId:       result.BatchID,
		TotalCostTime: result.TotalCostTime,
	}

	for _, res := range result.Results {
		response.Results = append(response.Results, convertToProtoResponse(res))
	}

	return response, nil
}

// CheckContentWithContext 基于上下文的内容检查
func (s *GRPCServer) CheckContentWithContext(ctx context.Context, req *pb.CheckContentWithContextRequest) (*pb.CheckContentResponse, error) {
	if req.Content == "" {
		return nil, status.Error(codes.InvalidArgument, "content cannot be empty")
	}

	extraData := make(map[string]string)
	if req.ExtraData != nil {
		extraData = req.ExtraData
	}

	contextItems := make([]*model.ContextItem, 0, len(req.ContextItems))
	for _, item := range req.ContextItems {
		contextItems = append(contextItems, &model.ContextItem{
			Content:   item.Content,
			UserID:    item.UserId,
			Timestamp: item.Timestamp,
			ContentID: item.ContentId,
		})
	}

	result, err := s.service.CheckContentWithContext(ctx, req.Content, req.UserId, req.Scene, contextItems, extraData)
	if err != nil {
		s.logger.Errorf("Failed to check content with context: %v", err)
		return nil, status.Errorf(codes.Internal, "failed to check content with context: %v", err)
	}

	return convertToProtoResponse(result), nil
}

// StreamCheckContent 实时流式内容检查
func (s *GRPCServer) StreamCheckContent(stream pb.ContentCheckService_StreamCheckContentServer) error {
	wrapper := &streamWrapper{
		stream: stream,
	}

	return s.service.StreamCheckContent(wrapper)
}

// streamWrapper 流包装器
type streamWrapper struct {
	stream pb.ContentCheckService_StreamCheckContentServer
}

// Send 发送响应
func (w *streamWrapper) Send(result *model.CheckResult) error {
	return w.stream.Send(convertToProtoResponse(result))
}

// Recv 接收请求
func (w *streamWrapper) Recv() (*model.CheckRequest, error) {
	req, err := w.stream.Recv()
	if err != nil {
		return nil, err
	}

	extraData := make(map[string]string)
	if req.ExtraData != nil {
		extraData = req.ExtraData
	}

	return &model.CheckRequest{
		Content:   req.Content,
		UserID:    req.UserId,
		Scene:     req.Scene,
		RequestID: req.RequestId,
		ExtraData: extraData,
	}, nil
}

// Context 获取上下文
func (w *streamWrapper) Context() context.Context {
	return w.stream.Context()
}

// convertToProtoResponse 将模型结果转换为Proto响应
func convertToProtoResponse(result *model.CheckResult) *pb.CheckContentResponse {
	response := &pb.CheckContentResponse{
		Result:     pb.ResultType(result.Result),
		RiskScore:  result.RiskScore,
		RequestId:  result.RequestID,
		Suggestion: result.Suggestion,
		CostTime:   result.CostTime,
	}

	if result.Extra != nil {
		response.Extra = result.Extra
	}

	if result.Risks != nil {
		for _, risk := range result.Risks {
			protoRisk := &pb.RiskItem{
				Type:        pb.RiskType(risk.Type),
				Score:       risk.Score,
				Description: risk.Description,
			}

			if risk.Details != nil {
				protoRisk.Details = risk.Details
			}

			response.Risks = append(response.Risks, protoRisk)
		}
	}

	return response
}
