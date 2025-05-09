package detector

import (
	"github.com/aa12gq/content-risk-control/internal/app/model"
)

// Detector 内容检测器接口
type Detector interface {
	// Detect 检测内容
	Detect(ctx *model.CheckContext) ([]*model.RiskItem, error)
}
