package service

import (
	"bufio"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/aa12gq/content-risk-control/internal/pkg/detector"
)

// SensitiveWords 敏感词检测器，实现detector.SensitiveWordChecker接口
type SensitiveWords struct {
	words     map[string]bool
	logger    *zap.SugaredLogger
	mu        sync.RWMutex
	filePaths []string
}

// 确保SensitiveWords实现了detector.SensitiveWordChecker接口
var _ detector.SensitiveWordChecker = (*SensitiveWords)(nil)

// NewSensitiveWords 创建敏感词检测器
func NewSensitiveWords(logger *zap.SugaredLogger) *SensitiveWords {
	sw := &SensitiveWords{
		words:  make(map[string]bool),
		logger: logger,
		filePaths: []string{
			"config/sensitive_words.txt",
		},
	}

	// 加载敏感词
	if err := sw.Update(); err != nil {
		logger.Warnf("Failed to load sensitive words: %v", err)
	}

	return sw
}

// Update 更新敏感词库
func (sw *SensitiveWords) Update() error {
	newWords := make(map[string]bool)

	for _, path := range sw.filePaths {
		if err := sw.loadFromFile(path, newWords); err != nil {
			sw.logger.Warnf("Failed to load sensitive words from %s: %v", path, err)
			// 继续加载其他文件
		}
	}

	// 只有在成功加载至少一些词后才更新
	if len(newWords) > 0 {
		sw.mu.Lock()
		sw.words = newWords
		sw.mu.Unlock()
		sw.logger.Infof("Loaded %d sensitive words", len(newWords))
		return nil
	}

	return nil
}

// loadFromFile 从文件加载敏感词
func (sw *SensitiveWords) loadFromFile(path string, words map[string]bool) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word == "" || strings.HasPrefix(word, "#") {
			continue // 跳过空行和注释
		}
		words[word] = true
	}

	return scanner.Err()
}

// AddWord 添加敏感词
func (sw *SensitiveWords) AddWord(word string) {
	if word == "" {
		return
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.words[word] = true
}

// RemoveWord 移除敏感词
func (sw *SensitiveWords) RemoveWord(word string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	delete(sw.words, word)
}

// ContainsWord 检查内容是否包含敏感词
func (sw *SensitiveWords) ContainsWord(content string) (bool, string) {
	if content == "" {
		return false, ""
	}

	sw.mu.RLock()
	defer sw.mu.RUnlock()

	for word := range sw.words {
		if strings.Contains(content, word) {
			return true, word
		}
	}

	return false, ""
}

// GetAllWords 获取所有敏感词
func (sw *SensitiveWords) GetAllWords() []string {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	words := make([]string, 0, len(sw.words))
	for word := range sw.words {
		words = append(words, word)
	}

	return words
}

// SetWordList 设置敏感词列表
func (sw *SensitiveWords) SetWordList(words []string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	sw.words = make(map[string]bool, len(words))
	for _, word := range words {
		if word != "" {
			sw.words[word] = true
		}
	}
}

// AddFilePath 添加敏感词文件路径
func (sw *SensitiveWords) AddFilePath(path string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.filePaths = append(sw.filePaths, path)
}
