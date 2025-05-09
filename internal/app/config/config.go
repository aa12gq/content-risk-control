package config

import (
	"fmt"

	"github.com/spf13/viper"
)

// Config 系统配置结构
type Config struct {
	Server       ServerConfig       `mapstructure:"server"`
	Database     DatabaseConfig     `mapstructure:"database"`
	Redis        RedisConfig        `mapstructure:"redis"`
	ContentCheck ContentCheckConfig `mapstructure:"content_check"`
	AIService    AIServiceConfig    `mapstructure:"ai_service"`
	NLPService   NLPServiceConfig   `mapstructure:"nlp_service"`
	RuleEngine   RuleEngineConfig   `mapstructure:"rule_engine"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port     int    `mapstructure:"port"`
	GRPCPort int    `mapstructure:"grpc_port"`
	Env      string `mapstructure:"env"`
	LogLevel string `mapstructure:"log_level"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Driver          string `mapstructure:"driver"`
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	Username        string `mapstructure:"username"`
	Password        string `mapstructure:"password"`
	DBName          string `mapstructure:"dbname"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime"`
}

// RedisConfig Redis配置
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// ContentCheckConfig 内容审核配置
type ContentCheckConfig struct {
	SensitiveWordsUpdateInterval int  `mapstructure:"sensitive_words_update_interval"`
	UseMLModel                   bool `mapstructure:"use_ml_model"`
	RiskScoreThreshold           int  `mapstructure:"risk_score_threshold"`
	CacheTTL                     int  `mapstructure:"cache_ttl"`
	BatchCheckMaxSize            int  `mapstructure:"batch_check_max_size"`
	ContextHistorySize           int  `mapstructure:"context_history_size"`
}

// AIServiceConfig AI服务配置
type AIServiceConfig struct {
	URL     string `mapstructure:"url"`
	APIKey  string `mapstructure:"api_key"`
	Timeout int    `mapstructure:"timeout"`
}

// NLPServiceConfig NLP服务配置
type NLPServiceConfig struct {
	Enabled      bool    `mapstructure:"enabled"`
	ModelPath    string  `mapstructure:"model_path"`
	ServerPort   int     `mapstructure:"server_port"`
	Threshold    float32 `mapstructure:"threshold"`
	ContextSize  int     `mapstructure:"context_size"`
	UseLocalLLM  bool    `mapstructure:"use_local_llm"`  // 是否使用本地大语言模型
	LocalLLMType string  `mapstructure:"local_llm_type"` // 本地模型类型: ollama, llamacpp等
	LocalLLMAPI  string  `mapstructure:"local_llm_api"`  // 本地模型API地址
	ModelName    string  `mapstructure:"model_name"`     // 使用的模型名称
}

// RuleEngineConfig 规则引擎配置
type RuleEngineConfig struct {
	RuleUpdateInterval int    `mapstructure:"rule_update_interval"`
	DefaultRulesPath   string `mapstructure:"default_rules_path"`
}

// Load 加载配置文件
func Load(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(configPath)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &config, nil
}
