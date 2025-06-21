package internal

import (
	"nebulafinger/internal/utils"
	"time"
)

// Config 全局配置
type Config struct {
	// 现有配置项
	Timeout          time.Duration `yaml:"timeout"`           // 超时设置
	EnableFavicon    bool          `yaml:"enable_favicon"`    // 是否启用favicon检测
	EnableFingerpint bool          `yaml:"enable_fingerpint"` // 是否启用指纹识别
	OutputFormat     string        `yaml:"output_format"`     // 输出格式
	OutputDir        string        `yaml:"output_dir"`        // 输出目录
	InputFiles       []string      `yaml:"input_files"`       // 输入文件列表

	// 新增HTTP客户端配置
	HTTP HTTPConfig `yaml:"http"` // HTTP客户端配置
}

// HTTPConfig HTTP客户端配置
type HTTPConfig struct {
	// TLS配置
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"` // 是否跳过证书验证
	MinTLSVersion      string `yaml:"min_tls_version"`      // 最低TLS版本 (TLS1.0, TLS1.1, TLS1.2, TLS1.3)

	// 重定向设置
	RedirectPolicy     string `yaml:"redirect_policy"`      // 重定向策略 (none, follow, custom)
	MaxRedirects       int    `yaml:"max_redirects"`        // 最大重定向次数
	AllowHostRedirects bool   `yaml:"allow_host_redirects"` // 是否允许跨主机重定向

	// Cookie设置
	EnableCookieJar bool `yaml:"enable_cookie_jar"` // 是否启用Cookie存储

	// 用户代理
	UserAgent string `yaml:"user_agent"` // 自定义用户代理

	// 自定义请求头
	DefaultHeaders map[string]string `yaml:"default_headers"` // 默认请求头
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		Timeout:          30 * time.Second,
		EnableFavicon:    true,
		EnableFingerpint: true,
		OutputFormat:     "json",
		OutputDir:        "output",
		HTTP: HTTPConfig{
			InsecureSkipVerify: true,
			MinTLSVersion:      "TLS1.0",
			RedirectPolicy:     "follow",
			MaxRedirects:       5,
			AllowHostRedirects: true,
			EnableCookieJar:    true,
			UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
			DefaultHeaders: map[string]string{
				"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
				"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
				"Accept-Encoding": "gzip, deflate, br",
				"Connection":      "keep-alive",
			},
		},
	}
}

// DefaultHTTPConfig 返回默认HTTP配置
func DefaultHTTPConfig() HTTPConfig {
	return HTTPConfig{
		InsecureSkipVerify: true,
		MinTLSVersion:      "TLS1.0",
		RedirectPolicy:     "follow",
		MaxRedirects:       5,
		AllowHostRedirects: true,
		EnableCookieJar:    true,
		UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		DefaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection":      "keep-alive",
		},
	}
}

// ToHTTPClientOptions 将HTTP配置转换为HTTP客户端选项
func (c *Config) ToHTTPClientOptions() utils.HTTPClientOptions {
	options := utils.DefaultHTTPClientOptions()

	// 设置超时
	options.Timeout = c.Timeout

	// 设置TLS配置
	options.InsecureSkipVerify = c.HTTP.InsecureSkipVerify

	// 设置TLS版本
	switch c.HTTP.MinTLSVersion {
	case "TLS1.0":
		options.MinTLSVersion = utils.TLS10
	case "TLS1.1":
		options.MinTLSVersion = utils.TLS11
	case "TLS1.2":
		options.MinTLSVersion = utils.TLS12
	case "TLS1.3":
		options.MinTLSVersion = utils.TLS13
	}

	// 设置重定向策略
	options.RedirectPolicy = c.HTTP.RedirectPolicy
	options.MaxRedirects = c.HTTP.MaxRedirects
	options.AllowHostRedirects = c.HTTP.AllowHostRedirects

	// 设置Cookie
	options.EnableCookieJar = c.HTTP.EnableCookieJar

	// 设置用户代理
	if c.HTTP.UserAgent != "" {
		options.UserAgent = c.HTTP.UserAgent
	}

	// 设置默认请求头
	if len(c.HTTP.DefaultHeaders) > 0 {
		options.DefaultHeaders = c.HTTP.DefaultHeaders
	}

	return options
}
