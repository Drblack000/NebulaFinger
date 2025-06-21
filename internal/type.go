package internal

import (
	"encoding/json"
	"os"
	"strings"
)

// 导入 strings 包，因为 FeatureKey 的定义可能依赖它，尽管当前简化版本 FeatureKey 是 string

// 指纹的完整结构体，映射指纹 JSON 结构的字段
type Fingerprint struct {
	ID   string        `json:"id"`             // 指纹的唯一ID
	Info Info          `json:"info"`           // 指纹信息
	HTTP []HTTPRequest `json:"http,omitempty"` // HTTP 请求探针列表
	TCP  []TCPRequest  `json:"tcp,omitempty"`  // TCP 请求探针列表
}

// 指纹的元数据信息
type Info struct {
	Name     string   `json:"name"`     // 指纹名称（产品/服务名称）
	Author   string   `json:"author"`   // 指纹作者
	Tags     string   `json:"tags"`     // 指纹标签
	Severity string   `json:"severity"` // 指纹严重程度
	Metadata Metadata `json:"metadata"` // 指纹元数据
}

// Metadata 包含指纹的其他元数据信息
type Metadata struct {
	Application string `json:"application,omitempty"` // 表示应用程序（application）
	Vendor      string `json:"vendor,omitempty"`      // 是供应商或制造商的名字
	Product     string `json:"product,omitempty"`     // 是产品的名称
	Version     string `json:"version,omitempty"`     // 是主要版本号
	Update      string `json:"update,omitempty"`      // 次要版本号或更新版本
	Edition     string `json:"edition,omitempty"`     // 特定版本（如企业版、标准版等）
	Language    string `json:"language,omitempty"`    // 语言环境
	SwEdition   string `json:"sw_edition,omitempty"`  // 软件版本（如专业版、家庭版等）
	TargetSw    string `json:"target_sw,omitempty"`   // 目标操作系统或其他软件平台
	TargetHw    string `json:"target_hw,omitempty"`   // 目标硬件平台
	Other       string `json:"other,omitempty"`       // 其他任何相关的信息
	// 添加您之前示例中出现的其他元数据字段
	FofaQuery    []string `json:"fofa-query,omitempty"`    // Fofa 查询语句
	ShodanQuery  []string `json:"shodan-query,omitempty"`  // Shodan 查询语句
	ZoomeyeQuery []string `json:"zoomeye-query,omitempty"` // Zoomeye 查询语句
	InfoField    string   `json:"info,omitempty"`          // 其他信息字段（避免与 Info 结构体名称冲突）
	Rarity       int      `json:"rarity,omitempty"`        // 稀有度
	Verified     bool     `json:"verified,omitempty"`      // 是否已验证
}

// HTTPRequest 定义了一个单独的 HTTP 请求探针
type HTTPRequest struct {
	Method     string       `json:"method"`               // HTTP 方法 (e.g., "GET")
	Path       []string     `json:"path,omitempty"`       // !!! 直接放在 HTTPRequest 中，对应 JSON 中的 "path" 字段
	Matchers   []Matchers   `json:"matchers,omitempty"`   // 添加 omitempty
	Extractors []Extractors `json:"extractors,omitempty"` // 添加 omitempty
}

// TCPRequest 定义了一个单独的 TCP 请求探针
type TCPRequest struct {
	Name       string       `json:"name"`                 // 服务名
	Port       string       `json:"port"`                 // 目标端口
	Inputs     []Input      `json:"inputs"`               // 发送给服务的输入数据
	Matchers   []Matchers   `json:"matchers,omitempty"`   // 添加 omitempty // 这里原来漏了 TCPRequest 的 Matchers
	Extractors []Extractors `json:"extractors,omitempty"` // 添加 omitempty
}

// Input 定义了发送给 TCP 服务的数据（简化版）
type Input struct {
	// Data 字段在这里不需要用于特征提取，所以注释掉
	Read int    `json:"read,omitempty"` // 读取响应的字节数
	Data string `json:"data,omitempty"` // 添加 Data 字段以匹配示例 JSON
}

type Extractors struct {
	Name  string   `json:"name,omitempty"`  // 添加 omitempty
	Type  string   `json:"type,omitempty"`  // 添加 omitempty
	Regex []string `json:"regex,omitempty"` // 修改为字符串数组以匹配JSON
}

type Matchers struct {
	Name            string   `json:"name,omitempty"`             // 匹配名称，如果不为空并且匹配到结果会返回
	Type            string   `json:"type"`                       // 匹配器类型：word，favicon，regex，status等
	Regex           []string `json:"regex,omitempty"`            // 修改为字符串数组以匹配JSON
	Part            string   `json:"part,omitempty"`             // 匹配位置：header,body,response,favicon,all 默认：body
	Favicon_hash    []string `json:"hash,omitempty"`             // 如果是favicon类型：hash为图标hash列表，支持md5和mmh3
	Words           []string `json:"words,omitempty"`            // 关键词列表
	Status          []int    `json:"status,omitempty"`           // 状态码列表 (用于 "status" 匹配器)
	CaseInsensitive bool     `json:"case-insensitive,omitempty"` // 是否忽略大小写，默认为false
	Negative        bool     `json:"negative,omitempty"`         // 是否将匹配结果取反，默认为false
	Condition       string   `json:"condition,omitempty"`        // 匹配关系：or,and，当为or时匹配到就立即返回，为and时要全部匹配到才返回结果，默认为or
	Match_all       bool     `json:"match-all,omitempty"`        // 是否要求所有条件都匹配，默认为false
}

// FeatureKey 表示从指纹中提取的简化特征
// 为了简化 Map 的键，使用了字符串格式
type FeatureKey string

// RegexKey 表示正则表达式键
type RegexKey string

// FingerRet 查找指纹返回类型
type FingerRet struct {
	AllProbes int  `json:"all_probes"`
	Probed    int  `json:"probed"`
	Found     bool `json:"found"`
}

// MatcherWeights 定义不同匹配器类型的权重
type MatcherWeights struct {
	Favicon float64            `json:"favicon"`
	Regex   map[string]float64 `json:"regex"`
	Word    map[string]float64 `json:"word"`
}

// ComboWeights 定义组合匹配器的额外权重
type ComboWeights struct {
	MultipleMatchers     float64 `json:"multiple_matchers"`
	FaviconWithOthers    float64 `json:"favicon_with_others"`
	ServerRegexWithTitle float64 `json:"server_regex_with_title"`
}

// ConfidenceConfig 定义置信度计算的配置
type ConfidenceConfig struct {
	MatcherWeights MatcherWeights `json:"matcher_weights"`
	ComboWeights   ComboWeights   `json:"combo_weights"`
	MinConfidence  float64        `json:"min_confidence"`
	MaxConfidence  float64        `json:"max_confidence"`
}

// LoadConfidenceConfig 从配置文件加载置信度配置
func LoadConfidenceConfig(configPath string) (*ConfidenceConfig, error) {
	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// 解析为ConfidenceConfig结构
	var config ConfidenceConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// 计算匹配器的置信度
func CalculateMatcherConfidence(matcher Matchers, content string, headers map[string][]string, config *ConfidenceConfig) float64 {
	var confidence float64 = 0.0

	switch strings.ToLower(matcher.Type) {
	case "favicon":
		confidence = config.MatcherWeights.Favicon
	case "regex":
		// 默认regex置信度
		confidence = config.MatcherWeights.Regex["default"]

		// 检查是否包含server或title相关的正则
		for _, regex := range matcher.Regex {
			if strings.Contains(strings.ToLower(regex), "server:") {
				confidence = config.MatcherWeights.Regex["server"]
				break
			} else if strings.Contains(strings.ToLower(regex), "title") {
				confidence = config.MatcherWeights.Regex["title"]
				break
			}
		}
	case "word":
		// 默认word置信度
		confidence = config.MatcherWeights.Word["default"]

		// 检查是否包含server或title相关的单词
		for _, word := range matcher.Words {
			if strings.Contains(strings.ToLower(word), "server:") {
				confidence = config.MatcherWeights.Word["server"]
				break
			} else if strings.Contains(strings.ToLower(word), "title") ||
				strings.Contains(strings.ToLower(word), "<title") {
				confidence = config.MatcherWeights.Word["title"]
				break
			}
		}
	default:
		// 其他类型的匹配器使用最低置信度
		confidence = config.MinConfidence
	}

	// 确保置信度在有效范围内
	if confidence < config.MinConfidence {
		confidence = config.MinConfidence
	} else if confidence > config.MaxConfidence {
		confidence = config.MaxConfidence
	}

	return confidence
}
