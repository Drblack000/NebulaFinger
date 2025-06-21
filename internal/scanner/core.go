package scanner

import (
	"encoding/json"
	"fmt"
	"nebulafinger/internal"
	"nebulafinger/internal/cluster"
	"nebulafinger/internal/detector"
	"nebulafinger/internal/matcher"
	"net/url"
	"os"
	"strings"
	"time"
)

// ScanResult 表示扫描结果
type ScanResult struct {
	Target     string                // 目标地址
	WebResults []matcher.MatchResult // Web指纹结果
	TCPResults []matcher.MatchResult // TCP服务结果
}

// Scanner 定义扫描器
type Scanner struct {
	WebFingerprints     []internal.Fingerprint           // Web指纹库
	ServiceFingerprints []internal.Fingerprint           // 服务指纹库
	FeatureMap          map[internal.FeatureKey][]string // 特征映射表
	FeatureDetector     *detector.FeatureDetector        // 特征探测器
	WebCluster          *cluster.ClusterType             // Web指纹聚类
	ServiceCluster      *cluster.ClusterType             // 服务指纹聚类
	Config              *ScannerConfig                   // 扫描器配置
	ConfidenceConfig    *internal.ConfidenceConfig       // 置信度配置
}

// ScannerConfig 扫描器配置
type ScannerConfig struct {
	Timeout            time.Duration // HTTP请求超时时间
	FeatureThreshold   int           // 特征匹配阈值
	MaxCandidates      int           // 最大候选指纹数
	Concurrency        int           // 并发数
	EnableFavicon      bool          // 是否启用favicon检测
	EnableTCP          bool          // 是否启用TCP服务检测
	CustomPorts        []string      // 自定义TCP扫描端口
	MaxPortsPerService int           // 每个服务最多扫描的端口数
	AdaptiveTimeout    bool          // 是否启用自适应超时
	DefaultTCPPorts    []uint16      // 默认TCP端口列表，从配置文件加载
	BPStat             bool          // 是否只输出有指纹匹配的结果

	// HTTP客户端配置
	HTTP internal.HTTPConfig // HTTP客户端配置
}

// TCPPortConfig 定义TCP端口配置
type TCPPortConfig struct {
	DefaultPorts []uint16            `json:"default_ports"`
	ServicePorts map[string][]uint16 `json:"service_ports"`
	ScanOptions  struct {
		MaxPortCount   int `json:"max_port_count"`
		TimeoutSeconds int `json:"timeout_seconds"`
	} `json:"scan_options"`
}

// LoadTCPPortConfig 从配置文件加载TCP端口配置
func LoadTCPPortConfig(configPath string) (*TCPPortConfig, error) {
	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// 解析为TCPPortConfig结构
	var config TCPPortConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// DefaultConfig 返回默认配置
func DefaultConfig() *ScannerConfig {
	return &ScannerConfig{
		Timeout:            10 * time.Second,
		FeatureThreshold:   1,
		MaxCandidates:      10,
		Concurrency:        5,
		EnableFavicon:      true,
		EnableTCP:          true,
		CustomPorts:        []string{},
		MaxPortsPerService: 5,
		AdaptiveTimeout:    true,
		HTTP:               internal.DefaultHTTPConfig(),
		BPStat:             false, // 默认关闭BP-stat选项
	}
}

// NewScanner 创建新的扫描器
func NewScanner(
	webFingerprints []internal.Fingerprint,
	serviceFingerprints []internal.Fingerprint,
	featureMap map[internal.FeatureKey][]string,
	config *ScannerConfig,
) *Scanner {
	// 创建特征检测器
	featureDetector := detector.NewFeatureDetector(featureMap)

	// 聚类指纹
	webCluster := cluster.ClusterFingerprints(webFingerprints, serviceFingerprints)

	// 尝试加载置信度配置
	var confidenceConfig *internal.ConfidenceConfig
	conf, err := internal.LoadConfidenceConfig("configs/fingerprint_weights.json")
	if err != nil {
		fmt.Printf("警告: 加载置信度配置失败: %v，将使用默认值\n", err)
		confidenceConfig = &internal.ConfidenceConfig{
			MatcherWeights: internal.MatcherWeights{
				Favicon: 0.9,
				Regex: map[string]float64{
					"default": 0.6,
					"server":  0.8,
					"title":   0.7,
				},
				Word: map[string]float64{
					"default": 0.4,
					"server":  0.65,
					"title":   0.55,
				},
			},
			ComboWeights: internal.ComboWeights{
				MultipleMatchers:     0.1,
				FaviconWithOthers:    0.15,
				ServerRegexWithTitle: 0.2,
			},
			MinConfidence: 0.1,
			MaxConfidence: 1.0,
		}
	} else {
		confidenceConfig = conf
	}

	// 尝试加载TCP端口配置
	tcpPortConfig, err := LoadTCPPortConfig("configs/tcp_ports.json")
	if err != nil {
		fmt.Printf("警告: 加载TCP端口配置失败: %v，将使用默认值\n", err)
	} else if config != nil {
		// 将配置中的默认端口设置到config中
		config.DefaultTCPPorts = tcpPortConfig.DefaultPorts

		// 还可以设置其他配置项
		config.MaxPortsPerService = tcpPortConfig.ScanOptions.MaxPortCount
	}

	return &Scanner{
		WebFingerprints:     webFingerprints,
		ServiceFingerprints: serviceFingerprints,
		FeatureMap:          featureMap,
		WebCluster:          &webCluster,
		FeatureDetector:     featureDetector,
		Config:              config,
		ConfidenceConfig:    confidenceConfig,
	}
}

// preprocessFingerprints 预处理指纹，优化匹配器
func preprocessFingerprints(fingerprints []internal.Fingerprint) []internal.Fingerprint {
	// 创建一个新的副本，避免修改原始数据
	processedFingerprints := make([]internal.Fingerprint, len(fingerprints))
	copy(processedFingerprints, fingerprints)

	// 遍历每个指纹
	for i := range processedFingerprints {
		// 处理HTTP请求
		for j := range processedFingerprints[i].HTTP {
			// 处理每个匹配器
			for k := range processedFingerprints[i].HTTP[j].Matchers {
				matcher := &processedFingerprints[i].HTTP[j].Matchers[k]

				// 处理word类型匹配器
				if matcher.Type == "word" && matcher.CaseInsensitive {
					// 预先转换为小写，提高匹配效率
					for l := range matcher.Words {
						matcher.Words[l] = strings.ToLower(matcher.Words[l])
					}
				}
			}
		}

		// 处理TCP请求
		for j := range processedFingerprints[i].TCP {
			// 处理每个匹配器
			for k := range processedFingerprints[i].TCP[j].Matchers {
				matcher := &processedFingerprints[i].TCP[j].Matchers[k]

				// 处理word类型匹配器
				if matcher.Type == "word" && matcher.CaseInsensitive {
					// 预先转换为小写，提高匹配效率
					for l := range matcher.Words {
						matcher.Words[l] = strings.ToLower(matcher.Words[l])
					}
				}
			}
		}
	}

	return processedFingerprints
}
func processURL(target string) bool {
	// 检查是否已有协议头（http:// 或 https:// 或 tcp://）
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") || strings.HasPrefix(target, "tcp://") {
		// 已有协议头，保持不变
		return true
	}

	// 没有协议头，添加 http://
	return false
}
func parseURL(target string) (*url.URL, error) {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("无法解析目标URL: %v", err)
	}
	return parsedURL, nil
}
func quickscan(s *Scanner, parsedURL *url.URL) ([]string, error) {

	// 第一阶段：快速HTTP探测收集特征
	httpFeatures, err := s.quickHTTPProbe(parsedURL)
	if err != nil {
		return nil, fmt.Errorf("快速HTTP探测失败: %v", err)
	}

	// 第一阶段：TCP探测（如果启用）
	var tcpFeatures []internal.FeatureKey
	if s.Config.EnableTCP {
		tcpFeatures, _ = s.quickTCPProbe(parsedURL.Hostname())
		// 忽略TCP错误，继续处理HTTP
	}

	// 合并所有特征
	var allFeatures []internal.FeatureKey
	allFeatures = append(allFeatures, httpFeatures...)
	allFeatures = append(allFeatures, tcpFeatures...)

	// 获取可能匹配的指纹
	fingerprintCounts := s.FeatureDetector.GetPotentialFingerprints(allFeatures)

	// 选择候选指纹
	candidates := s.FeatureDetector.GetTopFingerprints(
		fingerprintCounts,
		s.Config.MaxCandidates,
		s.Config.FeatureThreshold,
	)

	return candidates, nil
}
func deletehttpstatuscode(results []matcher.MatchResult) []matcher.MatchResult {
	//http-status-code在其中且有其他指纹，那么删除http-status-code
	if len(results) >= 2 {
		hasstatus := false
		statusIndex := -1
		// 一次循环完成检查和定位 http-status-code
		for i, r := range results {
			if r.ID == "http-status-code" {
				statusIndex = i
				hasstatus = true
				break
			}
		}
		// 如果存在 http-status-code 且有其他指纹，则删除它
		if hasstatus {
			// 移除指定位置的元素
			results = append(results[:statusIndex], results[statusIndex+1:]...)
		}
	}
	return results
}

// Scan 扫描目标
func (s *Scanner) Scan(target string, modelFlag string) (*ScanResult, error) {
	// 创建扫描结果
	result := &ScanResult{
		Target: target,
	}

	// 检测target有无协议头
	var protocol_target string
	hasProtocol := processURL(target)

	if !hasProtocol {
		switch modelFlag {
		case "web":
			//fmt.Println("[+] Web模式：同时尝试HTTP和HTTPS协议")
			var allResults []matcher.MatchResult

			// 先尝试HTTP协议
			httpTarget := "http://" + target
			httpURL, err := parseURL(httpTarget)
			if err == nil {
				//fmt.Printf("[+] 尝试HTTP协议: %s\n", httpTarget)
				httpResults, httpErr := s.httpScan(httpURL)
				if httpErr == nil && len(httpResults) > 0 {
					//fmt.Printf("[+] HTTP协议探测成功，找到 %d 个匹配结果\n", len(httpResults))
					allResults = append(allResults, httpResults...)
					allResults = deletehttpstatuscode(allResults)
				}
			}

			// 再尝试HTTPS协议
			httpsTarget := "https://" + target
			httpsURL, err := parseURL(httpsTarget)
			if err == nil {
				//fmt.Printf("[+] 尝试HTTPS协议: %s\n", httpsTarget)
				httpsResults, httpsErr := s.httpScan(httpsURL)
				if httpsErr == nil && len(httpsResults) > 0 {
					//fmt.Printf("[+] HTTPS协议探测成功，找到 %d 个匹配结果\n", len(httpsResults))
					allResults = append(allResults, httpsResults...)
					allResults = deletehttpstatuscode(allResults)
				}
			}

			// 对结果去重
			if len(allResults) > 0 {
				result.WebResults = UniqueResults(allResults)
				//fmt.Printf("[+] 合并后共有 %d 个唯一匹配结果\n", len(result.WebResults))
			}
		case "service":
			protocol_target = "tcp://" + target
			parsedURL, err := parseURL(protocol_target)
			if err != nil {
				return nil, fmt.Errorf("无法解析目标URL: %v", err)
			}

			tcpResults, err := s.tcpScan(parsedURL)
			if err != nil {
				return nil, err
			}
			result.TCPResults = tcpResults

		case "all", "": // 默认为all
			// HTTP扫描
			httpTarget := "http://" + target
			parsedURL, err := parseURL(httpTarget)
			if err != nil {
				return nil, fmt.Errorf("无法解析HTTP目标URL: %v", err)
			}

			webResults, err := s.httpScan(parsedURL)
			if err == nil { // 即使出错也继续TCP扫描
				result.WebResults = webResults
				result.WebResults = deletehttpstatuscode(result.WebResults)
			}

			// Service扫描
			tcpTarget := "tcp://" + target
			parsedTCPURL, err := parseURL(tcpTarget)
			if err != nil {
				return nil, fmt.Errorf("无法解析Service目标URL: %v", err)
			}

			tcpResults, err := s.tcpScan(parsedTCPURL)
			if err == nil {
				result.TCPResults = tcpResults
			}
		}
	} else {
		// 已有协议头，直接解析
		parsedURL, err := parseURL(target)
		if err != nil {
			return nil, fmt.Errorf("无法解析目标URL: %v", err)
		}

		// 根据协议决定扫描方式
		if parsedURL.Scheme == "http" || parsedURL.Scheme == "https" {
			webResults, err := s.httpScan(parsedURL)
			if err != nil {
				return nil, err
			}
			result.WebResults = webResults
			result.WebResults = deletehttpstatuscode(result.WebResults)
		} else if parsedURL.Scheme == "tcp" {
			tcpResults, err := s.tcpScan(parsedURL)
			if err != nil {
				return nil, err
			}
			result.TCPResults = tcpResults
		}
	}

	return result, nil
}
func (s *Scanner) httpScan(parsedURL *url.URL) ([]matcher.MatchResult, error) {
	var results []matcher.MatchResult

	// 第一阶段：快速探测收集特征（暂时注释掉，用于测试）
	/*
		candidates, err := quickscan(s, parsedURL)
		if err != nil {
			return nil, err
		}
	*/

	// 直接使用空的candidates进行测试
	//fmt.Println("正在测试preciseHTTPMatch函数，跳过quickscan")
	candidates := []string{}

	// 如果需要测试某些特定的指纹ID，可以取消下面的注释并添加指纹ID
	candidates = []string{"thinkphp", "nginx", "wordpress"}

	// 第二阶段：精确匹配HTTP指纹
	results, err := s.preciseHTTPMatch(parsedURL, candidates)
	if err != nil {
		return nil, fmt.Errorf("精确HTTP探测失败: %v", err)
	}
	return results, nil
}

func (s *Scanner) tcpScan(parsedURL *url.URL) ([]matcher.MatchResult, error) {
	var results []matcher.MatchResult
	/*
		// 第一阶段：快速探测收集特征
		candidates, err := quickscan(s, parsedURL)
		if err != nil {
			return nil, err
		}
	*/

	candidates := []string{}

	// 如果需要测试某些特定的指纹ID，可以取消下面的注释并添加指纹ID
	candidates = []string{"thinkphp", "nginx", "wordpress"}
	// 第二阶段：精确匹配TCP指纹
	results, err := s.preciseTCPMatch(parsedURL.String(), candidates)
	if err != nil {
		return nil, fmt.Errorf("精确TCP探测失败: %v", err)
	}
	return results, nil
}

// selectCommonFingerprints 返回常见指纹ID作为回退
func (s *Scanner) selectCommonFingerprints() []string {
	// 此处可以返回一些常见的指纹ID
	// 实际实现可能需要根据WebCluster中的稀有度等进行排序
	// 为简化示例，此处返回空
	return []string{}
}

// UniqueResults 结果去重
func UniqueResults(results []matcher.MatchResult) []matcher.MatchResult {
	seen := make(map[string]bool)
	var unique []matcher.MatchResult

	for _, result := range results {
		// 使用ID作为唯一键
		if !seen[result.ID] {
			seen[result.ID] = true
			unique = append(unique, result)
		}
	}

	return unique
}
