package main

import (
	"encoding/json"
	"fmt" // 请根据您的实际 Go 模块路径修改这里
	"nebulafinger/internal"
	"os"
	"strings"
)

// buildFeatureFingerprintMap 从指纹中提取特征并构建特征-指纹关联映射
// webFingerprints 和 serviceFingerprints 分别是从 web_fingerprint_v4.json 和 service_fingerprint_v4.json 解析出的指纹列表
func buildFeatureFingerprintMap(webFingerprints []internal.Fingerprint, serviceFingerprints []internal.Fingerprint) map[internal.FeatureKey][]string {
	// featureMap 用于存储特征到指纹ID列表的映射
	featureMap := make(map[internal.FeatureKey][]string)

	// 处理 Web 指纹列表
	for _, fp := range webFingerprints {
		// 遍历当前 Web 指纹中的所有 HTTP 请求探针
		for _, req := range fp.HTTP {
			// 提取 Path 特征
			for _, path := range req.Path { // !!! 直接从 req.Path 获取
				normalizedPath := strings.ToLower(strings.TrimSpace(path))
				// 将 "{{BaseURL}}/" 识别为基础路径特征
				if normalizedPath == "{{baseurl}}/" {
					normalizedPath = "/" // 在特征 Key 中简化表示为 "/"
				}
				// 提取所有非空且非占位符的路径作为特征
				if normalizedPath != "" && !strings.HasPrefix(normalizedPath, "{{") {
					// 构建特征 Key，格式为 "path:normalized/path"
					key := internal.FeatureKey(fmt.Sprintf("path:%s", normalizedPath))
					// 将当前指纹 ID 添加到该特征对应的列表中 (确保唯一)
					featureMap[key] = appendUnique(featureMap[key], fp.ID)
				}
			}

			// 提取匹配器中的特征
			for _, matcher := range req.Matchers {
				part := strings.ToLower(strings.TrimSpace(matcher.Part))
				matcherType := strings.ToLower(strings.TrimSpace(matcher.Type))

				switch matcherType {
				case "status":
					// 提取状态码作为特征
					if part == "status" || part == "all" || part == "" { // 假设 status 匹配器的 part 是 "status", "all" 或为空
						for _, status := range matcher.Status {
							// 特征 Key 格式为 "status:statusCode"
							key := internal.FeatureKey(fmt.Sprintf("status:%d", status))
							featureMap[key] = appendUnique(featureMap[key], fp.ID)
						}
					}
				case "word":
					// 如果匹配部分是 Header 或 Body
					if part == "header" || part == "body" || part == "all" || part == "" { // 包含空 part 的情况
						for _, word := range matcher.Words {
							normalizedWord := strings.ToLower(strings.TrimSpace(word))
							if normalizedWord != "" {
								// 提取 Header 中的特定词语作为特征（例如 Server, X-Powered-By 的值）
								// 这里需要更精细的逻辑来识别 Header 名称和值
								// 简化处理：如果 Matcher Part 是 Header 且 Word 包含常见 Header 名称
								if part == "header" && (strings.Contains(normalizedWord, "server:") || strings.Contains(normalizedWord, "x-powered-by:") || strings.Contains(normalizedWord, "set-cookie:")) {
									key := internal.FeatureKey(fmt.Sprintf("header_word:%s:%s", part, normalizedWord))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								} else if part == "body" && (strings.Contains(normalizedWord, "<title") || strings.Contains(normalizedWord, "<h1") || strings.Contains(normalizedWord, "welcome") || strings.Contains(normalizedWord, "test page")) {
									// 提取 Body 中可能指示服务类型的词语作为特征
									key := internal.FeatureKey(fmt.Sprintf("body_word:%s", normalizedWord))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								} else if part == "all" { // 如果匹配所有部分
									key := internal.FeatureKey(fmt.Sprintf("word_all:%s", normalizedWord))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								}
							}
						}
					}
				case "regex":
					// 如果匹配部分是 Header 或 Body
					if part == "header" || part == "body" || part == "all" || part == "" { // 包含空 part 的情况
						// 遍历 matcher.Regex 数组
						for _, regex := range matcher.Regex {
							normalizedRegex := strings.ToLower(strings.TrimSpace(regex))
							if normalizedRegex != "" {
								// 提取 Header 中特定模式的 Regex 作为特征
								if part == "header" && (strings.Contains(normalizedRegex, "server:") || strings.Contains(normalizedRegex, "x-powered-by:") || strings.Contains(normalizedRegex, "set-cookie:")) {
									key := internal.FeatureKey(fmt.Sprintf("header_regex:%s:%s", part, normalizedRegex))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								} else if part == "body" && (strings.Contains(normalizedRegex, "<title") || strings.Contains(normalizedRegex, "<h1")) {
									// 提取 Body 中特定模式的 Regex (如标题、H1) 作为特征
									key := internal.FeatureKey(fmt.Sprintf("body_regex:%s", normalizedRegex))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								} else if part == "all" { // 如果匹配所有部分
									key := internal.FeatureKey(fmt.Sprintf("regex_all:%s", normalizedRegex))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								}
							}
						}
					}
				case "favicon":
					// 如果匹配部分是 Favicon
					if part == "favicon" || part == "all" || part == "" { // 假设 favicon 匹配器的 part 是 "favicon", "all" 或为空
						for _, hash := range matcher.Favicon_hash {
							normalizedHash := strings.ToLower(strings.TrimSpace(hash))
							if normalizedHash != "" {
								// 特征 Key 格式为 "favicon:hash_value"
								key := internal.FeatureKey(fmt.Sprintf("favicon:%s", normalizedHash))
								featureMap[key] = appendUnique(featureMap[key], fp.ID)
							}
						}
					}
					// 可以根据需要添加其他匹配器类型 (binary, xpath, dsl) 的特征提取，
					// 前提是这些匹配器能够提供有用的快速扫描特征。
				}
			}
		}
	}

	// 处理 Service 指纹列表
	for _, fp := range serviceFingerprints {
		// 遍历当前 Service 指纹中的所有 TCP 请求探针
		// 检查是否有 TCP 请求，避免处理实际上是 Web 指纹的数据
		if len(fp.TCP) == 0 {
			continue
		}
		for _, req := range fp.TCP {
			port := strings.TrimSpace(req.Port)
			if port != "" {
				// 特征 Key 格式为 "port:port_number"
				key := internal.FeatureKey(fmt.Sprintf("port:%s", port))
				featureMap[key] = appendUnique(featureMap[key], fp.ID)
			}

			// TCP 请求也可能有 Matchers (您之前的结构体和示例中 TCPRequest 是有 Matchers 的)
			for _, matcher := range req.Matchers { // 从 req.Matchers 获取
				part := strings.ToLower(strings.TrimSpace(matcher.Part))
				matcherType := strings.ToLower(strings.TrimSpace(matcher.Type))

				if part == "" { // 如果未指定匹配部分，默认为 "response"
					part = "response"
				}

				switch matcherType {
				case "word":
					if part == "response" || part == "all" {
						for _, word := range matcher.Words {
							normalizedWord := strings.ToLower(strings.TrimSpace(word))
							if normalizedWord != "" {
								// 提取服务 Banner 中包含关键信息的词语作为特征
								if strings.Contains(normalizedWord, "openssh") || strings.Contains(normalizedWord, "vsftpd") || strings.Contains(normalizedWord, "ftp") || strings.Contains(normalizedWord, "ssh") || strings.Contains(normalizedWord, "server") || strings.Contains(normalizedWord, "protocol") {
									// 特征 Key 格式为 "service_banner_word:port:normalized_word"（包含端口信息）
									key := internal.FeatureKey(fmt.Sprintf("service_banner_word:%s:%s", port, normalizedWord))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								}
							}
						}
					}
				case "regex":
					if part == "response" || part == "all" {
						for _, regex := range matcher.Regex {
							normalizedRegex := strings.ToLower(strings.TrimSpace(regex))
							if normalizedRegex != "" {
								// 提取服务 Banner 中特定模式的 Regex 作为特征
								if strings.Contains(normalizedRegex, "version") || strings.Contains(normalizedRegex, "protocol") || strings.Contains(normalizedRegex, "service") {
									// 特征 Key 格式为 "service_banner_regex:port:normalized_regex"（包含端口信息）
									key := internal.FeatureKey(fmt.Sprintf("service_banner_regex:%s:%s", port, normalizedRegex))
									featureMap[key] = appendUnique(featureMap[key], fp.ID)
								}
							}
						}
					}
				}
			}

			// 提取 Extractors 中的特征 (如果需要)
			if req.Extractors != nil {
				for _, extractor := range req.Extractors {
					extractorType := strings.ToLower(strings.TrimSpace(extractor.Type))
					switch extractorType {
					case "regex":
						// 处理 extractor.Regex 作为数组
						for _, regex := range extractor.Regex {
							if regex != "" {
								// 可以将 Extractor 的 Regex 也作为一种特征，表示如果提取器能匹配到这个模式，可能是什么服务
								key := internal.FeatureKey(fmt.Sprintf("service_extractor_regex:%s:%s", port, regex))
								featureMap[key] = appendUnique(featureMap[key], fp.ID)
							}
						}
					}
				}
			}
		}
	}

	return featureMap // 返回构建好的特征映射
}

// appendUnique 辅助函数，将字符串添加到切片中，前提是不存在
// Helper function to append a string to a slice only if it's not already present
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func main() {
	// --- 示例用法 ---
	// 在实际应用中，你应该从文件中加载 JSON 数据

	// 简化的 Web 指纹示例 (包含您提供的 office_anywhere 和 syncserver_s650)
	webJSON, err := os.ReadFile("configs/web_fingerprint_v4.json")
	if err != nil {
		fmt.Printf("Error reading web_test.json: %v\n", err)
		return
	}
	var webFingerprints []internal.Fingerprint
	// 解析 Web JSON
	err = json.Unmarshal([]byte(webJSON), &webFingerprints)
	if err != nil {
		fmt.Printf("Error unmarshalling web JSON: %v\n", err)
		return
	}

	// 简化的 Service 指纹示例 (使用假设的 TCP 指纹结构)
	// 请用实际的 service_fingerprint_v4.json 内容替换这里的示例
	serviceJSON, err := os.ReadFile("configs/service_fingerprint_v4.json")
	if err != nil {
		fmt.Printf("Error reading service_test.json: %v\n", err)
		return
	}

	var serviceFingerprints []internal.Fingerprint
	// 解析 Service JSON
	err = json.Unmarshal([]byte(serviceJSON), &serviceFingerprints)
	if err != nil {
		fmt.Printf("Error unmarshalling service JSON: %v\n", err)
		return
	}

	// 构建映射
	featureToFingerprintMap := buildFeatureFingerprintMap(webFingerprints, serviceFingerprints)

	file, err := os.Create("feature_map.json")
	if err != nil {
		// 处理错误
		fmt.Printf("Error creating file: %v\n", err)
		return // 或者 log.Fatal(err)
	}
	defer file.Close() // 确保文件关闭

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // 可选：格式化输出，使其更易读
	err = encoder.Encode(featureToFingerprintMap)
	if err != nil {
		// 处理编码错误
		fmt.Printf("Error encoding map to JSON: %v\n", err)
		return
	}
	fmt.Println("特征映射已保存到 feature_map.json")

	// 打印结果映射

}
