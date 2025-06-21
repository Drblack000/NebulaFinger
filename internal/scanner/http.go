package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"nebulafinger/internal"
	"nebulafinger/internal/cluster"
	"nebulafinger/internal/detector"
	"nebulafinger/internal/matcher"
	"nebulafinger/internal/utils"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// headerContains 检查HTTP头是否包含指定的字符串
func headerContains(headers map[string][]string, substr string) bool {
	// 遍历所有header
	for name, values := range headers {
		// 检查header名称
		if strings.Contains(strings.ToLower(name), strings.ToLower(substr)) {
			return true
		}
		// 检查header值
		for _, value := range values {
			// 构造"name: value"格式的字符串
			headerStr := fmt.Sprintf("%s: %s", strings.ToLower(name), strings.ToLower(value))
			if strings.Contains(headerStr, strings.ToLower(substr)) {
				return true
			}
		}
	}
	return false
}

// quickHTTPProbe 执行快速HTTP探测
func (s *Scanner) quickHTTPProbe(parsedURL *url.URL) ([]internal.FeatureKey, error) {
	var features []internal.FeatureKey

	// 创建HTTP客户端选项
	clientOptions := utils.DefaultHTTPClientOptions()
	clientOptions.Timeout = s.Config.Timeout

	// 创建HTTP客户端
	client, err := utils.NewHTTPClient(clientOptions)
	if err != nil {
		return nil, fmt.Errorf("创建HTTP客户端失败: %v", err)
	}

	// 执行GET请求
	fullURL := parsedURL.String()

	// 创建请求
	request := utils.HTTPRequest{
		Method: "GET",
		URL:    fullURL,
	}

	// 发送请求
	resp, err := utils.SendRequest(client, request, clientOptions)
	if err != nil {
		// 尝试添加端口号，如果没有指定端口
		if !strings.Contains(parsedURL.Host, ":") {
			altURL := parsedURL.Scheme + "://" + parsedURL.Host + ":80" + parsedURL.Path
			fmt.Printf("原始请求失败，尝试使用显式端口: %s\n", altURL)

			// 尝试使用备用URL
			request.URL = altURL
			resp, err = utils.SendRequest(client, request, clientOptions)

			// 如果仍然失败，返回详细错误
			if err != nil {
				return nil, fmt.Errorf("HTTP请求失败: %v (URL: %s, 超时: %v)",
					err, fullURL, s.Config.Timeout)
			}
		} else {
			return nil, fmt.Errorf("HTTP请求失败: %v (URL: %s, 超时: %v)",
				err, fullURL, s.Config.Timeout)
		}
	}
	defer resp.Body.Close()

	fmt.Printf("HTTP请求成功，状态码: %d\n", resp.StatusCode)

	// 读取响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应体失败: %v", err)
	}
	body := string(bodyBytes)

	// 创建HTTP响应对象
	httpResp := &detector.HTTPResponse{
		URL:        parsedURL.String(),
		Path:       parsedURL.Path,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}

	// 如果启用favicon检测
	if s.Config.EnableFavicon {
		// 直接使用原始URL获取favicon，现在我们的FetchFavicon函数已经能从HTML中提取favicon URL
		faviconHash, err := detector.FetchFavicon(fullURL)
		if err == nil {
			httpResp.FaviconHash = faviconHash
			fmt.Printf("成功获取favicon哈希: %s\n", faviconHash)
		} else {
			fmt.Printf("获取favicon失败: %v\n", err)
		}
	}

	// 提取特征
	features = s.FeatureDetector.ExtractHTTPFeatures(httpResp)

	return features, nil
}

// preciseHTTPMatch 执行精确HTTP匹配
func (s *Scanner) preciseHTTPMatch(parsedURL *url.URL, candidates []string) ([]matcher.MatchResult, error) {
	var results []matcher.MatchResult

	//判断端口是否存在
	targetURI, err := url.Parse(parsedURL.String())
	var targetPorts []uint16
	if err == nil && targetURI.Port() != "" {
		// URI中指定了端口
		portInt, err := strconv.ParseUint(targetURI.Port(), 10, 16)
		if err == nil {
			targetPort := uint16(portInt)
			//fmt.Printf("[TCP] 目标URI中指定了端口: %d\n", targetPort)
			targetPorts = append(targetPorts, targetPort)
		}
	} else {
		// URI中没有指定端口，使用默认端口序列
		if parsedURL.Scheme == "http" {
			targetPorts = []uint16{80}
		} else if parsedURL.Scheme == "https" {
			targetPorts = []uint16{443}
		}
	}

	// 记录开始扫描

	//fmt.Printf("[HTTP] 开始对 %s 进行HTTP精确匹配\n", parsedURL.String())
	// 对每个端口执行匹配，收集所有匹配结果
	for _, port := range targetPorts {
		//fmt.Printf("[TCP] 开始探测端口 %d\n", port)
		portResults, found := s.matchHttpPortFingerprints(parsedURL, port, candidates)
		if found {
			//fmt.Printf("[TCP] 端口 %d 匹配成功，找到 %d 个结果\n", port, len(portResults))
			results = append(results, portResults...)
			// 继续探测其他端口
		}
	}

	return results, nil
}

type HttpClusterInfo struct {
	Name    string
	Path    string
	Cluster cluster.ClusterExecute
	Rarity  int
	Default bool
}

func uniquePathClusters(pathClusters []HttpClusterInfo) []HttpClusterInfo {
	seen := make(map[string]bool)
	var unique []HttpClusterInfo
	for _, cluster := range pathClusters {
		if !seen[cluster.Path] {
			seen[cluster.Path] = true
			unique = append(unique, cluster)
		}
	}
	return unique
}

// 这里使用core.go中定义的uniqueResults函数
func (s *Scanner) matchHttpPortFingerprints(parsedURL *url.URL, port uint16, candidates []string) ([]matcher.MatchResult, bool) {

	// 收集所有需要请求的路径信息
	var pathClusters []HttpClusterInfo
	var results []matcher.MatchResult
	// 先添加默认路径，这些是优先级最高的
	for name, cluster := range s.WebCluster.WebDefault {
		pathClusters = append(pathClusters, HttpClusterInfo{
			Name:    fmt.Sprintf("%s", name),
			Path:    cluster.Path,
			Rarity:  cluster.Rarity,
			Default: true,
		})
	}

	// 再添加其他路径
	for name, cluster := range s.WebCluster.WebOther {
		pathClusters = append(pathClusters, HttpClusterInfo{
			Name:    fmt.Sprintf("%s", name),
			Path:    cluster.Path,
			Rarity:  cluster.Rarity,
			Default: false,
		})
	}
	// 再添加其他路径
	for name, cluster := range s.WebCluster.WebFavicon {
		pathClusters = append(pathClusters, HttpClusterInfo{
			Name:    fmt.Sprintf("%s", name),
			Path:    cluster.Path,
			Rarity:  cluster.Rarity,
			Default: false,
		})
	}
	//pathClusters路径去重
	pathClusters = uniquePathClusters(pathClusters)
	//获取favicon指纹
	var faviconClusters []HttpClusterInfo
	for i, clusterExec := range s.WebCluster.WebFavicon {
		name := fmt.Sprintf("WebFavicon-%d", i) // 生成一个名称
		faviconClusters = append(faviconClusters, HttpClusterInfo{
			Name:    name,
			Cluster: clusterExec,
			Rarity:  clusterExec.Rarity,
		})
	}
	// 尝试HttpDefault
	httpDefaultResults := s.matchHttpDefault(parsedURL, port, candidates, pathClusters, faviconClusters)
	results = append(results, httpDefaultResults...)

	// 3. 如果HttpDefault没有匹配，尝试HttpOther
	httpOtherResults := s.matchHttpOther(parsedURL, port, candidates, pathClusters, faviconClusters)
	results = append(results, httpOtherResults...)

	if len(results) > 0 {
		return results, true
	}
	// 没有找到任何匹配
	return nil, false
}

func (s *Scanner) matchHttpDefault(parsedURL *url.URL, port uint16, candidates []string, pathClusters []HttpClusterInfo, faviconClusters []HttpClusterInfo) []matcher.MatchResult {
	var results []matcher.MatchResult
	// 收集包含该端口的HttpDefault指纹
	var defaultClusters []HttpClusterInfo

	for i, clusterExec := range s.WebCluster.WebDefault {
		name := fmt.Sprintf("WebDefault-%d", i) // 生成一个名称
		defaultClusters = append(defaultClusters, HttpClusterInfo{
			Name:    name,
			Cluster: clusterExec,
			Rarity:  clusterExec.Rarity,
		})
	}
	// 执行匹配
	matched, results := s.probeHttpService(parsedURL, port, defaultClusters, candidates, pathClusters, faviconClusters)
	if matched {
		return results
	}
	return nil
}

func (s *Scanner) matchHttpOther(parsedURL *url.URL, port uint16, candidates []string, pathClusters []HttpClusterInfo, faviconClusters []HttpClusterInfo) []matcher.MatchResult {
	var results []matcher.MatchResult
	// 收集包含该端口的HttpOther指纹
	var otherClusters []HttpClusterInfo

	for i, clusterExec := range s.WebCluster.WebOther {
		name := fmt.Sprintf("WebOther-%d", i) // 生成一个名称
		otherClusters = append(otherClusters, HttpClusterInfo{
			Name:    name,
			Cluster: clusterExec,
			Rarity:  clusterExec.Rarity,
		})
	}
	// 执行匹配
	matched, results := s.probeHttpService(parsedURL, port, otherClusters, candidates, pathClusters, faviconClusters)
	if matched {
		return results
	}
	return nil

}

// probeHttpService 探测HTTP服务
func (s *Scanner) probeHttpService(parsedURL *url.URL, port uint16, matchingClusters []HttpClusterInfo, candidates []string, pathClusters []HttpClusterInfo, faviconClusters []HttpClusterInfo) (bool, []matcher.MatchResult) {
	// 创建一个切片收集所有匹配的结果
	var allResults []matcher.MatchResult

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: s.Config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过SSL证书验证
			},
		},
	}

	// 预先获取favicon哈希（如果启用）
	var faviconHash string
	if s.Config.EnableFavicon {
		hash, err := detector.FetchFavicon(parsedURL.String())
		if err == nil {
			faviconHash = hash
		}
	}

	// 对每个路径执行请求并进行匹配
	for _, cluster := range pathClusters {
		// 构建请求URL
		reqURL := parsedURL.Scheme + "://" + parsedURL.Host + cluster.Path
		//fmt.Printf("[HTTP] 请求路径: %s\n", reqURL)

		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			//fmt.Printf("[HTTP] 创建请求失败: %v\n", err)
			continue
		}

		// 设置User-Agent
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		// 设置Accept请求头
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")

		resp, err := client.Do(req)
		if err != nil {
			//fmt.Printf("[HTTP] 请求失败: %v\n", err)
			continue
		}

		// 读取响应体
		bodyBytes, err := io.ReadAll(resp.Body)
		resp.Body.Close() // 确保关闭响应体

		if err != nil {
			//fmt.Printf("[HTTP] 读取响应体失败: %v\n", err)
			continue
		}
		body := strings.ToLower(string(bodyBytes))

		// 转换Headers格式
		headers := make(map[string][]string)
		for name, values := range resp.Header {
			headers[name] = values
		}

		// 创建HTTP响应对象
		httpResp := &matcher.HTTPResponse{
			URL:         reqURL,
			Path:        cluster.Path,
			StatusCode:  resp.StatusCode,
			Headers:     headers,
			Body:        body,
			FaviconHash: faviconHash,
		}

		// 遍历matchingClusters集群指纹进行匹配
		for _, clusterInfo := range matchingClusters {
			// 遍历集群中的每个操作符（指纹）
			for _, fingerprint := range clusterInfo.Cluster.Operators {
				matched := false

				// 遍历所有Extractors进行匹配
				for _, matcher := range fingerprint.Matchers {
					// 检查word类型提取器
					if matcher.Type == "word" && len(matcher.Words) > 0 {
						if len(matcher.Words) > 1 {
							if matcher.Condition == "and" {
								matched = true // 默认匹配成功，除非有一个词不匹配
								for _, word := range matcher.Words {
									// 只要body或header匹配任一个就算成功
									if !strings.Contains(httpResp.Body, word) && !headerContains(httpResp.Headers, word) {
										matched = false
										break
									}
								}
							} else if matcher.Condition == "or" || matcher.Condition == "" {
								matched = false // 默认匹配失败，除非有一个词匹配
								for _, word := range matcher.Words {
									// 只要body或header匹配任一个就算成功
									if strings.Contains(httpResp.Body, word) || headerContains(httpResp.Headers, word) {
										matched = true
										break
									}
								}
							}
						} else {
							// 单个单词的情况
							word := matcher.Words[0]
							// 只要body或header匹配任一个就算成功
							if strings.Contains(httpResp.Body, word) || headerContains(httpResp.Headers, word) {
								matched = true
							}
						}
					}

					// 检查regex类型提取器
					if matcher.Type == "regex" && len(matcher.Regex) > 0 {
						for _, regexStr := range matcher.Regex {
							// 编译正则表达式
							regex, err := regexp.Compile(regexStr)
							if err != nil {
								//fmt.Printf("[TCP] 正则表达式编译失败: %v\n", err)
								continue
							}

							// 尝试对每一行进行匹配，处理可能存在的多行响应
							httpResp.Body = strings.TrimRight(httpResp.Body, "\r")
							if regex.MatchString(httpResp.Body) {
								matched = true
								break
							}

							// 如果已经匹配成功，退出循环
							if matched {
								break
							}
						}
					}

					// 如果已经匹配成功，退出循环
					if matched {
						break
					}
				}

				// 如果匹配成功，创建结果并添加到结果列表中
				if matched {
					// 计算置信度
					var confidence float64 = 0.0

					// 遍历所有匹配器，查找匹配成功的匹配器类型
					for _, m := range fingerprint.Matchers {
						if m.Type == "word" {
							// 检查是否包含特殊关键词
							for _, word := range m.Words {
								lowWord := strings.ToLower(word)
								if strings.Contains(lowWord, "server:") {
									confidence = s.ConfidenceConfig.MatcherWeights.Word["server"]
									break
								} else if strings.Contains(lowWord, "<title") || strings.Contains(lowWord, "title>") {
									confidence = s.ConfidenceConfig.MatcherWeights.Word["title"]
									break
								}
							}
							// 如果没有特殊关键词，使用默认值
							if confidence == 0.0 {
								confidence = s.ConfidenceConfig.MatcherWeights.Word["default"]
							}
						} else if m.Type == "regex" {
							// 检查是否包含特殊正则
							for _, regex := range m.Regex {
								lowRegex := strings.ToLower(regex)
								if strings.Contains(lowRegex, "server:") {
									confidence = s.ConfidenceConfig.MatcherWeights.Regex["server"]
									break
								} else if strings.Contains(lowRegex, "<title") || strings.Contains(lowRegex, "title>") {
									confidence = s.ConfidenceConfig.MatcherWeights.Regex["title"]
									break
								}
							}
							// 如果没有特殊正则，使用默认值
							if confidence == 0.0 {
								confidence = s.ConfidenceConfig.MatcherWeights.Regex["default"]
							}
						}
					}

					// 确保至少有最小置信度
					if confidence < s.ConfidenceConfig.MinConfidence {
						confidence = s.ConfidenceConfig.MinConfidence
					}

					result := matcher.MatchResult{
						ID:         fingerprint.ID,
						Name:       fingerprint.Info.Name,
						Confidence: confidence, // 使用计算的置信度
						Details:    make(map[string]string),
						Tags:       []string{fingerprint.Info.Tags},
					}

					// 添加请求URL路径
					result.Details["url"] = httpResp.URL

					// 添加状态码
					result.Details["status_code"] = fmt.Sprintf("%d", httpResp.StatusCode)

					// 提取并添加网页标题
					titleRegex := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
					titleMatches := titleRegex.FindStringSubmatch(httpResp.Body)
					if len(titleMatches) > 1 {
						result.Details["title"] = strings.TrimSpace(titleMatches[1])
					}

					// 提取详细信息
					for _, extractor := range fingerprint.Extractors {
						if extractor.Type == "regex" && len(extractor.Regex) > 0 {
							regexStr := extractor.Regex[0]
							regex, err := regexp.Compile(regexStr)
							if err == nil {
								// 对每一行尝试提取详细信息
								responseLines := strings.Split(httpResp.Body, "\n")
								for _, line := range responseLines {
									line = strings.TrimRight(line, "\r")
									matches := regex.FindStringSubmatch(line)
									if len(matches) > 1 {
										result.Details[extractor.Name] = matches[1]
										break
									} else if len(matches) == 1 {
										result.Details[extractor.Name] = matches[0]
										break
									}
								}
							}
						} else if extractor.Type == "word" && len(extractor.Regex) > 0 {
							// 也支持word类型的提取器
							word := extractor.Regex[0]
							if strings.Contains(httpResp.Body, word) {
								result.Details[extractor.Name] = word
							}
						}
					}

					// 将结果添加到列表中，而不是立即返回
					allResults = append(allResults, result)
				}
			}
		}
		if len(allResults) == 0 && httpResp.StatusCode != 0 {
			// 如果BPStat为true，则不处理只有状态码没有匹配指纹的情况
			if s.Config.BPStat {
				continue
			}

			result := matcher.MatchResult{
				ID:         "http-status-code",
				Name:       "http-status-code",
				Details:    make(map[string]string),
				Confidence: s.ConfidenceConfig.MatcherWeights.Favicon, // Favicon有最高置信度
			}
			result.Details["url"] = httpResp.URL
			result.Details["status_code"] = fmt.Sprintf("%d", httpResp.StatusCode)
			// 提取并添加网页标题
			titleRegex := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
			titleMatches := titleRegex.FindStringSubmatch(httpResp.Body)
			if len(titleMatches) > 1 {
				result.Details["title"] = strings.TrimSpace(titleMatches[1])
			}

			allResults = append(allResults, result)
			continue
		}
	}

	// 遍历faviconClusters集群指纹进行匹配
	if s.Config.EnableFavicon && faviconHash != "" {
		//fmt.Printf("[HTTP] 尝试使用Favicon哈希进行匹配: %s\n", faviconHash)
		for _, clusterInfo := range faviconClusters {
			// 遍历集群中的每个操作符（指纹）
			for _, fingerprint := range clusterInfo.Cluster.Operators {
				matched := false

				// 遍历所有Matchers进行匹配
				for _, matcher := range fingerprint.Matchers {
					// 检查favicon类型匹配器
					if matcher.Type == "favicon" && len(matcher.Favicon_hash) > 0 {
						for _, hash := range matcher.Favicon_hash {
							if hash == faviconHash {
								matched = true
								//fmt.Printf("[HTTP] Favicon哈希匹配成功: %s -> %s\n", hash, fingerprint.Info.Name)
								break
							}
						}
					}

					// 如果已经匹配成功，退出循环
					if matched {
						break
					}
				}

				// 如果匹配成功，创建结果并添加到结果列表中
				if matched {
					result := matcher.MatchResult{
						ID:         fingerprint.ID,
						Name:       fingerprint.Info.Name,
						Confidence: s.ConfidenceConfig.MatcherWeights.Favicon, // Favicon有最高置信度
						Details:    make(map[string]string),
						Tags:       []string{fingerprint.Info.Tags},
					}
					result.Details["favicon_match"] = "true"
					result.Details["favicon_hash"] = faviconHash

					// 将结果添加到列表中
					allResults = append(allResults, result)
				}
			}
		}
	}

	// 检查是否找到了至少一个匹配
	if len(allResults) > 0 {

		return true, allResults
	}

	return false, nil
}
