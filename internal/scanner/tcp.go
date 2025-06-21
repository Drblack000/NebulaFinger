package scanner

import (
	"fmt"
	"io"
	"nebulafinger/internal"
	"nebulafinger/internal/cluster"
	"nebulafinger/internal/detector"
	"nebulafinger/internal/matcher"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 在文件顶部定义ClusterInfo类型
type ClusterInfo struct {
	Name    string
	Cluster cluster.ClusterExecute
	Rarity  int
}

// quickTCPProbe 执行快速TCP探测
func (s *Scanner) quickTCPProbe(host string) ([]internal.FeatureKey, error) {
	var features []internal.FeatureKey

	// 如果未启用TCP检测，直接返回
	if !s.Config.EnableTCP {
		return features, nil
	}

	fmt.Printf("[TCP] 开始快速TCP探测: %s\n", host)

	// 获取要扫描的端口列表
	var ports []string

	// 如果用户配置了自定义端口
	if len(s.Config.CustomPorts) > 0 {
		fmt.Printf("[TCP] 使用自定义端口列表: %v\n", s.Config.CustomPorts)
		ports = s.Config.CustomPorts
	} else {
		// 从指纹聚类中获取常见端口
		if s.WebCluster != nil {
			ports = getCommonPorts(*s.WebCluster)
		} else {
			// 使用默认端口
			ports = []string{"21", "22", "25", "80", "443", "1521", "3306", "5432", "6379", "8080", "8443"}
		}
		fmt.Printf("[TCP] 使用常见TCP端口列表: %v\n", ports)
	}

	// 结果通道
	type probeResult struct {
		Port     string
		Features []internal.FeatureKey
		Error    error
	}

	resultChan := make(chan probeResult, len(ports))
	var wg sync.WaitGroup

	// 限制并发
	semaphore := make(chan struct{}, s.Config.Concurrency)

	// 对每个端口进行探测
	for _, port := range ports {
		wg.Add(1)
		semaphore <- struct{}{} // 获取信号量

		go func(port string) {
			defer wg.Done()
			defer func() { <-semaphore }() // 释放信号量

			address := fmt.Sprintf("%s:%s", host, port)
			fmt.Printf("[TCP] 尝试连接 %s\n", address)

			// 连接TCP服务
			conn, err := net.DialTimeout("tcp", address, s.Config.Timeout)
			if err != nil {
				fmt.Printf("[TCP] 连接失败 %s: %v\n", address, err)
				resultChan <- probeResult{Port: port, Error: err}
				return
			}

			fmt.Printf("[TCP] 连接成功 %s\n", address)

			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(3 * time.Second))

			// 发送HTTP GET请求（通用探测）
			httpRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n", host)
			_, err = conn.Write([]byte(httpRequest))
			if err != nil {
				conn.Close()
				fmt.Printf("[TCP] 发送数据失败 %s: %v\n", address, err)
				resultChan <- probeResult{Port: port, Error: err}
				return
			}

			// 读取响应
			buffer := make([]byte, 2048)
			var banner strings.Builder
			for {
				n, err := conn.Read(buffer)
				if err != nil {
					if err != io.EOF {
						fmt.Printf("[TCP] 读取数据失败 %s: %v\n", address, err)
					}
					break
				}
				banner.Write(buffer[:n])
				// 只读取前2048字节
				if banner.Len() >= 2048 {
					break
				}
			}

			// 关闭连接
			conn.Close()

			// 创建TCP响应对象
			tcpResp := &detector.TCPResponse{
				Host:     host,
				Port:     port,
				Response: banner.String(),
			}

			// 提取特征
			portFeatures := s.FeatureDetector.ExtractTCPFeatures(tcpResp)
			fmt.Printf("[TCP] 从端口 %s 提取了 %d 个特征\n", port, len(portFeatures))

			resultChan <- probeResult{Port: port, Features: portFeatures}
		}(port)
	}

	// 等待所有协程完成
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果
	for result := range resultChan {
		if result.Error == nil && len(result.Features) > 0 {
			features = append(features, result.Features...)
		}
	}

	fmt.Printf("[TCP] 快速TCP探测完成，共获取 %d 个特征\n", len(features))
	return features, nil
}

// isValidPort 检查端口是否为有效的单个数字端口（为避免循环引用而复制）
func isValidPort(port string) bool {
	// 检查端口是否为纯数字
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	// 确保端口不为空且在有效范围内
	if port == "" {
		return false
	}
	// 检查端口长度，最多5位数字
	if len(port) > 5 {
		return false
	}
	return true
}

// extractValidPorts 从可能包含多个端口或端口范围的字符串中提取有效端口（为避免循环引用而复制）
func extractValidPorts(portsStr string) []string {
	var result []string

	// 处理逗号分隔的端口列表
	parts := strings.Split(portsStr, ",")
	for _, part := range parts {
		// 处理端口范围 (例如 "1000-2000")
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 && isValidPort(rangeParts[0]) && isValidPort(rangeParts[1]) {
				// 处理端口范围
				start, _ := strconv.Atoi(rangeParts[0])
				end, _ := strconv.Atoi(rangeParts[1])

				// 限制范围大小，防止过大的范围导致资源占用过多
				if end-start > 20 {
					end = start + 20 // 最多处理20个端口
				}

				// 添加范围内的所有端口
				for port := start; port <= end; port++ {
					result = append(result, strconv.Itoa(port))
				}
			}
		} else if isValidPort(part) {
			// 单个有效端口
			result = append(result, part)
		}
	}

	return result
}

// 获取常见端口
func getCommonPorts(webCluster cluster.ClusterType) []string {
	portMap := make(map[string]bool)

	// 收集默认TCP服务的端口
	if webCluster.TCPDefault != nil && webCluster.TCPDefault.Port != "" {
		for _, port := range extractValidPorts(webCluster.TCPDefault.Port) {
			portMap[port] = true
		}
	}

	// 收集其他服务的端口
	for _, clusterExec := range webCluster.TCPOther {
		if clusterExec.Port != "" {
			for _, port := range extractValidPorts(clusterExec.Port) {
				portMap[port] = true
			}
		}
	}

	// 添加一些常见端口
	commonPorts := []string{"21", "22", "25", "80", "443", "3306", "5432", "6379", "8080", "8443", "9200", "27017"}
	for _, port := range commonPorts {
		portMap[port] = true
	}

	// 转换为切片
	var ports []string
	for port := range portMap {
		ports = append(ports, port)
	}

	// 排序
	sort.Strings(ports)

	// 限制数量，避免过多连接
	if len(ports) > 15 {
		ports = ports[:15]
	}

	return ports
}

// preciseTCPMatch 执行精确TCP匹配
func (s *Scanner) preciseTCPMatch(host string, candidates []string) ([]matcher.MatchResult, error) {
	var results []matcher.MatchResult

	// 记录开始扫描
	//fmt.Printf("[TCP] 开始对 %s 进行TCP精确匹配\n", host)

	// 解析URI中的端口，如果存在
	targetURI, err := url.Parse(host)
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
		if s.Config != nil && len(s.Config.DefaultTCPPorts) > 0 {
			// 使用配置中的默认端口
			targetPorts = s.Config.DefaultTCPPorts
			//fmt.Printf("[TCP] 使用配置文件中的默认端口列表，共 %d 个端口\n", len(targetPorts))
		} else {
			//fmt.Printf("[TCP] 未找到配置文件或配置为空，使用硬编码默认端口序列\n")
			targetPorts = []uint16{21, 22, 25, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9200, 27017}
		}
	}

	// 对每个端口执行匹配，收集所有匹配结果
	for _, port := range targetPorts {
		//fmt.Printf("[TCP] 开始探测端口 %d\n", port)
		portResults, found := s.matchTcpPortFingerprints(host, port, candidates)
		if found {
			//fmt.Printf("[TCP] 端口 %d 匹配成功，找到 %d 个结果\n", port, len(portResults))
			results = append(results, portResults...)
			// 继续探测其他端口
		}
	}

	// 去重结果
	if len(results) > 0 {
		//fmt.Printf("[TCP] 共完成 %d 个端口的探测，找到 %d 个匹配结果\n", len(targetPorts), len(results))
		return UniqueResults(results), nil
	}

	return results, nil
}

// matchPortFingerprints 对指定端口执行指纹匹配
func (s *Scanner) matchTcpPortFingerprints(host string, port uint16, candidates []string) ([]matcher.MatchResult, bool) {
	//fmt.Printf("[TCP] 尝试匹配端口 %d 的指纹\n", port)

	// 1. 首先匹配TCPOther中的指纹
	tcpOtherResults, otherMatched := s.matchTCPOther(host, port, candidates)
	if otherMatched {
		return tcpOtherResults, true
	}

	// 2. 如果TCPOther没有匹配，尝试TCPNull
	tcpNullResults, nullMatched := s.matchTCPNull(host, port, candidates)
	if nullMatched {
		return tcpNullResults, true
	}

	// 没有找到匹配
	return nil, false
}

// matchTCPOther 匹配TCPOther中的指纹
func (s *Scanner) matchTCPOther(host string, port uint16, candidates []string) ([]matcher.MatchResult, bool) {
	// 收集包含该端口的TCPOther指纹
	var matchingClusters []ClusterInfo

	// 遍历TCPOther，找出包含指定端口的指纹
	for name, clusterExec := range s.WebCluster.TCPOther {
		portStr := strconv.Itoa(int(port))
		// 检查端口是否在Port字符串中
		if clusterExec.Port != "" {
			// 提取有效端口
			validPorts := extractValidPorts(clusterExec.Port)
			for _, p := range validPorts {
				if p == portStr {
					matchingClusters = append(matchingClusters, ClusterInfo{
						Name:    name,
						Cluster: clusterExec,
						Rarity:  clusterExec.Rarity,
					})
					continue
				}
			}
		}
	}

	//fmt.Printf("[TCP] 找到 %d 个包含端口 %d 的TCPOther指纹\n", len(matchingClusters), port)
	if len(matchingClusters) == 0 {
		//fmt.Printf("[TCP] 未找到匹配的TCPOther指纹\n\n")
		return nil, false
	}

	// 按Rarity从小到大排序
	sort.Slice(matchingClusters, func(i, j int) bool {
		return matchingClusters[i].Rarity < matchingClusters[j].Rarity
	})

	// 优化：将整个matchingClusters传给probeTCPService函数
	matched, results := s.probeTCPService(host, port, matchingClusters, candidates)
	return results, matched
}

// matchTCPNull 匹配TCPNull中的指纹
func (s *Scanner) matchTCPNull(host string, port uint16, candidates []string) ([]matcher.MatchResult, bool) {
	// 收集包含该端口的TCPNull指纹
	var matchingClusters []ClusterInfo

	// 直接将所有TCPNull指纹添加到匹配列表中，不进行端口筛选
	for i, clusterExec := range s.WebCluster.TCPNull {
		name := fmt.Sprintf("TCPNull-%d", i) // 生成一个名称
		matchingClusters = append(matchingClusters, ClusterInfo{
			Name:    name,
			Cluster: clusterExec,
			Rarity:  clusterExec.Rarity,
		})
	}

	// 按Rarity从小到大排序
	sort.Slice(matchingClusters, func(i, j int) bool {
		return matchingClusters[i].Rarity < matchingClusters[j].Rarity
	})

	// 优化：将整个matchingClusters传给probeTCPServiceNull函数
	matched, results := s.probeTCPServiceNull(host, port, matchingClusters, candidates)
	return results, matched
}

// probeTCPService 探测单个TCP服务
func (s *Scanner) probeTCPService(host string, port uint16, matchingClusters []ClusterInfo, candidates []string) (bool, []matcher.MatchResult) {
	parts := strings.SplitN(host, "://", 2)
	if len(parts) > 1 {
		host = parts[1]
	}
	//fmt.Printf("[TCP] 探测tcp other\n")
	// 分离主机名和端口
	hostParts := strings.SplitN(host, ":", 2)
	hostname := hostParts[0]
	address := fmt.Sprintf("%s:%d", hostname, port)
	//fmt.Printf("[TCP] 连接到: %s\n", address)

	// 连接到服务，使用较短的超时时间
	dialer := &net.Dialer{
		Timeout: s.Config.Timeout,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		//fmt.Printf("[TCP] 连接失败: %v\n", err)
		return false, nil
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 读取响应数据
	buffer := make([]byte, 2048)
	var banner strings.Builder

	// 使用带超时的读取操作
	readDone := make(chan bool, 1)
	go func() {
		// 读取响应
		n, err := conn.Read(buffer)
		if err != nil && err != io.EOF {
			//fmt.Printf("[TCP] 读取响应失败: %v\n", err)
			readDone <- false
			return
		}
		if n > 0 {
			banner.Write(buffer[:n])
			//fmt.Printf("[TCP] 收到响应: %d 字节\n", n)
		}
		readDone <- true
	}()

	// 等待读取完成或超时
	var readSuccess bool
	select {
	case readSuccess = <-readDone:
		// 读取操作完成，根据结果处理
	case <-time.After(3 * time.Second):
		//fmt.Printf("[TCP] 读取操作超时，继续处理\n")
		readSuccess = false
	}

	// 如果读取失败且没有任何数据，直接返回
	if !readSuccess && banner.Len() == 0 {
		return false, nil
	}

	// 创建TCP响应对象
	tcpResp := &matcher.TCPResponse{
		Host:     hostname,
		Port:     strconv.Itoa(int(port)),
		Response: banner.String(),
	}
	/*
			tcpResp.Response = `HTTP/1.0 404 Not Found
		Content-Type: text/html
		Content-Length: 123

		<html>...（响应体内容）`
	*/
	// 保存匹配结果
	var allResults []matcher.MatchResult

	// 遍历所有集群指纹进行匹配
	for _, clusterInfo := range matchingClusters {
		// 遍历集群中的每个操作符（指纹）
		for _, fingerprint := range clusterInfo.Cluster.Operators {
			matched := false

			// 遍历所有Extractors进行匹配
			for _, extractor := range fingerprint.Extractors {
				// 检查word类型提取器
				if extractor.Type == "word" && len(extractor.Regex) > 0 {
					word := extractor.Regex[0] // 对于word类型，使用Regex字段的第一个元素作为关键字

					// 检查响应中是否包含这个关键字
					if strings.Contains(tcpResp.Response, word) {
						matched = true
						//fmt.Printf("[TCP] 指纹 %s 的word匹配成功: %s\n", fingerprint.ID, word)
						break
					}
				}

				// 检查regex类型提取器
				if extractor.Type == "regex" && len(extractor.Regex) > 0 {
					for _, regexStr := range extractor.Regex {
						// 编译正则表达式
						regex, err := regexp.Compile(regexStr)
						if err != nil {
							//fmt.Printf("[TCP] 正则表达式编译失败: %v\n", err)
							continue
						}

						// 尝试对每一行进行匹配，处理可能存在的多行响应
						tcpResp.Response = strings.TrimRight(tcpResp.Response, "\r")
						if regex.MatchString(tcpResp.Response) {
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
				for _, extractor := range fingerprint.Extractors {
					if extractor.Type == "word" {
						// 检查是否包含特殊关键词
						for _, word := range extractor.Regex {
							lowWord := strings.ToLower(word)
							if strings.Contains(lowWord, "server:") {
								confidence = s.ConfidenceConfig.MatcherWeights.Word["server"]
								break
							}
						}
						// 如果没有特殊关键词，使用默认值
						if confidence == 0.0 {
							confidence = s.ConfidenceConfig.MatcherWeights.Word["default"]
						}
					} else if extractor.Type == "regex" {
						// 检查是否包含特殊正则
						for _, regex := range extractor.Regex {
							lowRegex := strings.ToLower(regex)
							if strings.Contains(lowRegex, "server:") {
								confidence = s.ConfidenceConfig.MatcherWeights.Regex["server"]
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

				// 添加主机和端口信息
				result.Details["host"] = hostname
				result.Details["port"] = tcpResp.Port

				// 提取详细信息
				for _, extractor := range fingerprint.Extractors {
					if extractor.Type == "regex" && len(extractor.Regex) > 0 {
						regexStr := extractor.Regex[0]
						regex, err := regexp.Compile(regexStr)
						if err == nil {
							// 对每一行尝试提取详细信息
							responseLines := strings.Split(tcpResp.Response, "\n")
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
						if strings.Contains(tcpResp.Response, word) {
							result.Details[extractor.Name] = word
						}
					}
				}

				fmt.Printf("[TCP] 成功匹配TCPother指纹 ")
				return true, []matcher.MatchResult{result}
			}
		}
	}

	// 如果找到匹配结果，返回
	if len(allResults) > 0 {
		return true, allResults
	}

	return false, nil
}

// probeTCPServiceNull 探测TCP服务（专门处理name为null的TCP指纹）
func (s *Scanner) probeTCPServiceNull(host string, port uint16, matchingClusters []ClusterInfo, candidates []string) (bool, []matcher.MatchResult) {
	//fmt.Printf("[TCP] 开始探测TCP Null服务，端口: %d\n", port)

	// 移除协议前缀
	parts := strings.SplitN(host, "://", 2)
	if len(parts) > 1 {
		host = parts[1]
	}

	// 分离主机名和端口
	hostParts := strings.SplitN(host, ":", 2)
	hostname := hostParts[0]
	address := fmt.Sprintf("%s:%d", hostname, port)
	//fmt.Printf("[TCP] 连接到: %s\n", address)

	// 连接到服务，使用较短的超时时间
	dialer := &net.Dialer{
		Timeout: s.Config.Timeout,
	}
	conn, err := dialer.Dial("tcp", address)
	if err != nil {
		//fmt.Printf("[TCP] 连接失败: %v\n", err)
		return false, nil
	}
	defer conn.Close()

	// 设置读写超时
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 读取响应数据
	buffer := make([]byte, 2048)
	var banner strings.Builder

	// 使用带超时的读取操作
	readDone := make(chan bool, 1)
	go func() {
		// 读取响应
		n, err := conn.Read(buffer)
		if err != nil && err != io.EOF {
			//fmt.Printf("[TCP] 读取响应失败: %v\n", err)
			readDone <- false
			return
		}
		if n > 0 {
			banner.Write(buffer[:n])
			//fmt.Printf("[TCP] 收到响应: %d 字节\n", n)
		}
		readDone <- true
	}()

	// 等待读取完成或超时
	var readSuccess bool
	select {
	case readSuccess = <-readDone:
		// 读取操作完成，根据结果处理
	case <-time.After(3 * time.Second):
		//fmt.Printf("[TCP] 读取操作超时，继续处理\n")
		readSuccess = false
	}

	// 如果读取失败且没有任何数据，直接返回
	if !readSuccess && banner.Len() == 0 {
		return false, nil
	}

	// 创建TCP响应对象
	tcpResp := &matcher.TCPResponse{
		Host:     hostname,
		Port:     strconv.Itoa(int(port)),
		Response: banner.String(),
	}

	// 遍历所有集群进行匹配
	for _, clusterInfo := range matchingClusters {
		// 直接匹配每个指纹
		for _, fingerprint := range clusterInfo.Cluster.Operators {
			matched := false

			// 遍历所有Extractors进行匹配
			for _, extractor := range fingerprint.Extractors {
				// 检查word类型提取器
				if extractor.Type == "word" && len(extractor.Regex) > 0 {
					word := extractor.Regex[0] // 对于word类型，使用Regex字段的第一个元素作为关键字

					// 检查响应中是否包含这个关键字
					if strings.Contains(tcpResp.Response, word) {
						matched = true
						//fmt.Printf("[TCP] 指纹 %s 的word匹配成功: %s\n", fingerprint.ID, word)
						break
					}
				}

				// 检查regex类型提取器
				if extractor.Type == "regex" && len(extractor.Regex) > 0 {
					for _, regexStr := range extractor.Regex {
						// 编译正则表达式
						regex, err := regexp.Compile(regexStr)
						if err != nil {
							//fmt.Printf("[TCP] 正则表达式编译失败: %v\n", err)
							continue
						}
						tcpResp.Response = strings.TrimRight(tcpResp.Response, "\r")

						// 去除每行末尾可能存在的回车符

						if regex.MatchString(tcpResp.Response) {
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

			// 如果匹配成功，创建结果并返回
			if matched {
				// 计算置信度
				var confidence float64 = 0.0

				// 遍历所有匹配器，查找匹配成功的匹配器类型
				for _, extractor := range fingerprint.Extractors {
					if extractor.Type == "word" {
						// 检查是否包含特殊关键词
						for _, word := range extractor.Regex {
							lowWord := strings.ToLower(word)
							if strings.Contains(lowWord, "server:") {
								confidence = s.ConfidenceConfig.MatcherWeights.Word["server"]
								break
							}
						}
						// 如果没有特殊关键词，使用默认值
						if confidence == 0.0 {
							confidence = s.ConfidenceConfig.MatcherWeights.Word["default"]
						}
					} else if extractor.Type == "regex" {
						// 检查是否包含特殊正则
						for _, regex := range extractor.Regex {
							lowRegex := strings.ToLower(regex)
							if strings.Contains(lowRegex, "server:") {
								confidence = s.ConfidenceConfig.MatcherWeights.Regex["server"]
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

				// 添加主机和端口信息
				result.Details["host"] = hostname
				result.Details["port"] = tcpResp.Port

				// 提取详细信息
				for _, extractor := range fingerprint.Extractors {
					if extractor.Type == "regex" && len(extractor.Regex) > 0 {
						regexStr := extractor.Regex[0]
						regex, err := regexp.Compile(regexStr)
						if err == nil {
							// 对每一行尝试提取详细信息
							responseLines := strings.Split(tcpResp.Response, "\n")
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
						if strings.Contains(tcpResp.Response, word) {
							result.Details[extractor.Name] = word
						}
					}
				}

				//fmt.Printf("[TCP] 成功匹配TCPNull指纹 #%d: %s (%s)\n", i+1, fingerprint.ID, fingerprint.Info.Name)
				return true, []matcher.MatchResult{result}
			}
		}
	}

	//fmt.Printf("[TCP] 未找到匹配的TCPNull指纹\n")
	return false, nil
}

// 这里使用core.go中定义的UniqueResults函数
