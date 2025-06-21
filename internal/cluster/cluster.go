package cluster

import (
	"fmt"
	"nebulafinger/internal"
	"sort"
	"strconv"
	"strings"
)

// ClusterType 存储不同类型的聚类后的请求组
type ClusterType struct {
	WebDefault  []ClusterExecute          // 默认Web请求（如首页）
	WebFavicon  []ClusterExecute          // 图标相关请求
	WebOther    []ClusterExecute          // 其他Web路径请求
	TCPDefault  *ClusterExecute           // 默认TCP请求
	TCPNull     []ClusterExecute          // TCP name为null的请求
	TCPOther    map[string]ClusterExecute // 特定TCP服务请求
	PortMapping map[string]string         // 服务名到端口的映射
	PortRanges  map[string]*PortRange     // 服务名到端口范围的映射
}

// ClusterExecute 表示一组具有相同请求特征的指纹
type ClusterExecute struct {
	Path      string                 // HTTP路径或TCP信息
	Method    string                 // HTTP方法
	Rarity    int                    // 稀有度
	Port      string                 // TCP端口
	Operators []ClusteredFingerprint // 聚类后的指纹组
}

// ClusteredFingerprint 表示被聚类的指纹
type ClusteredFingerprint struct {
	ID         string                // 指纹ID
	Info       internal.Info         // 指纹信息
	Matchers   []internal.Matchers   // 匹配器
	Extractors []internal.Extractors // 提取器
}

// PortRange 结构体用于表示端口范围
type PortRange struct {
	// 单个端口列表
	Single []uint16
	// 范围端口列表
	Range []PortRangeSet
}

// PortRangeSet 表示端口范围集合
type PortRangeSet struct {
	Start uint16
	End   uint16
}

// Contains 检查给定端口是否在范围内
func (pr *PortRange) Contains(port uint16) bool {
	// 检查单个端口列表
	for _, p := range pr.Single {
		if p == port {
			return true
		}
	}

	// 检查端口范围
	for _, r := range pr.Range {
		if port >= r.Start && port <= r.End {
			return true
		}
	}

	return false
}

// IsEmpty 检查端口范围是否为空，即没有任何端口定义
// 这通常表示该服务可以匹配任何端口，用于无端口指定的指纹
func (pr *PortRange) IsEmpty() bool {
	return len(pr.Single) == 0 && len(pr.Range) == 0
}

// GetAllPorts 返回所有单个端口和限制范围内的端口
func (pr *PortRange) GetAllPorts(maxRangeSize int) []uint16 {
	result := make([]uint16, 0, len(pr.Single))

	// 添加单个端口
	result = append(result, pr.Single...)

	// 添加范围内的端口
	for _, r := range pr.Range {
		size := int(r.End - r.Start + 1)
		if size > maxRangeSize {
			// 如果范围太大，只取前maxRangeSize个
			for i := 0; i < maxRangeSize; i++ {
				result = append(result, r.Start+uint16(i))
			}
		} else {
			// 否则取全部
			for p := r.Start; p <= r.End; p++ {
				result = append(result, p)
			}
		}
	}

	return result
}

// ClusterFingerprints 将指纹按请求特征聚类
func ClusterFingerprints(webfingerprints []internal.Fingerprint, serviceFingerprints []internal.Fingerprint) ClusterType {
	// 初始化聚类结果
	result := ClusterType{
		WebDefault:  []ClusterExecute{},
		WebFavicon:  []ClusterExecute{},
		WebOther:    []ClusterExecute{},
		TCPNull:     []ClusterExecute{},
		TCPOther:    make(map[string]ClusterExecute),
		PortMapping: make(map[string]string),
		PortRanges:  make(map[string]*PortRange),
	}

	// 处理HTTP指纹，直接分类到Default、Favicon和Other类别
	webDefault, webFavicon, webOther := createHTTPClusters(webfingerprints)
	result.WebDefault = webDefault
	result.WebFavicon = webFavicon
	result.WebOther = webOther

	// 处理TCP指纹
	tcpClusters, tcpNullClusters := createTCPClusters(serviceFingerprints)

	// 直接使用tcpNullClusters作为TCPNull
	result.TCPNull = tcpNullClusters

	// 直接使用tcpClusters作为TCPOther，不再进行分类
	result.TCPOther = tcpClusters

	return result
}

// createHTTPClusters 将HTTP指纹聚类，并直接分类到不同类别
func createHTTPClusters(fingerprints []internal.Fingerprint) (webDefault []ClusterExecute, webFavicon []ClusterExecute, webOther []ClusterExecute) {
	// 用于临时存储每个路径的指纹
	defaultPathGroups := make(map[string][]ClusteredFingerprint) // 存储默认路径的指纹
	faviconPathGroups := make(map[string][]ClusteredFingerprint) // 存储favicon相关的指纹
	otherPathGroups := make(map[string][]ClusteredFingerprint)   // 存储其他路径的指纹

	// 遍历所有指纹
	for _, fp := range fingerprints {

		// 处理每个HTTP请求
		for _, http := range fp.HTTP {
			for _, path := range http.Path {
				normalizedPath := normalizePath(path)

				// 创建聚类指纹
				clustered := ClusteredFingerprint{
					ID:         fp.ID,
					Info:       fp.Info,
					Matchers:   http.Matchers,
					Extractors: http.Extractors,
				}

				// 路径和方法组合的键
				key := http.Method + ":" + normalizedPath

				// 判断指纹类型并分类
				if normalizedPath == "/favicon.ico" || hasFaviconMatcher(http.Matchers) {
					// Favicon类型
					faviconPathGroups[key] = append(faviconPathGroups[key], clustered)
				}
				if isDefaultRootPath(normalizedPath) && isGetOrHeadMethod(http.Method) {
					// 默认路径类型
					defaultPathGroups[key] = append(defaultPathGroups[key], clustered)
				} else {
					// 其他路径类型
					otherPathGroups[key] = append(otherPathGroups[key], clustered)
				}
			}
		}
	}

	// 转换defaultPathGroups为ClusterExecute列表
	for key, fps := range defaultPathGroups {
		parts := strings.SplitN(key, ":", 2)
		method := parts[0]
		path := parts[1]
		// HTTP指纹不需要计算rarity，统一设为0

		webDefault = append(webDefault, ClusterExecute{
			Path:      path,
			Method:    method,
			Rarity:    0, // HTTP指纹不需要rarity
			Operators: fps,
		})
	}

	// 转换faviconPathGroups为ClusterExecute列表
	for key, fps := range faviconPathGroups {
		parts := strings.SplitN(key, ":", 2)
		method := parts[0]
		path := parts[1]
		// HTTP指纹不需要计算rarity，统一设为0

		webFavicon = append(webFavicon, ClusterExecute{
			Path:      path,
			Method:    method,
			Rarity:    0, // HTTP指纹不需要rarity
			Operators: fps,
		})
	}

	// 转换otherPathGroups为ClusterExecute列表
	for key, fps := range otherPathGroups {
		parts := strings.SplitN(key, ":", 2)
		method := parts[0]
		path := parts[1]
		// HTTP指纹不需要计算rarity，统一设为0

		webOther = append(webOther, ClusterExecute{
			Path:      path,
			Method:    method,
			Rarity:    0, // HTTP指纹不需要rarity
			Operators: fps,
		})
	}

	return webDefault, webFavicon, webOther
}

// hasFaviconMatcher 检查是否包含favicon匹配器
func hasFaviconMatcher(matchers []internal.Matchers) bool {
	for _, matcher := range matchers {
		if matcher.Type == "favicon" || len(matcher.Favicon_hash) > 0 {
			return true
		}
	}
	return false
}

// createTCPClusters 将TCP指纹聚类
func createTCPClusters(fingerprints []internal.Fingerprint) (map[string]ClusterExecute, []ClusterExecute) {
	// 用于存储按服务名和端口分组的指纹
	type servicePortKey struct {
		ServiceName string
		Port        string // 使用字符串表示端口范围
	}

	servicePortGroups := make(map[servicePortKey][]ClusteredFingerprint)

	// 存储name为null的TCP指纹
	var nullNameFingerprints []struct {
		fingerprint ClusteredFingerprint
		port        string
	}

	// 首先按"服务名+端口范围"分组
	for _, fp := range fingerprints {
		// 处理每个TCP请求
		for _, tcp := range fp.TCP {
			// 创建聚类指纹
			clustered := ClusteredFingerprint{
				ID:         fp.ID,
				Info:       fp.Info,
				Matchers:   tcp.Matchers,
				Extractors: tcp.Extractors,
			}

			// 检查是否为null名称
			if tcp.Name == "null" {
				nullNameFingerprints = append(nullNameFingerprints, struct {
					fingerprint ClusteredFingerprint
					port        string
				}{
					fingerprint: clustered,
					port:        tcp.Port,
				})
				continue
			}

			// 处理非null的正常TCP指纹
			key := servicePortKey{
				ServiceName: fp.Info.Name,
				Port:        tcp.Port,
			}

			// 将指纹添加到相应组
			servicePortGroups[key] = append(servicePortGroups[key], clustered)
		}
	}

	// 第二阶段：合并相似端口范围的同类服务
	type serviceGroup struct {
		fingerprints []ClusteredFingerprint
		ports        []string
	}

	// 按服务名分组
	serviceGroups := make(map[string]serviceGroup)
	for key, fingerprints := range servicePortGroups {
		serviceName := key.ServiceName
		if group, exists := serviceGroups[serviceName]; exists {
			group.fingerprints = append(group.fingerprints, fingerprints...)
			group.ports = append(group.ports, key.Port)
			serviceGroups[serviceName] = group
		} else {
			serviceGroups[serviceName] = serviceGroup{
				fingerprints: fingerprints,
				ports:        []string{key.Port},
			}
		}
	}

	// 转换为最终的ClusterExecute映射
	TCPOtherclusters := make(map[string]ClusterExecute)
	var tcpNullClusters []ClusterExecute

	// 处理正常的TCP指纹
	for serviceName, group := range serviceGroups {
		// 合并端口范围
		mergedPorts := mergePorts(group.ports)

		// 创建一个ClusterExecute，使用原始指纹的rarity值
		// 如果有多个指纹，只使用第一个指纹的rarity值
		rarity := 0
		if len(group.fingerprints) > 0 {
			rarity = group.fingerprints[0].Info.Metadata.Rarity
		}

		TCPOtherclusters[serviceName] = ClusterExecute{
			Port:      mergedPorts,
			Rarity:    rarity,
			Operators: group.fingerprints,
		}
	}

	// 处理null名称的TCP指纹，按端口分组
	nullPortGroups := make(map[string][]ClusteredFingerprint)

	for _, item := range nullNameFingerprints {
		nullPortGroups[item.port] = append(nullPortGroups[item.port], item.fingerprint)
	}

	// 创建TCPNull聚类
	for port, fingerprints := range nullPortGroups {
		// 使用原始指纹的rarity值
		// 如果有多个指纹，只使用第一个指纹的rarity值
		rarity := 0
		if len(fingerprints) > 0 {
			rarity = fingerprints[0].Info.Metadata.Rarity
		}

		tcpNullClusters = append(tcpNullClusters, ClusterExecute{
			Port:      port,
			Rarity:    rarity,
			Operators: fingerprints,
		})
	}

	return TCPOtherclusters, tcpNullClusters
}

// getDefaultPortForService 根据服务名获取默认端口
func getDefaultPortForService(serviceName string) string {
	serviceToPorts := map[string]string{
		"ssh":        "22",
		"ftp":        "21",
		"http":       "80,443,8080,8443",
		"https":      "443,8443",
		"smtp":       "25,587",
		"smb":        "445",
		"mysql":      "3306",
		"postgresql": "5432",
		"redis":      "6379",
		"mongodb":    "27017,27018",
		"dns":        "53",
		"telnet":     "23",
		"mssql":      "1433",
		"rdp":        "3389",
	}

	if port, ok := serviceToPorts[serviceName]; ok {
		return port
	}

	return "0" // 通配端口
}

// mergePorts 合并多个端口字符串为单一范围表示
func mergePorts(ports []string) string {
	if len(ports) == 0 {
		return ""
	}

	if len(ports) == 1 {
		return ports[0]
	}

	// 收集所有单个端口和端口范围
	var singlePorts []int
	var rangePorts []struct{ start, end int }

	for _, port := range ports {
		// 处理逗号分隔的端口列表
		portParts := strings.Split(port, ",")

		for _, p := range portParts {
			p = strings.TrimSpace(p)

			// 处理端口范围 (例如 "1000-2000")
			if strings.Contains(p, "-") {
				rangeParts := strings.SplitN(p, "-", 2)
				if len(rangeParts) == 2 {
					start, err1 := strconv.Atoi(rangeParts[0])
					end, err2 := strconv.Atoi(rangeParts[1])

					if err1 == nil && err2 == nil {
						rangePorts = append(rangePorts, struct{ start, end int }{start, end})
					}
				}
			} else {
				// 处理单个端口
				singlePort, err := strconv.Atoi(p)
				if err == nil {
					singlePorts = append(singlePorts, singlePort)
				}
			}
		}
	}

	// 去重排序
	sort.Ints(singlePorts)
	uniqueSinglePorts := make([]int, 0)

	for i, port := range singlePorts {
		if i == 0 || port != singlePorts[i-1] {
			uniqueSinglePorts = append(uniqueSinglePorts, port)
		}
	}

	// 合并相邻或重叠的范围
	if len(rangePorts) > 0 {
		sort.Slice(rangePorts, func(i, j int) bool {
			return rangePorts[i].start < rangePorts[j].start
		})

		// TODO: 合并重叠范围的逻辑
	}

	// 构建最终的端口字符串
	var parts []string

	for _, port := range uniqueSinglePorts {
		parts = append(parts, strconv.Itoa(port))
	}

	for _, r := range rangePorts {
		parts = append(parts, fmt.Sprintf("%d-%d", r.start, r.end))
	}

	return strings.Join(parts, ",")
}

// 辅助函数

// normalizePath 标准化路径
func normalizePath(path string) string {
	// 替换占位符
	path = strings.ReplaceAll(path, "{{BaseURL}}", "")
	// 替换尾部可能的/（有些指纹可能写作{{BaseURL}}/)
	path = strings.TrimSpace(path)

	// 确保路径以/开头
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	// 移除末尾的/（除非路径只有一个/）
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		path = path[:len(path)-1]
	}

	return path
}

// isDefaultPath 检查是否为默认路径
func isDefaultPath(path string) bool {
	return path == "/" || path == "/index.html" || path == "/index.php" || path == "/default.html"
}

// isDefaultRootPath 检查是否为根路径 /
func isDefaultRootPath(path string) bool {
	// 判断是否为根路径
	return path == "/"
}

// isGetOrHeadMethod 检查是否为GET或HEAD方法
func isGetOrHeadMethod(method string) bool {
	return method == "GET" || method == "HEAD"
}

// getServiceName 从Info中提取服务名
func getServiceName(name string) string {
	name = strings.ToLower(name)
	// 简单处理：提取第一个单词
	parts := strings.Fields(name)
	if len(parts) > 0 {
		return parts[0]
	}
	return name
}
