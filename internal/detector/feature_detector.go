package detector

import (
	"crypto/md5"
	"fmt"
	"io"
	"nebulafinger/internal"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// FeatureDetector 负责从HTTP/TCP响应中提取特征
type FeatureDetector struct {
	FeatureMap map[internal.FeatureKey][]string
}

// NewFeatureDetector 创建特征检测器
func NewFeatureDetector(featureMap map[internal.FeatureKey][]string) *FeatureDetector {
	return &FeatureDetector{
		FeatureMap: featureMap,
	}
}

// HTTPResponse 表示HTTP响应的关键信息
type HTTPResponse struct {
	URL         string
	Path        string
	StatusCode  int
	Headers     http.Header
	Body        string
	FaviconHash string
}

// TCPResponse 表示TCP响应的关键信息
type TCPResponse struct {
	Host     string
	Port     string
	Response string
}

// ExtractHTTPFeatures 从HTTP响应中提取所有特征
func (d *FeatureDetector) ExtractHTTPFeatures(resp *HTTPResponse) []internal.FeatureKey {
	var features []internal.FeatureKey

	// 1. 提取路径特征
	pathFeature := internal.FeatureKey(fmt.Sprintf("path:%s", resp.Path))
	features = append(features, pathFeature)

	// 2. 提取状态码特征
	statusFeature := internal.FeatureKey(fmt.Sprintf("status:%d", resp.StatusCode))
	features = append(features, statusFeature)

	// 3. 提取Header特征
	for name, values := range resp.Headers {
		for _, value := range values {
			// 检测关键header
			lowerName := strings.ToLower(name)
			lowerValue := strings.ToLower(value)

			if lowerName == "server" || lowerName == "x-powered-by" || lowerName == "set-cookie" {
				headerFeature := internal.FeatureKey(fmt.Sprintf("header_word:header:%s: %s", lowerName, lowerValue))
				features = append(features, headerFeature)
			}
		}
	}

	// 4. 提取body中的特征
	// 提取title标签内容
	titleRegex := regexp.MustCompile(`<title[^>]*>([^<]+)</title>`)
	if matches := titleRegex.FindStringSubmatch(resp.Body); len(matches) > 1 {
		titleFeature := internal.FeatureKey(fmt.Sprintf("body_word:%s",
			strings.ToLower(strings.TrimSpace(matches[1]))))
		features = append(features, titleFeature)
	}

	// 5. 提取favicon特征
	if resp.FaviconHash != "" {
		faviconFeature := internal.FeatureKey(fmt.Sprintf("favicon:%s", resp.FaviconHash))
		features = append(features, faviconFeature)
	}

	return features
}

// ExtractTCPFeatures 从TCP响应中提取特征
func (d *FeatureDetector) ExtractTCPFeatures(resp *TCPResponse) []internal.FeatureKey {
	var features []internal.FeatureKey

	// 1. 提取端口特征
	portFeature := internal.FeatureKey(fmt.Sprintf("port:%s", resp.Port))
	features = append(features, portFeature)

	// 2. 从响应中提取常见服务banner特征
	lowerResp := strings.ToLower(resp.Response)
	for _, keyword := range []string{"ssh", "ftp", "http", "smtp", "openssh", "server", "mysql", "postgresql"} {
		if strings.Contains(lowerResp, keyword) {
			bannerFeature := internal.FeatureKey(fmt.Sprintf("service_banner_word:%s:%s",
				resp.Port, keyword))
			features = append(features, bannerFeature)
		}
	}

	return features
}

// GetPotentialFingerprints 从特征列表中获取可能的指纹ID
func (d *FeatureDetector) GetPotentialFingerprints(features []internal.FeatureKey) map[string]int {
	// 每个指纹ID的特征匹配计数
	fingerprintCounts := make(map[string]int)

	// 检查每个特征的关联指纹
	for _, feature := range features {
		if fingerprints, ok := d.FeatureMap[feature]; ok {
			for _, fpID := range fingerprints {
				fingerprintCounts[fpID]++
			}
		}
	}

	return fingerprintCounts
}

// GetTopFingerprints 获取匹配特征数最多的前N个指纹ID
func (d *FeatureDetector) GetTopFingerprints(counts map[string]int, limit int, threshold int) []string {
	// 将所有超过阈值的指纹ID放入切片
	var fpList []struct {
		ID    string
		Count int
	}

	for id, count := range counts {
		if count >= threshold {
			fpList = append(fpList, struct {
				ID    string
				Count int
			}{ID: id, Count: count})
		}
	}

	// 按计数排序
	// 简单冒泡排序，实际可以用更高效的排序
	for i := 0; i < len(fpList)-1; i++ {
		for j := 0; j < len(fpList)-i-1; j++ {
			if fpList[j].Count < fpList[j+1].Count {
				fpList[j], fpList[j+1] = fpList[j+1], fpList[j]
			}
		}
	}

	// 限制数量
	if limit > 0 && len(fpList) > limit {
		fpList = fpList[:limit]
	}

	// 转换为ID列表
	var result []string
	for _, item := range fpList {
		result = append(result, item.ID)
	}

	return result
}

// CalculateFaviconHash 计算favicon的哈希值
func CalculateFaviconHash(faviconData []byte) string {
	hash := md5.New()
	hash.Write(faviconData)
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// FetchFavicon 获取并哈希favicon
func FetchFavicon(baseURL string) (string, error) {
	// 先发送请求获取主页内容，尝试从HTML中提取favicon链接
	resp, err := http.Get(baseURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 如果能成功获取主页，尝试从HTML中提取favicon链接
	if resp.StatusCode == 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			// 如果读取失败，回退到默认favicon路径
			return fetchDefaultFavicon(baseURL)
		}

		html := string(bodyBytes)

		// 尝试提取各种可能的favicon链接
		var faviconURLs []string

		// 正则表达式匹配各种favicon链接格式
		// 1. 标准 link rel="icon" 或 rel="shortcut icon"
		iconRegex := regexp.MustCompile(`<link[^>]+rel=["'](?:shortcut icon|icon)["'][^>]+href=["']([^"']+)["']`)
		if matches := iconRegex.FindStringSubmatch(html); len(matches) > 1 {
			faviconURLs = append(faviconURLs, matches[1])
		}

		// 2. Apple Touch Icon
		appleIconRegex := regexp.MustCompile(`<link[^>]+rel=["']apple-touch-icon["'][^>]+href=["']([^"']+)["']`)
		if matches := appleIconRegex.FindStringSubmatch(html); len(matches) > 1 {
			faviconURLs = append(faviconURLs, matches[1])
		}

		// 3. 以不同顺序指定的标准图标
		altIconRegex := regexp.MustCompile(`<link[^>]+href=["']([^"']+)["'][^>]+rel=["'](?:shortcut icon|icon)["']`)
		if matches := altIconRegex.FindStringSubmatch(html); len(matches) > 1 {
			faviconURLs = append(faviconURLs, matches[1])
		}

		// 如果找到了任何favicon链接，尝试获取并哈希
		for _, iconURL := range faviconURLs {
			// 处理相对URL
			absoluteURL := iconURL
			if !strings.HasPrefix(iconURL, "http") {
				if strings.HasPrefix(iconURL, "/") {
					// 绝对路径
					baseURLParsed, err := url.Parse(baseURL)
					if err == nil {
						absoluteURL = fmt.Sprintf("%s://%s%s", baseURLParsed.Scheme, baseURLParsed.Host, iconURL)
					}
				} else {
					// 相对路径
					if !strings.HasSuffix(baseURL, "/") {
						absoluteURL = baseURL + "/" + iconURL
					} else {
						absoluteURL = baseURL + iconURL
					}
				}
			}

			// 尝试获取favicon
			hash, err := fetchAndHashFavicon(absoluteURL)
			if err == nil {
				return hash, nil
			}
		}
	}

	// 如果从HTML中无法提取或获取favicon失败，回退到默认favicon路径
	return fetchDefaultFavicon(baseURL)
}

// fetchDefaultFavicon 尝试获取默认路径的favicon
func fetchDefaultFavicon(baseURL string) (string, error) {
	// 构建默认favicon URL
	faviconURL := baseURL
	if !strings.HasSuffix(faviconURL, "/") {
		faviconURL += "/"
	}
	faviconURL += "favicon.ico"

	return fetchAndHashFavicon(faviconURL)
}

// fetchAndHashFavicon 获取并计算指定URL的favicon哈希值
func fetchAndHashFavicon(faviconURL string) (string, error) {
	// 发送请求
	resp, err := http.Get(faviconURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 检查状态码
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("favicon not found, status: %d", resp.StatusCode)
	}

	// 读取内容
	faviconData, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 计算哈希值
	return CalculateFaviconHash(faviconData), nil
}
