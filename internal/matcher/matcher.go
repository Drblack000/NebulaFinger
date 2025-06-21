package matcher

import (
	"nebulafinger/internal"
	"regexp"
	"strings"
)

// MatchResult 表示指纹匹配结果
type MatchResult struct {
	ID         string            // 指纹ID
	Name       string            // 指纹名称
	Confidence float64           // 匹配置信度
	Details    map[string]string // 提取的详细信息（如版本）
	Tags       []string          // 相关标签
}

// Matcher 负责精确匹配指纹
type Matcher struct {
	Fingerprints map[string]internal.Fingerprint // ID到指纹的映射
}

// NewMatcher 创建匹配器
func NewMatcher(fingerprints []internal.Fingerprint) *Matcher {
	fpMap := make(map[string]internal.Fingerprint)
	for _, fp := range fingerprints {
		fpMap[fp.ID] = fp
	}

	return &Matcher{
		Fingerprints: fpMap,
	}
}

// HTTPResponse 表示HTTP响应的关键信息
type HTTPResponse struct {
	URL         string
	Path        string
	StatusCode  int
	Headers     map[string][]string
	Body        string
	FaviconHash string
}

// TCPResponse 表示TCP响应的关键信息
type TCPResponse struct {
	Host     string
	Port     string
	Response string
}

// 辅助函数

// normalizePath 标准化路径
func normalizePath(path string) string {
	// 替换占位符
	path = strings.ReplaceAll(path, "{{BaseURL}}", "")

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

// isMatcherHit 检查HTTP匹配器是否命中
func isMatcherHit(matcher internal.Matchers, resp *HTTPResponse) bool {
	var result bool = false
	var hasMatchers bool = false

	// 获取条件，为空时默认为"or"
	condition := matcher.Condition
	if condition == "" {
		condition = "or"
	}

	// 检查favicon匹配器
	if len(matcher.Favicon_hash) > 0 {
		hasMatchers = true
		if matchFavicon(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 检查word匹配器
	if len(matcher.Words) > 0 {
		hasMatchers = true
		if matchWords(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 检查regex匹配器
	if len(matcher.Regex) > 0 {
		hasMatchers = true
		if matchRegex(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 检查status匹配器
	if len(matcher.Status) > 0 {
		hasMatchers = true
		if matchStatus(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 如果没有任何匹配器，返回false
	if !hasMatchers {
		return false
	}

	// 根据条件返回结果
	// 如果是AND条件，所有匹配器都通过才返回true
	// 如果是OR条件，有一个匹配器通过就返回true（已在上面处理）
	return result != matcher.Negative
}

// isMatcherHitTCP 检查TCP匹配器是否命中
func isMatcherHitTCP(matcher internal.Matchers, resp *TCPResponse) bool {
	var result bool = false
	var hasMatchers bool = false

	// 获取条件，为空时默认为"or"
	condition := matcher.Condition
	if condition == "" {
		condition = "or"
	}

	// 检查word匹配器
	if len(matcher.Words) > 0 {
		hasMatchers = true
		if matchWordsTCP(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 检查regex匹配器
	if len(matcher.Regex) > 0 {
		hasMatchers = true
		if matchRegexTCP(matcher, resp) {
			if condition == "or" {
				return !matcher.Negative // 如果是OR条件，一个匹配成功就返回
			}
			result = true
		} else if condition == "and" {
			return matcher.Negative // 如果是AND条件，一个失败就返回negative
		}
	}

	// 如果没有任何匹配器，返回false
	if !hasMatchers {
		return false
	}

	// 根据条件返回结果
	return result != matcher.Negative
}

// matchWords 匹配关键词
func matchWords(matcher internal.Matchers, resp *HTTPResponse) bool {
	part := strings.ToLower(matcher.Part)

	// 默认匹配body
	if part == "" {
		part = "body"
	}

	var content string

	switch part {
	case "body":
		content = resp.Body
	case "header":
		var headers strings.Builder
		for name, values := range resp.Headers {
			for _, value := range values {
				headers.WriteString(name)
				headers.WriteString(": ")
				headers.WriteString(value)
				headers.WriteString("\n")
			}
		}
		content = headers.String()
	case "all", "response":
		var all strings.Builder
		all.WriteString("HTTP/1.1 ")
		all.WriteString(string(resp.StatusCode))
		all.WriteString("\n")

		for name, values := range resp.Headers {
			for _, value := range values {
				all.WriteString(name)
				all.WriteString(": ")
				all.WriteString(value)
				all.WriteString("\n")
			}
		}

		all.WriteString("\n")
		all.WriteString(resp.Body)
		content = all.String()
	default:
		// 处理特定的HTTP头 (例如: "Server", "X-Powered-By")
		// 如果part是特定的头名称，则只在该头中搜索
		headerValues, exists := resp.Headers[part]
		if exists {
			var specificHeader strings.Builder
			for _, value := range headerValues {
				specificHeader.WriteString(value)
				specificHeader.WriteString("\n")
			}
			content = specificHeader.String()
		} else {
			// 如果指定的头不存在，直接返回不匹配
			return matcher.Negative
		}
	}

	// 大小写处理
	// 注意：现在我们在预处理阶段已经处理了Words数组的大小写
	// 这里只需要处理content的大小写
	if matcher.CaseInsensitive {
		content = strings.ToLower(content)
	}

	// 处理条件和匹配逻辑
	var matchedWords []string

	// 遍历每个待匹配的word
	for i, word := range matcher.Words {
		if strings.Contains(content, word) {
			matchedWords = append(matchedWords, word)

			// OR条件且不要求全部匹配，命中一个就返回成功
			if matcher.Condition == "or" && !matcher.Match_all {
				return !matcher.Negative
			}

			// 最后一个word且不要求全部匹配，返回成功
			if i == len(matcher.Words)-1 && !matcher.Match_all {
				return !matcher.Negative
			}
		} else if matcher.Condition == "and" {
			// AND条件下有一个不匹配就返回negative
			return matcher.Negative
		}
	}

	// 如果要求全部匹配且所有words都匹配上了
	if len(matchedWords) > 0 && matcher.Match_all {
		return !matcher.Negative
	}

	// 默认返回未匹配
	return matcher.Negative
}

// matchRegex 匹配正则表达式
func matchRegex(matcher internal.Matchers, resp *HTTPResponse) bool {
	part := strings.ToLower(matcher.Part)

	// 默认匹配body
	if part == "" {
		part = "body"
	}

	var content string

	switch part {
	case "body":
		content = resp.Body
	case "header":
		var headers strings.Builder
		for name, values := range resp.Headers {
			for _, value := range values {
				headers.WriteString(name)
				headers.WriteString(": ")
				headers.WriteString(value)
				headers.WriteString("\n")
			}
		}
		content = headers.String()
	case "all", "response":
		var all strings.Builder
		all.WriteString("HTTP/1.1 ")
		all.WriteString(string(resp.StatusCode))
		all.WriteString("\n")

		for name, values := range resp.Headers {
			for _, value := range values {
				all.WriteString(name)
				all.WriteString(": ")
				all.WriteString(value)
				all.WriteString("\n")
			}
		}

		all.WriteString("\n")
		all.WriteString(resp.Body)
		content = all.String()
	default:
		return false
	}

	// 大小写处理
	if matcher.CaseInsensitive {
		content = strings.ToLower(content)
	}

	// 处理条件和匹配逻辑
	matched := 0

	for _, regexStr := range matcher.Regex {
		// 大小写处理
		if matcher.CaseInsensitive {
			regexStr = "(?i)" + regexStr
		}

		// 编译正则
		regex, err := regexp.Compile(regexStr)
		if err != nil {
			continue
		}

		if regex.MatchString(content) {
			matched++

			// OR条件且不要求全部匹配
			if matcher.Condition == "or" && !matcher.Match_all {
				return !matcher.Negative
			}
		} else if matcher.Condition == "and" {
			// AND条件下有一个不匹配就返回false
			return matcher.Negative
		}
	}

	// 全部匹配检查
	if matcher.Match_all && matched == len(matcher.Regex) {
		return !matcher.Negative
	}

	return matched > 0 && !matcher.Negative
}

// matchStatus 匹配HTTP状态码
func matchStatus(matcher internal.Matchers, resp *HTTPResponse) bool {
	for _, status := range matcher.Status {
		if status == resp.StatusCode {
			return !matcher.Negative
		}
	}

	return matcher.Negative
}

// matchFavicon 匹配favicon哈希
func matchFavicon(matcher internal.Matchers, resp *HTTPResponse) bool {
	if resp.FaviconHash == "" {
		return false
	}

	for _, hash := range matcher.Favicon_hash {
		if hash == resp.FaviconHash {
			return !matcher.Negative
		}
	}

	return matcher.Negative
}

// matchWordsTCP 匹配TCP响应中的关键词
func matchWordsTCP(matcher internal.Matchers, resp *TCPResponse) bool {
	content := resp.Response

	// 大小写处理
	// 注意：现在我们在预处理阶段已经处理了Words数组的大小写
	// 这里只需要处理content的大小写
	if matcher.CaseInsensitive {
		content = strings.ToLower(content)
	}

	// 处理条件和匹配逻辑
	var matchedWords []string

	// 遍历每个待匹配的word
	for i, word := range matcher.Words {
		if strings.Contains(content, word) {
			matchedWords = append(matchedWords, word)

			// OR条件且不要求全部匹配，命中一个就返回成功
			if matcher.Condition == "or" && !matcher.Match_all {
				return !matcher.Negative
			}

			// 最后一个word且不要求全部匹配，返回成功
			if i == len(matcher.Words)-1 && !matcher.Match_all {
				return !matcher.Negative
			}
		} else if matcher.Condition == "and" {
			// AND条件下有一个不匹配就返回negative
			return matcher.Negative
		}
	}

	// 如果要求全部匹配且所有words都匹配上了
	if len(matchedWords) > 0 && matcher.Match_all {
		return !matcher.Negative
	}

	// 默认返回未匹配
	return matcher.Negative
}

// matchRegexTCP 匹配TCP响应中的正则表达式
func matchRegexTCP(matcher internal.Matchers, resp *TCPResponse) bool {
	content := resp.Response

	// 大小写处理
	if matcher.CaseInsensitive {
		content = strings.ToLower(content)
	}

	// 处理条件和匹配逻辑
	matched := 0

	for _, regexStr := range matcher.Regex {
		// 大小写处理
		if matcher.CaseInsensitive {
			regexStr = "(?i)" + regexStr
		}

		// 编译正则
		regex, err := regexp.Compile(regexStr)
		if err != nil {
			continue
		}

		if regex.MatchString(content) {
			matched++

			// OR条件且不要求全部匹配
			if matcher.Condition == "or" && !matcher.Match_all {
				return !matcher.Negative
			}
		} else if matcher.Condition == "and" {
			// AND条件下有一个不匹配就返回false
			return matcher.Negative
		}
	}

	// 全部匹配检查
	if matcher.Match_all && matched == len(matcher.Regex) {
		return !matcher.Negative
	}

	return matched > 0 && !matcher.Negative
}

// extractValue 从HTTP响应中提取值
func extractValue(extractor internal.Extractors, resp *HTTPResponse) string {
	if extractor.Type != "regex" || len(extractor.Regex) == 0 {
		return ""
	}

	// 只使用第一个正则
	regexStr := extractor.Regex[0]

	// 编译正则
	regex, err := regexp.Compile(regexStr)
	if err != nil {
		return ""
	}

	// 匹配内容
	matches := regex.FindStringSubmatch(resp.Body)
	if len(matches) > 1 {
		return matches[1] // 返回第一个捕获组
	} else if len(matches) == 1 {
		return matches[0] // 返回整个匹配
	}

	return ""
}

// extractValueTCP 从TCP响应中提取值
func extractValueTCP(extractor internal.Extractors, resp *TCPResponse) string {
	if extractor.Type != "regex" || len(extractor.Regex) == 0 {
		return ""
	}

	// 只使用第一个正则
	regexStr := extractor.Regex[0]

	// 编译正则
	regex, err := regexp.Compile(regexStr)
	if err != nil {
		return ""
	}

	// 匹配内容
	matches := regex.FindStringSubmatch(resp.Response)
	if len(matches) > 1 {
		return matches[1] // 返回第一个捕获组
	} else if len(matches) == 1 {
		return matches[0] // 返回整个匹配
	}

	return ""
}
