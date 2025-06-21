package main

import (
	"fmt"
	"io"
	"nebulafinger/internal/matcher"
	"nebulafinger/internal/scanner"
	"strings"
	"time"
)

// getConfidenceLevel 将置信度百分比转换为级别字符串
func getConfidenceLevel(confidence int) string {
	if confidence >= 80 {
		return "high"
	} else if confidence >= 50 {
		return "medium"
	} else {
		return "low"
	}
}

// 输出HTML格式结果
func outputHTML(result *scanner.ScanResult, writer io.Writer, isFirstResult bool, isLastResult bool) {
	// 如果是第一个结果，写入HTML头部
	if isFirstResult {
		writeHTMLHeader(writer)
	}

	// 为每个目标添加一个区块
	fmt.Fprintf(writer, "<div class=\"target-block\" data-target=\"%s\">\n", result.Target)
	fmt.Fprintf(writer, "  <h2>%s</h2>\n", result.Target)

	// 创建一个唯一的目标ID用于筛选器
	targetID := strings.ReplaceAll(result.Target, ".", "-")

	// 创建指纹容器，但现在不区分Web和TCP标题
	fmt.Fprintf(writer, "  <div class=\"fingerprints-container\" id=\"%s-fingerprints\">\n", targetID)

	// 处理Web指纹结果
	if len(result.WebResults) > 0 {
		// 按URL对指纹进行分组
		urlGroups := make(map[string][]matcher.MatchResult)
		targetURL := result.Target
		if !strings.HasPrefix(targetURL, "http") {
			targetURL = "http://" + targetURL
		}

		for _, webResult := range result.WebResults {
			url := webResult.Details["url"]
			// 处理未知URL的情况，尝试使用目标URL
			if url == "" || url == "未知URL" {
				// 如果有favicon匹配结果，使用目标URL代替未知URL
				if _, hasFavicon := webResult.Details["favicon_hash"]; hasFavicon {
					url = targetURL
				} else {
					url = "未知URL"
				}
			}
			urlGroups[url] = append(urlGroups[url], webResult)
		}

		// 对每个URL分组处理
		for url, results := range urlGroups {
			// 记录当前URL共有的状态码和标题
			statusCode := ""
			title := ""
			if len(results) > 0 {
				statusCode = results[0].Details["status_code"]
				title = results[0].Details["title"]
			}

			// 分别创建每个指纹的卡片，而不是合并在一起
			for _, webResult := range results {
				// 计算置信度百分比
				confidencePercent := int(webResult.Confidence * 100)
				if confidencePercent > 100 {
					confidencePercent = 100
				}

				// 为Web结果创建卡片
				fmt.Fprintf(writer, "    <div class=\"fingerprint-card\" data-type=\"web\" data-status=\"%s\" data-confidence=\"%d\" data-confidence-level=\"%s\" data-fingerprint=\"%s\">\n",
					statusCode, confidencePercent, getConfidenceLevel(confidencePercent), strings.ToLower(webResult.Name))
				fmt.Fprintf(writer, "      <div class=\"card-header web\">\n")
				fmt.Fprintf(writer, "        <span class=\"type-badge\">WEB</span>\n")
				fmt.Fprintf(writer, "        <span class=\"fingerprint-name\">%s (%d%%)</span>\n",
					webResult.Name, confidencePercent)
				fmt.Fprintf(writer, "      </div>\n")
				fmt.Fprintf(writer, "      <div class=\"card-content\">\n")
				fmt.Fprintf(writer, "        <div class=\"url\"><a href=\"%s\" target=\"_blank\">%s</a></div>\n",
					url, url)

				if statusCode != "" || title != "" {
					fmt.Fprintf(writer, "        <div class=\"meta-info\">\n")
					if statusCode != "" {
						// 获取状态码的第一位数字作为类名
						statusClass := ""
						if len(statusCode) > 0 {
							firstChar := string(statusCode[0])
							statusClass = fmt.Sprintf("status-code-%sxx", firstChar)
						}
						fmt.Fprintf(writer, "          <span class=\"status-code %s\">%s</span>\n",
							statusClass, statusCode)
					}
					if title != "" {
						fmt.Fprintf(writer, "          <span class=\"page-title\">%s</span>\n", title)
					}
					fmt.Fprintf(writer, "        </div>\n")
				}

				// 添加该指纹特有的详情
				var detailItems []string
				for k, v := range webResult.Details {
					// 跳过已经显示的字段、共有字段以及favicon相关字段
					if k == "url" || k == "status_code" || k == "title" ||
						strings.Contains(k, "favicon") {
						continue
					}

					detailItems = append(detailItems,
						fmt.Sprintf("<span class=\"detail-item\"><span class=\"detail-name\">%s.%s</span>: <span class=\"detail-value\">%s</span></span>",
							webResult.Name, k, v))
				}

				if len(detailItems) > 0 {
					fmt.Fprintf(writer, "        <div class=\"details\">\n")
					for _, item := range detailItems {
						fmt.Fprintf(writer, "          %s\n", item)
					}
					fmt.Fprintf(writer, "        </div>\n")
				}

				fmt.Fprintf(writer, "      </div>\n")
				fmt.Fprintf(writer, "    </div>\n")
			}
		}
	}

	// 处理TCP指纹结果
	if len(result.TCPResults) > 0 {
		// 按主机和端口对指纹进行分组
		hostPortGroups := make(map[string][]matcher.MatchResult)
		for _, tcpResult := range result.TCPResults {
			host := tcpResult.Details["host"]
			port := tcpResult.Details["port"]
			key := host + ":" + port
			if host == "" || port == "" {
				key = "未知主机端口"
			}
			hostPortGroups[key] = append(hostPortGroups[key], tcpResult)
		}

		// 对每个主机:端口分组处理
		for hostPort, results := range hostPortGroups {
			// 分离主机和端口以便单独显示
			parts := strings.Split(hostPort, ":")
			var hostDisplay, portDisplay string
			if len(parts) == 2 {
				hostDisplay = parts[0]
				portDisplay = parts[1]
			} else {
				hostDisplay = hostPort
				portDisplay = ""
			}

			// 为每个指纹创建独立的卡片
			for _, tcpResult := range results {
				// 计算置信度百分比
				confidencePercent := int(tcpResult.Confidence * 100)
				if confidencePercent > 100 {
					confidencePercent = 100
				}

				// 每个TCP指纹创建一个单独的卡片
				fmt.Fprintf(writer, "    <div class=\"fingerprint-card\" data-type=\"tcp\" data-port=\"%s\" data-confidence=\"%d\" data-confidence-level=\"%s\" data-fingerprint=\"%s\">\n",
					portDisplay, confidencePercent, getConfidenceLevel(confidencePercent), strings.ToLower(tcpResult.Name))
				fmt.Fprintf(writer, "      <div class=\"card-header tcp\">\n")
				fmt.Fprintf(writer, "        <span class=\"type-badge\">Service</span>\n")
				fmt.Fprintf(writer, "        <span class=\"fingerprint-name\">%s (%d%%)</span>\n",
					tcpResult.Name, confidencePercent)
				fmt.Fprintf(writer, "      </div>\n")
				fmt.Fprintf(writer, "      <div class=\"card-content\">\n")
				fmt.Fprintf(writer, "        <div class=\"host\">%s</div>\n", hostDisplay)

				if portDisplay != "" {
					fmt.Fprintf(writer, "        <div class=\"meta-info\">\n")
					fmt.Fprintf(writer, "          <span class=\"port\">%s</span>\n", portDisplay)
					fmt.Fprintf(writer, "        </div>\n")
				}

				// 添加该指纹特有的详情
				var detailItems []string
				for k, v := range tcpResult.Details {
					// 跳过已经显示的字段
					if k == "host" || k == "port" {
						continue
					}

					detailItems = append(detailItems,
						fmt.Sprintf("<span class=\"detail-item\"><span class=\"detail-name\">%s.%s</span>: <span class=\"detail-value\">%s</span></span>",
							tcpResult.Name, k, v))
				}

				if len(detailItems) > 0 {
					fmt.Fprintf(writer, "        <div class=\"details\">\n")
					for _, item := range detailItems {
						fmt.Fprintf(writer, "          %s\n", item)
					}
					fmt.Fprintf(writer, "        </div>\n")
				}

				fmt.Fprintf(writer, "      </div>\n")
				fmt.Fprintf(writer, "    </div>\n")
			}
		}
	}

	fmt.Fprintf(writer, "  </div>\n")
	fmt.Fprintf(writer, "</div>\n")

	// 如果是最后一个结果，写入HTML尾部
	if isLastResult {
		writeHTMLFooter(writer)
	}
}

// 写入HTML头部
func writeHTMLHeader(w io.Writer) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NebulaFinger - 星云指纹扫描报告</title>`+"\n")

	fmt.Fprintf(w, `
  <style>
    :root {
      --web-color: #26c6da;
      --tcp-color: #ec407a;
      --bg-color: #f5f5f5;
      --card-bg: #ffffff;
      --text-color: #333333;
      --text-light: #767676;
      --border-color: #e0e0e0;
      --hover-color: #f0f0f0;
      --filter-bg: #f9f9f9;
      --tag-bg: #e8f5e9;
      --tag-color: #2e7d32;
      --active-filter: #2196f3;
      --filter-hover: #e3f2fd;
    }
    
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      line-height: 1.6;
      color: var(--text-color);
      background-color: var(--bg-color);
      margin: 0;
      padding: 20px;
    }
    
    .header {
      background-color: #2c3e50;
      color: white;
      padding: 20px;
      border-radius: 5px;
      margin-bottom: 20px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.1);
      text-align: center;
    }
    
    .header h1 {
      margin: 0;
      font-size: 28px;
    }
    
    .header p {
      margin: 5px 0 0;
      font-size: 14px;
      opacity: 0.8;
    }
    
    .filter-container {
      background-color: var(--filter-bg);
      padding: 15px 20px;
      margin: 0 0 20px 0;
      border-radius: 5px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.05);
      display: flex;
      flex-wrap: wrap;
      gap: 15px;
    }
    
    /* 创建专门的搜索容器样式 */
    .search-container {
      width: 100%;
      display: flex;
      justify-content: center;
      margin-bottom: 20px;
    }
    
    .filter-group {
      flex: 1;
      min-width: 200px;
    }
    
    .filter-group h4 {
      margin: 0 0 8px 0;
      font-size: 14px;
      color: #555;
    }
    
    .filter-button-group {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
    }
    
    .filter-button {
      background-color: white;
      border: 1px solid var(--border-color);
      border-radius: 4px;
      padding: 6px 12px;
      font-size: 13px;
      cursor: pointer;
      transition: all 0.2s;
      display: flex;
      align-items: center;
    }
    
    .filter-button:hover {
      background-color: var(--filter-hover);
    }
    
    .filter-button.active {
      background-color: var(--active-filter);
      color: white;
      border-color: var(--active-filter);
    }
    
    .filter-button .count {
      background-color: rgba(0,0,0,0.1);
      border-radius: 10px;
      padding: 2px 6px;
      font-size: 11px;
      margin-left: 5px;
    }
    
    .search-box {
      flex: none;
      position: relative;
      max-width: 800px;
      width: 80%;
    }
    
    .search-input {
      width: 100%;
      padding: 18px 30px;
      border: 2px solid var(--border-color);
      border-radius: 40px;
      font-size: 18px;
      box-sizing: border-box;
      text-align: center;
      transition: all 0.3s;
      box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
    
    .search-input:focus {
      outline: none;
      border-color: var(--active-filter);
      box-shadow: 0 0 0 3px rgba(33, 150, 243, 0.3);
    }
    
    .clear-button {
      display: none;
      position: absolute;
      right: 20px;
      top: 50%;
      transform: translateY(-50%);
      background: none;
      border: none;
      font-size: 20px;
      color: #999;
      cursor: pointer;
      padding: 8px;
      border-radius: 50%;
      transition: all 0.2s;
    }
    
    .clear-button:hover {
      background-color: #f0f0f0;
      color: #666;
    }
    
    .search-box.has-text .clear-button {
      display: block;
    }
    
    .target-block {
      background-color: var(--card-bg);
      border-radius: 5px;
      padding: 20px;
      margin-bottom: 30px;
      box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    
    .target-block h2 {
      margin-top: 0;
      padding-bottom: 10px;
      border-bottom: 1px solid var(--border-color);
      color: #2c3e50;
    }
    
    h3 {
      margin-top: 30px;
      margin-bottom: 15px;
      color: #37474f;
      font-size: 18px;
      font-weight: 600;
    }
    
    .fingerprints-container {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
      gap: 20px;
    }
    
    .fingerprint-card {
      border-radius: 5px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
      transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .fingerprint-card:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(0,0,0,0.1);
    }
    
    .fingerprint-card.hidden {
      display: none;
    }
    
    .card-header {
      padding: 15px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    
    .card-header.web {
      background-color: var(--web-color);
      color: white;
    }
    
    .card-header.tcp {
      background-color: var(--tcp-color);
      color: white;
    }
    
    .type-badge {
      font-size: 12px;
      font-weight: bold;
      padding: 3px 6px;
      border-radius: 3px;
      background-color: rgba(255, 255, 255, 0.2);
    }
    
    .fingerprint-name {
      font-weight: 600;
      font-size: 14px;
    }
    
    .card-content {
      padding: 15px;
      background-color: white;
    }
    
    .url, .host {
      font-size: 15px;
      word-break: break-all;
      margin-bottom: 10px;
      font-weight: 500;
    }
    
    .url a {
      color: #1976d2;
      text-decoration: none;
    }
    
    .url a:hover {
      text-decoration: underline;
    }
    
    .meta-info {
      display: flex;
      gap: 15px;
      margin: 10px 0;
      font-size: 14px;
      align-items: center;
    }
    
    .status-code {
      padding: 3px 6px;
      border-radius: 4px;
      font-weight: bold;
      font-size: 0.9em;
      background-color: #e8f5e9;
      color: #2e7d32;
      margin-right: 10px;
    }
    
    /* 添加不同状态码的颜色类 */
    .status-code-4xx {
      background-color: #ffebee;
      color: #c62828;
    }
    
    .status-code-5xx {
      background-color: #f3e5f5;
      color: #6a1b9a;
    }
    
    .status-code-2xx {
      background-color: #e8f5e9;
      color: #2e7d32;
    }
    
    .status-code-3xx {
      background-color: #e3f2fd;
      color: #1565c0;
    }
    
    .port {
      background-color: #ff9800;
      color: white;
      padding: 2px 8px;
      border-radius: 3px;
      font-weight: 500;
    }
    
    .page-title {
      color: var(--text-color);
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      flex: 1;
    }
    
    .details {
      margin-top: 15px;
      padding-top: 15px;
      border-top: 1px dashed var(--border-color);
      font-size: 13px;
      color: var(--text-light);
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }
    
    .detail-item {
      background-color: #f5f5f5;
      padding: 4px 8px;
      border-radius: 3px;
      white-space: nowrap;
    }
    
    .detail-name {
      font-weight: 500;
      color: #5c6bc0;
    }
    
    .detail-value {
      color: #333;
    }
    
    .tags {
      margin-top: 12px;
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
    }
    
    .tag {
      background-color: var(--tag-bg);
      color: var(--tag-color);
      font-size: 12px;
      padding: 3px 8px;
      border-radius: 12px;
      cursor: pointer;
    }
    
    .tag:hover {
      opacity: 0.8;
    }
    
    .status-info {
      margin-top: 15px;
      text-align: center;
      font-size: 14px;
      color: var(--text-light);
      padding: 20px 0;
    }
    
    .no-results {
      display: none;
      text-align: center;
      padding: 40px 20px;
      background-color: var(--card-bg);
      border-radius: 5px;
      margin: 20px 0;
      color: var(--text-light);
    }
    
    .footer {
      text-align: center;
      margin-top: 40px;
      padding: 20px;
      color: var(--text-light);
      font-size: 13px;
      border-top: 1px solid var(--border-color);
    }
    
    @media (max-width: 768px) {
      .fingerprints-container {
        grid-template-columns: 1fr;
      }
      
      body {
        padding: 10px;
      }
      
      .filter-container {
        flex-direction: column;
        padding: 15px;
      }
      
      .filter-group {
        min-width: 100%;
      }
      
      .search-box {
        width: 100%;
        max-width: none;
      }
      
      .search-input {
        padding: 14px 20px;
        font-size: 15px;
        border-radius: 20px;
      }
    }
    
    /* 筛选区块样式 */
    .filter-section {
      background-color: #f5f8fa;
      border-radius: 8px;
      padding: 16px;
      margin: 20px 0;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    
    .filter-group {
      margin-bottom: 15px;
    }
    
    .filter-group h4 {
      margin: 0 0 8px 0;
      color: #555;
      font-size: 14px;
      font-weight: 600;
    }
    
    /* 下拉菜单样式 */
    .dropdown-container {
      position: relative;
      display: inline-block;
    }
    
    .dropdown-button {
      background-color: #3498db;
      color: white;
      padding: 8px 16px;
      font-size: 14px;
      border: none;
      border-radius: 4px;
      cursor: pointer;
      min-width: 160px;
      text-align: left;
      position: relative;
    }
    
    .dropdown-button:after {
      content: "▼";
      font-size: 10px;
      position: absolute;
      right: 10px;
      top: 50%;
      transform: translateY(-50%);
    }
    
    .dropdown-content {
      display: none;
      position: absolute;
      background-color: #f9f9f9;
      min-width: 250px;
      max-width: 350px;
      max-height: 400px;
      overflow-y: auto;
      box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
      z-index: 1000;
      border-radius: 4px;
      padding: 0;
      margin-top: 5px;
    }
    
    .dropdown-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 10px 15px;
      background-color: #f1f1f1;
      border-bottom: 1px solid #ddd;
      font-weight: bold;
    }
    
    .close-dropdown {
      cursor: pointer;
      font-size: 18px;
    }
    
    .dropdown-section {
      padding: 5px 0;
      border-bottom: 1px solid #eee;
    }
    
    .dropdown-section:last-child {
      border-bottom: none;
    }
    
    .dropdown-section-header {
      padding: 5px 15px;
      font-weight: bold;
      color: #555;
      background-color: #f5f5f5;
    }
    
    .dropdown-section-content {
      max-height: 200px;
      overflow-y: auto;
    }
    
    .dropdown-item {
      display: block;
      padding: 8px 15px;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    
    .dropdown-item:hover {
      background-color: #f1f1f1;
    }
    
    .dropdown-item input[type="checkbox"] {
      margin-right: 8px;
    }
    
    /* 显示下拉菜单 */
    .dropdown-container.active .dropdown-content {
      display: block;
    }
    
    /* 按钮激活状态 */
    .dropdown-button.active {
      background-color: #2980b9;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>NebulaFinger 星云指纹扫描报告</h1>
    <p>扫描时间: `+currentTime+`</p>
  </div>
  
  <div class="filter-container" style="flex-direction: column;">
    <div class="search-container" style="display: flex; justify-content: center; width: 100%;">
      <div class="search-box">
        <input type="text" class="search-input" placeholder="搜索指纹、URL、主机..." id="searchInput">
        <button class="clear-button" id="clearSearch">✕</button>
      </div>
    </div>
    
    <div style="display: flex; flex-wrap: wrap; gap: 15px;">
      <div class="filter-group">
        <h4>指纹类型</h4>
        <div class="dropdown-container">
          <button class="dropdown-button" id="fingerprintTypeButton">选择指纹类型 (<span id="selectedFingerprintCount">全部</span>)</button>
          <div class="dropdown-content" id="fingerprintDropdown">
            <div class="dropdown-header">
              <span>指纹类型筛选</span>
              <span class="close-dropdown">&times;</span>
            </div>
            <div class="dropdown-section">
              <div class="dropdown-section-header">全部</div>
              <label class="dropdown-item">
                <input type="checkbox" value="all" checked id="allFingerprintsCheckbox"> 全部 (<span id="totalCount">0</span>)
              </label>
            </div>
            <div class="dropdown-section">
              <div class="dropdown-section-header">Web</div>
              <div class="dropdown-section-content" id="webFingerprintTypes">
                <!-- Web指纹类型将在JS中动态生成 -->
              </div>
            </div>
            <div class="dropdown-section">
              <div class="dropdown-section-header">Service</div>
              <div class="dropdown-section-content" id="tcpFingerprintTypes">
                <!-- Service指纹类型将在JS中动态生成 -->
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="filter-group">
        <h4>状态码</h4>
        <div class="dropdown-container">
          <button class="dropdown-button" id="statusCodeButton">状态码筛选</button>
          <div class="dropdown-content" id="statusCodeDropdown">
            <div class="dropdown-header">
              <span>状态码筛选</span>
              <span class="close-dropdown">&times;</span>
            </div>
            <div class="dropdown-section">
              <label class="dropdown-item">
                <input type="checkbox" value="all" checked id="allStatusCheckbox"> 全部
              </label>
              <div id="statusCodeCheckboxes">
                <!-- 状态码选项将在JS中动态生成 -->
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="filter-group">
        <h4>置信度</h4>
        <div class="dropdown-container">
          <button class="dropdown-button" id="confidenceButton">置信度筛选</button>
          <div class="dropdown-content" id="confidenceDropdown">
            <div class="dropdown-header">
              <span>置信度筛选</span>
              <span class="close-dropdown">&times;</span>
            </div>
            <div class="dropdown-section">
              <label class="dropdown-item">
                <input type="checkbox" value="all" checked id="allConfidenceCheckbox"> 全部
              </label>
              <label class="dropdown-item">
                <input type="checkbox" value="high" class="confidence-checkbox"> 高 (≥80%%)
              </label>
              <label class="dropdown-item">
                <input type="checkbox" value="medium" class="confidence-checkbox"> 中 (50-79%%)
              </label>
              <label class="dropdown-item">
                <input type="checkbox" value="low" class="confidence-checkbox"> 低 (&lt;50%%)
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
  
  <div class="no-results" id="noResults">
    <h3>没有匹配的结果</h3>
    <p>请尝试调整筛选条件或清除搜索</p>
  </div>
`, currentTime)
}

// 写入HTML尾部
func writeHTMLFooter(w io.Writer) {
	fmt.Fprintf(w, `
  <div class="footer">
        <p>由 NebulaFinger v%s 生成</p>
  </div>

  <script>
    document.addEventListener('DOMContentLoaded', function() {
      // 初始化过滤器和搜索功能
      initFilters();
    });
    
    function initFilters() {
      // 获取所有指纹卡片
      const cards = document.querySelectorAll('.fingerprint-card');
      const searchInput = document.getElementById('searchInput');
      const clearButton = document.getElementById('clearSearch');
      const noResults = document.getElementById('noResults');
      
      // 下拉菜单元素
      const fingerprintButton = document.getElementById('fingerprintTypeButton');
      const fingerprintDropdown = document.getElementById('fingerprintDropdown');
      const statusCodeButton = document.getElementById('statusCodeButton');
      const statusCodeDropdown = document.getElementById('statusCodeDropdown');
      const confidenceButton = document.getElementById('confidenceButton');
      const confidenceDropdown = document.getElementById('confidenceDropdown');
      
      // 复选框元素
      const allFingerprintsCheckbox = document.getElementById('allFingerprintsCheckbox');
      const allStatusCheckbox = document.getElementById('allStatusCheckbox');
      const allConfidenceCheckbox = document.getElementById('allConfidenceCheckbox');
      const webFingerprintTypes = document.getElementById('webFingerprintTypes');
      const tcpFingerprintTypes = document.getElementById('tcpFingerprintTypes');
      const statusCodeCheckboxes = document.getElementById('statusCodeCheckboxes');
      
      // 使用Map保存指纹类型和计数
      const webFingerprintTypesMap = new Map();
      const tcpFingerprintTypesMap = new Map();
      
      // 统计各类型的数量
      let webCount = 0;
      let tcpCount = 0;
      
      // 收集所有指纹类型
      cards.forEach(card => {
        const fpType = card.getAttribute('data-fingerprint');
        const cardType = card.getAttribute('data-type');
        
        if (fpType) {
          if (cardType === 'web') {
            webCount++;
            if (webFingerprintTypesMap.has(fpType)) {
              webFingerprintTypesMap.set(fpType, webFingerprintTypesMap.get(fpType) + 1);
            } else {
              webFingerprintTypesMap.set(fpType, 1);
            }
          } else if (cardType === 'tcp') {
            tcpCount++;
            if (tcpFingerprintTypesMap.has(fpType)) {
              tcpFingerprintTypesMap.set(fpType, tcpFingerprintTypesMap.get(fpType) + 1);
            } else {
              tcpFingerprintTypesMap.set(fpType, 1);
            }
          }
        }
      });
      
      // 更新指纹总数
      document.getElementById('totalCount').textContent = cards.length;
      
      // 动态创建Web指纹类型复选框
      if (webFingerprintTypesMap.size > 0) {
        // 按出现次数降序排序
        const sortedWebFingerprintTypes = Array.from(webFingerprintTypesMap.entries()).sort((a, b) => b[1] - a[1]);
        sortedWebFingerprintTypes.forEach(entry => {
          const type = entry[0];
          const count = entry[1];
          
          const label = document.createElement('label');
          label.className = 'dropdown-item';
          
          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.value = type;
          checkbox.className = 'fingerprint-checkbox';
          checkbox.setAttribute('data-type', 'web');
          
          label.appendChild(checkbox);
          label.appendChild(document.createTextNode(type + ' (' + count + ')'));
          
          webFingerprintTypes.appendChild(label);
        });
      }
      
      // 动态创建TCP指纹类型复选框
      if (tcpFingerprintTypesMap.size > 0) {
        // 按出现次数降序排序
        const sortedTcpFingerprintTypes = Array.from(tcpFingerprintTypesMap.entries()).sort((a, b) => b[1] - a[1]);
        sortedTcpFingerprintTypes.forEach(entry => {
          const type = entry[0];
          const count = entry[1];
          
          const label = document.createElement('label');
          label.className = 'dropdown-item';
          
          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.value = type;
          checkbox.className = 'fingerprint-checkbox';
          checkbox.setAttribute('data-type', 'tcp');
          
          label.appendChild(checkbox);
          label.appendChild(document.createTextNode(type + ' (' + count + ')'));
          
          tcpFingerprintTypes.appendChild(label);
        });
      }
      
      // 收集所有状态码
      const statusCodes = new Set();
      cards.forEach(card => {
        const status = card.getAttribute('data-status');
        if (status && status !== "") {
          statusCodes.add(status);
        }
      });
      
      // 动态创建状态码复选框
      if (statusCodes.size > 0) {
        const sortedStatusCodes = Array.from(statusCodes).sort((a, b) => parseInt(a) - parseInt(b));
        sortedStatusCodes.forEach(code => {
          const label = document.createElement('label');
          label.className = 'dropdown-item';
          
          const checkbox = document.createElement('input');
          checkbox.type = 'checkbox';
          checkbox.value = code;
          checkbox.className = 'status-checkbox';
          
          label.appendChild(checkbox);
          label.appendChild(document.createTextNode(code));
          
          statusCodeCheckboxes.appendChild(label);
        });
      }
      
      // 下拉菜单切换功能
      function setupDropdown(button, dropdown) {
        // 点击按钮显示/隐藏下拉菜单
        button.addEventListener('click', function(e) {
          e.stopPropagation();
          
          // 关闭所有其他下拉菜单
          document.querySelectorAll('.dropdown-container').forEach(container => {
            if (container !== button.parentElement) {
              container.classList.remove('active');
            }
          });
          
          // 切换当前下拉菜单
          button.parentElement.classList.toggle('active');
        });
        
        // 点击关闭按钮关闭下拉菜单
        dropdown.querySelector('.close-dropdown').addEventListener('click', function() {
          button.parentElement.classList.remove('active');
        });
      }
      
      // 设置所有下拉菜单
      setupDropdown(fingerprintButton, fingerprintDropdown);
      setupDropdown(statusCodeButton, statusCodeDropdown);
      setupDropdown(confidenceButton, confidenceDropdown);
      
      // 点击页面其他地方关闭所有下拉菜单
      document.addEventListener('click', function(e) {
        if (!e.target.closest('.dropdown-container')) {
          document.querySelectorAll('.dropdown-container').forEach(container => {
            container.classList.remove('active');
          });
        }
      });
      
      // 全选/取消全选功能
      function setupAllCheckbox(allCheckbox, checkboxClass) {
        allCheckbox.addEventListener('change', function() {
          const checkboxes = document.querySelectorAll('.' + checkboxClass);
          checkboxes.forEach(checkbox => {
            checkbox.checked = allCheckbox.checked;
          });
          applyFilters();
          updateFilterButtonText();
        });
        
        // 当单个复选框改变时，检查是否需要更新"全部"复选框
        document.addEventListener('change', function(e) {
          if (e.target.classList.contains(checkboxClass)) {
            const checkboxes = document.querySelectorAll('.' + checkboxClass);
            const allChecked = Array.from(checkboxes).every(cb => cb.checked);
            const anyChecked = Array.from(checkboxes).some(cb => cb.checked);
            
            allCheckbox.checked = allChecked;
            allCheckbox.indeterminate = anyChecked && !allChecked;
            
            applyFilters();
            updateFilterButtonText();
          }
        });
      }
      
      // 设置所有全选/取消全选功能
      setupAllCheckbox(allFingerprintsCheckbox, 'fingerprint-checkbox');
      setupAllCheckbox(allStatusCheckbox, 'status-checkbox');
      setupAllCheckbox(allConfidenceCheckbox, 'confidence-checkbox');
      
      // 更新筛选按钮文本
      function updateFilterButtonText() {
        // 更新指纹类型按钮文本
        const selectedFingerprintCheckboxes = document.querySelectorAll('.fingerprint-checkbox:checked');
        if (allFingerprintsCheckbox.checked || selectedFingerprintCheckboxes.length === 0) {
          document.getElementById('selectedFingerprintCount').textContent = '全部';
        } else {
          document.getElementById('selectedFingerprintCount').textContent = selectedFingerprintCheckboxes.length + '项';
        }
        
        // 更新状态码按钮文本
        const selectedStatusCheckboxes = document.querySelectorAll('.status-checkbox:checked');
        if (allStatusCheckbox.checked || selectedStatusCheckboxes.length === 0) {
          statusCodeButton.textContent = '状态码筛选';
        } else {
          statusCodeButton.textContent = '状态码筛选 (' + selectedStatusCheckboxes.length + '项)';
        }
        
        // 更新置信度按钮文本
        const selectedConfidenceCheckboxes = document.querySelectorAll('.confidence-checkbox:checked');
        if (allConfidenceCheckbox.checked || selectedConfidenceCheckboxes.length === 0) {
          confidenceButton.textContent = '置信度筛选';
        } else {
          confidenceButton.textContent = '置信度筛选 (' + selectedConfidenceCheckboxes.length + '项)';
        }
      }
      
      // 搜索功能
      searchInput.addEventListener('input', () => {
        const searchBox = searchInput.parentElement;
        if (searchInput.value) {
          searchBox.classList.add('has-text');
        } else {
          searchBox.classList.remove('has-text');
        }
        applyFilters();
      });
      
      // 清除搜索
      clearButton.addEventListener('click', () => {
        searchInput.value = '';
        searchInput.parentElement.classList.remove('has-text');
        applyFilters();
      });
      
      // 标签点击事件
      document.querySelectorAll('.tag').forEach(tag => {
        tag.addEventListener('click', () => {
          searchInput.value = tag.textContent.trim();
          searchInput.parentElement.classList.add('has-text');
          applyFilters();
        });
      });
      
      // 应用所有筛选器
      function applyFilters() {
        const searchText = searchInput.value.toLowerCase().trim();
        
        // 获取选中的指纹类型
        let selectedFingerprintTypes = [];
        if (allFingerprintsCheckbox.checked) {
          // 全部选中，不需要过滤
        } else {
          // 收集选中的指纹类型
          document.querySelectorAll('.fingerprint-checkbox:checked').forEach(checkbox => {
            selectedFingerprintTypes.push({
              type: checkbox.value,
              category: checkbox.getAttribute('data-type')
            });
          });
        }
        
        // 获取选中的状态码
        let selectedStatusCodes = [];
        if (allStatusCheckbox.checked) {
          // 全部选中，不需要过滤
        } else {
          // 收集选中的状态码
          document.querySelectorAll('.status-checkbox:checked').forEach(checkbox => {
            selectedStatusCodes.push(checkbox.value);
          });
        }
        
        // 获取选中的置信度级别
        let selectedConfidenceLevels = [];
        if (allConfidenceCheckbox.checked) {
          // 全部选中，不需要过滤
        } else {
          // 收集选中的置信度级别
          document.querySelectorAll('.confidence-checkbox:checked').forEach(checkbox => {
            selectedConfidenceLevels.push(checkbox.value);
          });
        }
        
        let visibleCount = 0;
        const targetBlocks = document.querySelectorAll('.target-block');
        
        // 遍历所有卡片应用筛选条件
        cards.forEach(card => {
          const type = card.getAttribute('data-type');
          const fpType = card.getAttribute('data-fingerprint');
          const status = card.getAttribute('data-status') || '';
          const confidenceLevel = card.getAttribute('data-confidence-level') || 'low';
          
          // 检查每个筛选条件
          let matchesFpType;
          if (allFingerprintsCheckbox.checked) {
            matchesFpType = true;
          } else {
            matchesFpType = selectedFingerprintTypes.some(item => item.type === fpType && item.category === type);
          }
          
          let matchesStatus;
          if (allStatusCheckbox.checked) {
            matchesStatus = true;
          } else {
            matchesStatus = selectedStatusCodes.includes(status);
          }
          
          let matchesConfidence;
          if (allConfidenceCheckbox.checked) {
            matchesConfidence = true;
          } else {
            matchesConfidence = selectedConfidenceLevels.includes(confidenceLevel);
          }
          
          // 检查搜索文本
          let matchesSearch = true;
          if (searchText) {
            const cardText = card.textContent.toLowerCase();
            matchesSearch = cardText.includes(searchText);
          }
          
          // 如果满足所有条件，则显示该卡片
          const isVisible = matchesFpType && matchesStatus && matchesConfidence && matchesSearch;
          card.style.display = isVisible ? '' : 'none';
          
          if (isVisible) {
            visibleCount++;
          }
        });
        
        // 检查每个目标块是否有可见的卡片，如果没有则隐藏整个目标块
        targetBlocks.forEach(block => {
          const visibleCards = Array.from(block.querySelectorAll('.fingerprint-card')).filter(card => card.style.display !== 'none');
          block.style.display = visibleCards.length > 0 ? '' : 'none';
        });
        
        // 显示或隐藏无结果提示
        noResults.style.display = visibleCount === 0 ? 'block' : 'none';
      }
      
      // 初始应用筛选器
      applyFilters();
      
      // 初始化所有复选框
      document.querySelectorAll('.fingerprint-checkbox').forEach(checkbox => {
        checkbox.checked = true;
      });
      document.querySelectorAll('.status-checkbox').forEach(checkbox => {
        checkbox.checked = true;
      });
      document.querySelectorAll('.confidence-checkbox').forEach(checkbox => {
        checkbox.checked = true;
      });
    }
  </script>
</body>
</html>
`, VERSION)
}
