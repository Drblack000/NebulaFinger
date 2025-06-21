package main

import (
	"encoding/json"
	"fmt"
	"io"
	"nebulafinger/internal/matcher"
	"nebulafinger/internal/scanner"
	"net/url"
	"os"
	"strings"
)

// 输出JSON格式结果
func outputJSON(results []*scanner.ScanResult, outputPath string) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 序列化JSON失败: %v\n"+ColorReset, err)
		return
	}

	if outputPath == "" {
		// 仅在非静默模式下输出到控制台
		if !silentFlag {
			fmt.Println(string(data))
		}
	} else {
		if err := os.WriteFile(outputPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 写入输出文件失败: %v\n"+ColorReset, err)
		} else if !silentFlag {
			fmt.Printf(ColorBrightGreen+StyleBold+"[+] 结果已保存到: %s\n"+ColorReset, outputPath)
		}
	}
}

// 输出文本格式结果
func outputText(results []*scanner.ScanResult, outputPath string) {
	var output io.Writer
	var file *os.File
	var err error

	// 判断是否输出到文件
	toFile := outputPath != ""
	isHTML := toFile && strings.HasSuffix(strings.ToLower(outputPath), ".html")

	if toFile {
		file, err = os.Create(outputPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 创建输出文件失败: %v\n"+ColorReset, err)
			if !silentFlag {
				output = os.Stdout // 仅在非静默模式下输出到控制台
			} else {
				return // 静默模式下直接返回
			}
			toFile = false
			isHTML = false
		} else {
			defer file.Close()
			output = file
		}
	} else if !silentFlag {
		output = os.Stdout // 仅在非静默模式下输出到控制台
	} else {
		return // 静默模式下不输出到控制台直接返回
	}

	for i, result := range results {
		// 如果是HTML格式，使用HTML输出函数
		if isHTML {
			outputHTML(result, file, i == 0, i == len(results)-1)
			continue
		}

		// 打印Web指纹结果
		if len(result.WebResults) > 0 {
			if !toFile {
				fmt.Fprintf(output, "\n")
			} else {
				fmt.Fprintf(output, "\nWeb指纹:\n")
			}

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

				// 提取域名部分，用于分组
				domain := extractDomain(url)
				if domain == "" {
					domain = "unknown"
				}

				urlGroups[domain] = append(urlGroups[domain], webResult)
			}

			// 将分组后的结果按URL展示
			index := 1
			for _, results := range urlGroups {
				if !toFile {
					// 终端输出 - 彩色格式

					// 按照URL路径再次分组
					pathGroups := make(map[string][]matcher.MatchResult)
					for _, r := range results {
						pathUrl := r.Details["url"]
						pathGroups[pathUrl] = append(pathGroups[pathUrl], r)
					}

					// 域名部分只显示一次，是否是首行
					isFirstLine := true

					// 遍历每个路径组
					for pathUrl, pathResults := range pathGroups {
						// 提取共有信息
						statusCode := ""
						title := ""
						if len(pathResults) > 0 {
							statusCode = pathResults[0].Details["status_code"]
							title = pathResults[0].Details["title"]
						}

						// 收集所有指纹名称
						var names []string
						for _, r := range pathResults {
							// 将置信度转换为百分比并四舍五入
							confidencePercent := int(r.Confidence * 100)
							if confidencePercent > 100 {
								confidencePercent = 100
							}
							// 添加带置信度百分比的名称
							names = append(names, fmt.Sprintf("%s (%d%%)", r.Name, confidencePercent))
						}

						// 如果是该域名的第一行，显示头部
						if isFirstLine {
							// 上部分行 - 显示指纹和URL
							fmt.Fprintf(output, "  %s┌─[ %sWEB-FINGERPRINTS%s ] %s [%s%s%s] %s%s%s\n",
								ColorBrightCyan,
								ColorBrightCyan,
								ColorBrightCyan,
								ColorBrightGreen,
								ColorBrightGreen, strings.Join(names, " • "), ColorBrightGreen,
								ColorBrightWhite, pathUrl, ColorReset)

							isFirstLine = false
						} else {
							// 不是第一行，使用一个连接符
							fmt.Fprintf(output, "  %s│ [ %sWEB-FINGERPRINTS%s ] %s [%s%s%s] %s%s%s\n",
								ColorBrightCyan,
								ColorBrightCyan,
								ColorBrightCyan,
								ColorBrightGreen,
								ColorBrightGreen, strings.Join(names, " • "), ColorBrightGreen,
								ColorBrightWhite, pathUrl, ColorReset)
						}

						// 状态码和标题行
						fmt.Fprintf(output, "  %s└─%s ",
							ColorBrightCyan, ColorReset)

						if statusCode != "" {
							// 使用根据状态码选择的颜色
							statusColor := getStatusColor(statusCode)
							fmt.Fprintf(output, "%s%s%s │ ",
								statusColor, statusCode, ColorReset)
						}

						if title != "" {
							fmt.Fprintf(output, "%s%s%s",
								ColorBrightWhite, title, ColorReset)
						}

						// 结束当前行
						fmt.Fprintf(output, "\n")

						// 打印每个指纹特有的其他详情（如有需要）
						// 对于favicon_hash相关的详情，不再显示
						hasFaviconDetails := false
						for _, result := range pathResults {
							if _, ok := result.Details["favicon_hash"]; ok {
								hasFaviconDetails = true
								break
							}
						}

						if !hasFaviconDetails {
							detailsCount := 0
							for _, result := range pathResults {
								for k, v := range result.Details {
									// 跳过已经显示的字段、共有字段以及favicon相关字段
									if k == "url" || k == "status_code" || k == "title" ||
										strings.Contains(k, "favicon") {
										continue
									}

									// 只显示第一个详情行，避免太多噪音
									if detailsCount == 0 {
										fmt.Fprintf(output, "     %s详情:%s ",
											ColorBrightYellow, ColorReset)
									}

									// 特有详情以指纹名称前缀显示
									fmt.Fprintf(output, "%s.%s=%s ",
										result.Name, k, v)

									detailsCount++
								}
							}

							// 如果有详情，添加换行符
							if detailsCount > 0 {
								fmt.Fprintf(output, "\n")
							}
						}
					}
				} else {
					// 普通文件输出 - 简化格式

					// 按照URL路径再次分组
					pathGroups := make(map[string][]matcher.MatchResult)
					for _, r := range results {
						pathUrl := r.Details["url"]
						pathGroups[pathUrl] = append(pathGroups[pathUrl], r)
					}

					for pathUrl, pathResults := range pathGroups {
						statusCode := ""
						title := ""
						if len(pathResults) > 0 {
							statusCode = pathResults[0].Details["status_code"]
							title = pathResults[0].Details["title"]
						}

						// 收集所有指纹名称
						var names []string
						for _, r := range pathResults {
							// 将置信度转换为百分比并四舍五入
							confidencePercent := int(r.Confidence * 100)
							if confidencePercent > 100 {
								confidencePercent = 100
							}
							// 添加带置信度百分比的名称
							names = append(names, fmt.Sprintf("%s (%d%%)", r.Name, confidencePercent))
						}

						fmt.Fprintf(output, "  [WEB] [%s] %s\n", strings.Join(names, " • "), pathUrl)
						if statusCode != "" || title != "" {
							// 使用根据状态码选择的颜色
							statusColor := getStatusColor(statusCode)
							fmt.Fprintf(output, "    └─ %s%s%s | %s\n",
								statusColor, statusCode, ColorReset, title)
						}

						// 跳过favicon相关的详情信息
						hasFaviconDetails := false
						for _, result := range pathResults {
							if _, ok := result.Details["favicon_hash"]; ok {
								hasFaviconDetails = true
								break
							}
						}

						if !hasFaviconDetails {
							// 打印简化的详情信息
							var detailsShown bool = false
							for _, result := range pathResults {
								for k, v := range result.Details {
									// 跳过已经显示的字段、共有字段以及favicon相关字段
									if k == "url" || k == "status_code" || k == "title" ||
										strings.Contains(k, "favicon") {
										continue
									}

									if !detailsShown {
										fmt.Fprintf(output, "      详情: ")
										detailsShown = true
									}

									fmt.Fprintf(output, "%s.%s=%s ", result.Name, k, v)
								}
							}

							if detailsShown {
								fmt.Fprintf(output, "\n")
							}
						}
					}
				}

				index++
			}
		}

		// 打印TCP服务指纹结果
		if len(result.TCPResults) > 0 {
			if !toFile {
				fmt.Fprintf(output, "\n")
			} else {
				fmt.Fprintf(output, "\n服务指纹:\n")
			}

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

			// 将端口结果按主机分组
			hostGroups := make(map[string]map[string][]matcher.MatchResult)
			for hostPort, results := range hostPortGroups {
				parts := strings.Split(hostPort, ":")
				var host, port string
				if len(parts) == 2 {
					host = parts[0]
					port = parts[1]
				} else {
					host = hostPort
					port = ""
				}

				// 为主机创建端口映射
				if _, exists := hostGroups[host]; !exists {
					hostGroups[host] = make(map[string][]matcher.MatchResult)
				}
				hostGroups[host][port] = results
			}

			// 将分组后的结果按主机和端口展示
			index := 1
			for host, portGroups := range hostGroups {
				if !toFile {
					// 终端输出 - 彩色格式
					isFirstLine := true

					for port, results := range portGroups {
						// 收集所有指纹名称
						var names []string
						for _, r := range results {
							// 将置信度转换为百分比并四舍五入
							confidencePercent := int(r.Confidence * 100)
							if confidencePercent > 100 {
								confidencePercent = 100
							}
							// 添加带置信度百分比的名称
							names = append(names, fmt.Sprintf("%s (%d%%)", r.Name, confidencePercent))
						}

						// 如果是该主机的第一行，显示头部
						if isFirstLine {
							// 上部分行 - 显示指纹和主机
							fmt.Fprintf(output, "  %s┌─[ %sSERVICES-FINGERPRINTS%s ] %s[%s%s%s]%s %s%s%s\n",
								ColorBrightRed,
								ColorBrightRed,
								ColorBrightRed,
								ColorBrightGreen,
								ColorBrightGreen, strings.Join(names, " • "), ColorBrightGreen,
								ColorBrightGreen,
								ColorBrightWhite, host, ColorReset)

							isFirstLine = false
						} else {
							// 不是第一行，使用一个连接符
							fmt.Fprintf(output, "  %s│ [ %sSERVICES-FINGERPRINTS%s ] %s[%s%s%s]%s %s%s%s\n",
								ColorBrightRed,
								ColorBrightRed,
								ColorBrightRed,
								ColorBrightGreen,
								ColorBrightGreen, strings.Join(names, " • "), ColorBrightGreen,
								ColorBrightGreen,
								ColorBrightWhite, host, ColorReset)
						}

						// 下部分行 - 显示端口和其他信息
						fmt.Fprintf(output, "  %s└─%s ",
							ColorBrightRed, ColorReset)

						if port != "" {
							fmt.Fprintf(output, "%s%s%s │ ",
								ColorBrightRed, port, ColorReset)
						}

						// 打印每个指纹特有的其他详情（如有需要）
						detailsCount := 0
						for _, result := range results {
							for k, v := range result.Details {
								// 跳过已经显示的字段
								if k == "host" || k == "port" {
									continue
								}

								// 只显示第一个详情行，避免太多噪音
								if detailsCount == 0 {
									// 不需要额外的标签
								}

								// 特有详情以指纹名称前缀显示
								fmt.Fprintf(output, "%s.%s=%s ",
									result.Name, k, v)

								detailsCount++
							}
						}

						// 结束当前行
						fmt.Fprintf(output, "\n")
					}

				} else {
					// 普通文件输出 - 简化格式
					for port, results := range portGroups {
						var names []string
						for _, r := range results {
							// 将置信度转换为百分比并四舍五入
							confidencePercent := int(r.Confidence * 100)
							if confidencePercent > 100 {
								confidencePercent = 100
							}
							// 添加带置信度百分比的名称
							names = append(names, fmt.Sprintf("%s (%d%%)", r.Name, confidencePercent))
						}

						fmt.Fprintf(output, "  [TCP] [%s] %s\n", strings.Join(names, " • "), host)
						if port != "" {
							fmt.Fprintf(output, "    └─ %s\n", port)
						}

						// 打印简化的详情信息
						var detailsShown bool = false
						for _, result := range results {
							for k, v := range result.Details {
								// 跳过已经显示的字段
								if k == "host" || k == "port" {
									continue
								}

								if !detailsShown {
									fmt.Fprintf(output, "      详情: ")
									detailsShown = true
								}

								fmt.Fprintf(output, "%s.%s=%s ", result.Name, k, v)
							}
						}

						if detailsShown {
							fmt.Fprintf(output, "\n")
						}
					}
				}

				index++
			}
		}

		fmt.Fprintf(output, "\n")
	}

	if outputPath != "" && !silentFlag {
		fmt.Printf(ColorBrightGreen+StyleBold+"[+] 结果已保存到: %s\n"+ColorReset, outputPath)
	}
}

// 处理单个扫描结果
func processResult(result *scanner.ScanResult, outputPath string) {
	// 如果启用了静默模式且没有输出文件，则直接返回
	if silentFlag && outputPath == "" {
		return
	}

	// 如果有输出文件但不是HTML，则先不处理，等所有结果收集完再一起处理
	if outputPath != "" && !strings.HasSuffix(strings.ToLower(outputPath), ".html") {
		return
	}

	// 对每个结果中的WebResults和TCPResults进行去重
	if len(result.WebResults) > 0 {
		result.WebResults = scanner.UniqueResults(result.WebResults)
	}
	if len(result.TCPResults) > 0 {
		result.TCPResults = scanner.UniqueResults(result.TCPResults)
	}

	// 如果是输出到HTML文件
	if outputPath != "" && strings.HasSuffix(strings.ToLower(outputPath), ".html") {
		// 检查文件是否存在，决定是否需要写入头部
		isFirstResult := false
		if _, err := os.Stat(outputPath); os.IsNotExist(err) {
			isFirstResult = true
		}

		// 追加模式打开文件
		file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 打开输出文件失败: %v\n"+ColorReset, err)
			return
		}
		defer file.Close()

		// 输出HTML格式，永远不是最后一个结果，因为我们实时输出
		outputHTML(result, file, isFirstResult, false)

		// 同时输出到命令行，除非启用了静默模式
		if !silentFlag {
			// 创建一个只包含当前结果的切片
			results := []*scanner.ScanResult{result}
			outputText(results, "")
		}

		// 这里不显示保存成功信息，防止过多输出
	} else if !silentFlag {
		// 输出到终端，但只在非静默模式下
		// 创建一个只包含当前结果的切片
		results := []*scanner.ScanResult{result}
		outputText(results, "")
	}
}

// 完成HTML报告
func finalizeHTMLReport(outputPath string) {
	if !strings.HasSuffix(strings.ToLower(outputPath), ".html") {
		return
	}

	// 打开文件追加尾部
	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 打开输出文件失败: %v\n"+ColorReset, err)
		return
	}
	defer file.Close()

	// 写入HTML尾部
	writeHTMLFooter(file)

	if !silentFlag {
		fmt.Printf(ColorBrightGreen+StyleBold+"[+] HTML报告已完成: %s\n"+ColorReset, outputPath)
	}
}

// getConfidenceColor 根据置信度选择颜色
func getConfidenceColor(confidence float64) string {
	switch {
	case confidence >= 0.8:
		return ColorBrightGreen
	case confidence >= 0.5:
		return ColorBrightYellow
	default:
		return ColorBrightRed
	}
}

// getStatusColor 根据状态码选择颜色
func getStatusColor(statusCode string) string {
	if len(statusCode) > 0 {
		firstChar := statusCode[0]
		if firstChar == '5' {
			return ColorBrightMagenta
		} else if firstChar == '4' {
			return ColorBrightRed
		}
	}
	return ColorBrightGreen
}

// extractDomain 从URL中提取域名
func extractDomain(urlStr string) string {
	// 尝试解析URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	// 返回Host部分（域名+端口）
	return parsedURL.Host
}
