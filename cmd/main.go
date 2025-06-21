package main

import (
	"flag"
	"fmt"
	"log"
	"nebulafinger/internal/scanner"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	// 解析命令行参数
	flag.Parse()

	// 打印横幅
	if !silentFlag {
		printBanner()
	}

	// 检查必要参数
	if targetFlag == "" && targetFileFlag == "" {
		fmt.Println(ColorRed + "[!] 错误: 必须指定目标(-u)或目标文件(-f)" + ColorReset)
		flag.Usage()
		os.Exit(1)
	}

	// 加载指纹库和特征映射
	webFingerprints, serviceFingerprints, featureMap, err := loadFingerprints()
	if err != nil {
		log.Fatalf(ColorRed+"[!] 加载指纹库失败: %v"+ColorReset, err)
	}

	if !silentFlag {
		fmt.Printf(ColorGreen+"[+] %sWeb指纹数量: %d%s\n", ColorBrightCyan, len(webFingerprints), ColorReset)
		fmt.Printf(ColorGreen+"[+] %sService指纹数量: %d%s\n", ColorBrightCyan, len(serviceFingerprints), ColorReset)
		fmt.Printf(ColorGreen+"[+] %s特征映射数量: %d%s\n", ColorBrightCyan, len(featureMap), ColorReset)
	}

	// 创建扫描器配置
	config := &scanner.ScannerConfig{
		Timeout:          2 * time.Second, // 固定2秒
		FeatureThreshold: 1,
		MaxCandidates:    10,
		Concurrency:      threadFlag,
		EnableFavicon:    !disableFaviconFlag,
		EnableTCP:        !disableTCPFlag,
		BPStat:           bpStatFlag, // 添加BP-stat选项
	}

	// 调试模式下打印提示
	if debugFlag {
		fmt.Printf("%s[*] %s调试模式已启用，单个TCP请求超时设置: %s %s\n",
			ColorGreen, ColorBlue, config.Timeout, ColorReset)
	}

	// 创建扫描器
	s := scanner.NewScanner(webFingerprints, serviceFingerprints, featureMap, config)

	// 收集目标
	var targets []string
	if targetFlag != "" {
		targets = append(targets, targetFlag)
	}

	if targetFileFlag != "" {
		fileTargets, err := loadTargetsFromFile(targetFileFlag)
		if err != nil {
			log.Fatalf(ColorRed+"[!] 读取目标文件失败: %v"+ColorReset, err)
		}
		targets = append(targets, fileTargets...)
	}

	// 去重
	targets = uniqueStrings(targets)

	// 显示目标数量
	if !silentFlag {
		fmt.Printf(ColorGreen+"[+] %s目标数量: %d%s\n", ColorBrightCyan, len(targets), ColorReset)
	}

	// 并发扫描，但是实时输出结果
	var wg sync.WaitGroup
	resultsCh := make(chan *scanner.ScanResult, threadFlag) // 使用与并发数相同大小的缓冲区
	errorsCh := make(chan error, len(targets))
	semaphore := make(chan struct{}, threadFlag)

	// 创建一个单独的goroutine来处理结果
	var allResults []*scanner.ScanResult // 保存所有结果用于非HTML文件输出
	var resultMutex sync.Mutex           // 保护allResults的互斥锁

	// 创建任务完成信号通道
	scanDone := make(chan struct{})
	processDone := make(chan struct{})

	// 启动结果处理goroutine
	go func() {
		for result := range resultsCh {
			// 只有当有结果时才处理
			if len(result.WebResults) > 0 || len(result.TCPResults) > 0 {
				// 保存结果到总结果集合
				resultMutex.Lock()
				allResults = append(allResults, result)
				resultMutex.Unlock()

				// 立即处理和输出结果
				processResult(result, outputFlag)
			}
		}
		close(processDone)
	}()

	// 启动扫描goroutine
	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			semaphore <- struct{}{}        // 获取信号量
			defer func() { <-semaphore }() // 释放信号量

			result, err := s.Scan(target, modelFlag)

			if err != nil {
				if debugFlag {
					errorsCh <- fmt.Errorf("扫描 %s 失败: %v", target, err)
				}
				return
			}

			if result != nil {
				resultsCh <- result
			}
		}(target)
	}

	// 使用goroutine等待所有扫描完成
	go func() {
		wg.Wait()
		close(resultsCh)
		close(scanDone)
	}()

	// 等待所有扫描完成
	<-scanDone
	// 等待所有结果处理完成
	<-processDone

	// 关闭错误通道
	close(errorsCh)

	// 输出错误信息
	for err := range errorsCh {
		fmt.Fprintf(os.Stderr, ColorRed+"[!] %v\n"+ColorReset, err)
	}

	// 如果输出到非HTML文件，等所有目标都扫描完成后再一次性输出
	if outputFlag != "" && !strings.HasSuffix(strings.ToLower(outputFlag), ".html") {
		if jsonOutputFlag {
			outputJSON(allResults, outputFlag)
		} else {
			outputText(allResults, outputFlag)
		}
	} else if outputFlag != "" && strings.HasSuffix(strings.ToLower(outputFlag), ".html") {
		// 检查是否有结果已经写入HTML文件
		if _, err := os.Stat(outputFlag); os.IsNotExist(err) && len(allResults) > 0 {
			// 如果文件不存在但有结果，说明没有实时输出结果（可能只有一个URL）
			// 手动输出所有结果
			file, err := os.Create(outputFlag)
			if err == nil {
				defer file.Close()
				// 写入HTML头部
				writeHTMLHeader(file)
				// 写入所有结果
				for i, result := range allResults {
					isLast := i == len(allResults)-1
					outputHTML(result, file, i == 0, isLast)
				}
				// 如果没有结果是最后一个（所有结果都已写入），则手动写入HTML尾部
				if len(allResults) > 0 {
					writeHTMLFooter(file)
				}
				if !silentFlag {
					fmt.Printf(ColorBrightGreen+StyleBold+"[+] HTML报告已完成: %s\n"+ColorReset, outputFlag)
				}
			} else {
				fmt.Fprintf(os.Stderr, ColorBrightRed+StyleBold+"[!] 创建输出文件失败: %v\n"+ColorReset, err)
			}
		} else {
			// 完成HTML报告（添加尾部）
			finalizeHTMLReport(outputFlag)
		}
	}

	// 如果没有结果
	if len(allResults) == 0 && !silentFlag {
		fmt.Println(ColorYellow + "[!] 没有找到任何匹配的指纹" + ColorReset)
	}
}
