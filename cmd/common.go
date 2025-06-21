package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// 定义颜色常量（ANSI转义序列）
const (
	// 基础颜色
	//ColorRed     = "\033[38;5;203m"
	ColorRed     = "\033[31m" // 普通红色
	ColorGreen   = "\033[32m"
	ColorYellow  = "\033[33m"
	ColorBlue    = "\033[34m"
	ColorMagenta = "\033[35m"
	ColorCyan    = "\033[36m"
	ColorWhite   = "\033[37m"
	ColorReset   = "\033[0m"

	// 亮色变体
	ColorBrightRed     = "\033[91m"
	ColorBrightGreen   = "\033[92m"
	ColorBrightYellow  = "\033[93m"
	ColorBrightBlue    = "\033[94m"
	ColorBrightMagenta = "\033[95m"
	ColorBrightCyan    = "\033[96m"
	ColorBrightWhite   = "\033[97m"

	// 文本样式
	StyleBold      = "\033[1m"
	StyleDim       = "\033[2m"
	StyleItalic    = "\033[3m"
	StyleUnderline = "\033[4m"
	StyleBlink     = "\033[5m"
	StyleReverse   = "\033[7m"
	StyleHidden    = "\033[8m"
	StyleReset     = "\033[0m"

	// 背景颜色
	BgBlack   = "\033[40m"
	BgRed     = "\033[41m"
	BgGreen   = "\033[42m"
	BgYellow  = "\033[43m"
	BgBlue    = "\033[44m"
	BgMagenta = "\033[45m"
	BgCyan    = "\033[46m"
	BgWhite   = "\033[47m"
)

// 版本信息
const VERSION = "1.0.0"

// 命令行参数
var (
	targetFlag         string
	modelFlag          string
	targetFileFlag     string
	outputFlag         string
	webFPFlag          string
	serviceFPFlag      string
	featureMapFlag     string
	threadFlag         int
	disableFaviconFlag bool
	disableTCPFlag     bool
	silentFlag         bool
	jsonOutputFlag     bool
	debugFlag          bool
	bpStatFlag         bool // 添加BP-stat标志
)

func init() {
	// 自定义Usage函数
	flag.Usage = customUsage

	// 解析命令行参数
	flag.IntVar(&threadFlag, "c", 5, "并发数")
	flag.BoolVar(&debugFlag, "debug", false, "调试模式")
	flag.StringVar(&featureMapFlag, "map", "feature_map.json", "特征映射文件路径")
	flag.StringVar(&targetFileFlag, "f", "", "从文件读取目标列表")
	flag.StringVar(&modelFlag, "m", "web", "扫描模式: web, service, all")
	flag.StringVar(&targetFlag, "u", "", "指定扫描的目标")
	flag.BoolVar(&disableFaviconFlag, "no-favicon", false, "禁用Favicon检测")
	flag.StringVar(&outputFlag, "o", "", "输出html文件")
	flag.BoolVar(&silentFlag, "silent", false, "静默模式，仅输出结果")
	flag.StringVar(&serviceFPFlag, "s", "configs/service_fingerprint_v4.json", "服务指纹库文件路径")
	flag.StringVar(&webFPFlag, "w", "configs/web_fingerprint_v4.json", "Web指纹库文件路径")
	flag.BoolVar(&bpStatFlag, "BP-stat", false, "只输出有指纹匹配的结果，不输出仅有状态码的结果")
}

// 自定义Usage输出
func customUsage() {
	// 显示横幅
	printBanner()

	// 输出程序名和简短说明
	fmt.Fprintf(os.Stderr, "%s%s选项列表:%s\n",
		StyleBold, ColorBrightCyan, ColorReset)

	// 定义选项名的最大长度，用于对齐描述
	maxOptLen := 0
	flag.VisitAll(func(f *flag.Flag) {
		if len(f.Name) > maxOptLen {
			maxOptLen = len(f.Name)
		}
	})

	// 设置对齐宽度
	alignWidth := maxOptLen + 4 // 加上前缀和一些空格

	// 按照用户指定的顺序显示参数
	orderedFlags := []string{
		"c", "debug", "f", "m", "u", "no-favicon", "o", "silent", "map", "s", "w", "BP-stat",
	}

	// 遍历按顺序显示标志
	for _, name := range orderedFlags {
		f := flag.Lookup(name)
		if f == nil {
			continue
		}

		// 构建参数名显示
		flagName := fmt.Sprintf("  %s-%s%s",
			ColorBrightCyan, f.Name, ColorReset)

		// 添加填充，确保描述对齐
		padding := strings.Repeat(" ", alignWidth-len(f.Name)-2)

		// 构建描述（包含默认值信息）
		description := f.Usage
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			description = fmt.Sprintf("%s（默认：%s）", description, f.DefValue)
		}

		// 输出参数和描述
		fmt.Fprintf(os.Stderr, "%s%s%s%s\n",
			flagName, padding, ColorBrightCyan, description)
	}

	fmt.Fprintf(os.Stderr, "\n%s%s示例:%s\n",
		StyleBold, ColorBrightYellow, ColorReset)
	fmt.Fprintf(os.Stderr, "  %s./nebulafinger -u example.com%s\n",
		ColorBrightYellow, ColorReset)
	fmt.Fprintf(os.Stderr, "  %s./nebulafinger -f targets.txt -o results.html%s\n",
		ColorBrightYellow, ColorReset)
	fmt.Fprintf(os.Stderr, "  %s./nebulafinger -u example.com -m all -c 10%s\n\n",
		ColorBrightYellow, ColorReset)
}
