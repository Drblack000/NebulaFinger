package main

import (
	"fmt"
	"strings"
)

// 打印横幅
func printBanner() {
	banner := `
	███╗   ██╗███████╗██████╗ ██╗   ██╗██╗      █████╗       ███████╗██╗███╗   ██╗ ██████╗ ███████╗██████╗ 
	████╗  ██║██╔════╝██╔══██╗██║   ██║██║     ██╔══██╗      ██╔════╝██║████╗  ██║██╔════╝ ██╔════╝██╔══██╗
	██╔██╗ ██║█████╗  ██████╔╝██║   ██║██║     ███████║█████╗█████╗  ██║██╔██╗ ██║██║  ███╗█████╗  ██████╔╝
	██║╚██╗██║██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║╚════╝██╔══╝  ██║██║╚██╗██║██║   ██║██╔══╝  ██╔══██╗
	██║ ╚████║███████╗██████╔╝╚██████╔╝███████╗██║  ██║      ██║     ██║██║ ╚████║╚██████╔╝███████╗██║  ██║
	╚═╝  ╚═══╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝      ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
`
	// 为横幅添加颜色（红色文字）
	coloredBanner := fmt.Sprintf("%s%s%s", ColorBrightCyan, banner, ColorReset)

	// 打印横幅
	fmt.Println(coloredBanner)

	// 打印水平分隔线
	fmt.Printf("%s%s%s\n",
		ColorBrightCyan, strings.Repeat("─", 100), ColorReset)

	// 打印工具信息
	fmt.Printf("%s%s🧩%s %s%sWeb指纹识别工具%s %s%sNebula-Finger【星云指纹】%s %s%sv%s%s\n",
		StyleBold, ColorBrightGreen, ColorReset,
		StyleBold, ColorBrightCyan, ColorReset,
		StyleBold, ColorBrightCyan, ColorReset,
		StyleBold, ColorBrightCyan, VERSION, ColorReset)

	// 作者信息
	fmt.Printf("%s%s🚀%s %s%s作者: Drblack%s\n",
		StyleBold, ColorBrightGreen, ColorReset,
		StyleBold, ColorBrightCyan, ColorReset)

	// 打印水平分隔线
	fmt.Printf("%s%s%s\n\n",
		ColorBrightCyan, strings.Repeat("─", 100), ColorReset)
}
