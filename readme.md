<div align="center">

![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750492454371-08523dae-1e70-493a-aad2-e92e5366054a.png)

<h1>🌳 NebulaFinger | 一款高效的WEB与服务指纹识别工具</h1>

[![Go 语言](https://img.shields.io/badge/Language-Go-blue?style=flat-square&logo=go)](https://go.dev)  [![版本](https://img.shields.io/badge/Version-1.0.0-green.svg)](https://github.com/Drblack000/NebulaFinger/releases)  [![Issues](https://img.shields.io/github/issues/Drblack000/NebulaFinger/issues?color=orange&logo=github)](https://github.com/Drblack000/NebulaFinger/issues) [![Stars](https://img.shields.io/github/stars/Drblack000/NebulaFinger?style=social)](https://github.com/Drblack000/NebulaFinger)  [![博客](https://img.shields.io/badge/Blog-drblack.top-00A3E0?style=flat-square&logo=blogger)](https://drblack.top)
</div>



![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750495997599-9518963b-66d2-4d04-9f9b-6c53b355318b.png)

## ⚠️ 免责声明 | Disclaimer
**郑重声明**：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担。

## 👨‍💻 关于作者 | About the Author
+ 作者: DrBlack
+ GitHub: [drblack000](https://github.com/yourusername)
+ Blog: [drblack.top](https://drblack.top)

## 📖 项目介绍 | Introduction
<font style="color:rgba(0, 0, 0, 0.85);">像「星云」之浩瀚覆盖大量资产，借「指纹」之精准穿透技术迷雾。</font>

<font style="color:rgba(0, 0, 0, 0.85);"></font>NebulaFinger（星云指纹），是一款强大的WEB与SERVICE指纹识别工具，能够快速识别网站使用的技术、框架、CMS系统以及SERVBVICE服务类型。通过构建特征->指纹映射、指纹库特征聚类，分析HTTP响应、Favicon图标、特征值等多维度数据，实现高精度的技术识别。



## ✨ 特性 | Features
+ **多维度指纹识别**：通过分析HTTP响应头、HTML内容、JS库、Favicon哈希等多维数据进行精准识别
+ **服务指纹识别**：能够识别常见的服务类型及版本
+ **高效并发扫描**：支持多线程并发扫描，提高扫描效率
+ **多种输出格式**：支持控制台彩色输出、HTML报告
+ **丰富的指纹库**：使用开源指纹库，内置大量Web和服务指纹
+ **置信度展示**：对不同类型的匹配项分配不同权重，提供更准确的识别结果
+ **HTML报告**：支持指纹类型筛选、状态码筛选、置信度筛选和关键词搜索功能

## 🚀 安装 | Installation
### 从源代码构建 | Build from Source
```bash
# 克隆仓库
git clone https://github.com/yourusername/nebulafinger.git
cd nebulafinger

# 编译
go build -o nebulafinger.exe ./cmd

#运行
.\nebulafinger.exe -h
```

### 直接下载预编译版本 | Download Pre-compiled Version
从 [Releases](https://github.com/yourusername/nebulafinger/releases) 页面下载适合您系统的预编译版本，目前仅编译win版本，其余版本可自行编译

![](image.png)![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750499663575-a09a860c-1f8f-4136-a539-b12451525fe0.png)
![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750499752749-22136e75-3486-450d-bad6-8fb1e516656b.png)

## 📁 项目结构 | Project Structure
```plain
NebulaFinger/
├── cmd/                    # 命令行工具源代码
│   ├── common.go           # 通用功能和常量定义
│   ├── html.go             # HTML报告生成
│   ├── main.go             # 主程序入口
│   └── output.go           # 输出格式化
├── configs/                # 配置文件
│   ├── fingerprint_weights.json  # 置信度权重配置
│   ├── service_fingerprint_v4.json  # 服务指纹库
│   ├── tcp_ports.json      # 服务端口配置
│   └── web_fingerprint_v4.json  # Web指纹库
├── internal/               # 内部包
│   ├── cluster/            # 指纹聚类算法
│   ├── detector/           # 特征检测器
│   ├── matcher/            # 指纹匹配器
│   ├── scanner/            # 扫描器实现
│   │   ├── core.go         # 核心扫描逻辑
│   │   ├── http.go         # HTTP扫描
│   │   └── tcp.go          # 服务扫描
│   ├── config.go           # 配置定义
│   └── type.go             # 类型定义
├── go.mod                  # Go模块定义
├── go.sum                  # 依赖校验和
└── README.md               # 项目说明文档
```

## 🔍 使用方法 | Usage
### 基本使用 | Basic Usage
```bash
# 扫描单个目标
./nebulafinger -t example.com

# 从文件加载多个目标
./nebulafinger -l targets.txt

# 扫描并生成HTML报告
./nebulafinger -t example.com -o report.html

# 扫描Web和服务服务
./nebulafinger -t example.com -m all

```
### 命令行选项 | Command-line Options
```plain
 -c                 并发数（默认：5）
  -debug             调试模式
  -f                 从文件读取目标列表
  -m                 扫描模式: web, service, all（默认：web）
  -u                 指定扫描的目标 (例如: example.com 或 http://example.com)
  -no-favicon        禁用Favicon检测
  -o                 输出html文件
  -silent            静默模式，仅输出结果
  -map               特征映射文件路径（默认：feature_map.json）
  -s                 服务指纹库文件路径（默认：configs/service_fingerprint_v4.json）
  -w                 Web指纹库文件路径（默认：configs/web_fingerprint_v4.json）
  -BP-stat           只输出有指纹匹配的结果，不输出仅有状态码的结果
```

## 📊 输出示例 | Output Examples
### 控制台输出 | Console Output
![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750495975051-b0d1c539-f75d-4fe2-bf58-d3908e340993.png)

### HTML报告 | HTML Report
HTML报告提供了更丰富的视觉展示，包括指纹匹配结果、HTTP状态码、网站标题等详细信息，并按照不同类型进行分类展示。

![](https://cdn.nlark.com/yuque/0/2025/png/29128302/1750495899976-eefa1381-1dc9-4f20-8806-93329933347d.png)

#### HTML报告新特性
最新版本的HTML报告增加了多项实用功能：

1. **独立指纹卡片展示**：每个指纹结果以独立卡片形式展示，不再合并同一URL的多个指纹，使结果更清晰直观
2. **高级筛选功能**：
    - **指纹类型筛选**：通过下拉菜单可选择特定类型的Web或Service指纹
    - **状态码筛选**：按HTTP状态码（如200、404、500等）筛选结果
    - **置信度筛选**：按置信度级别（高、中、低）筛选结果
3. **实时搜索功能**：支持在结果中实时搜索关键词，快速定位特定指纹、URL或主机
4. **响应式设计**：优化的界面在不同设备上都能良好显示
5. **视觉优化**：改进的色彩方案和卡片布局，使报告更美观易读

## 🛠️ 高级功能 | Advanced Features
### 自定义指纹库 | Custom Fingerprint Database
可以通过 `-w` 和 `-s` 参数分别指定自定义的Web指纹库和服务指纹库：

You can specify custom web and service fingerprint databases using the `-w` and `-s` parameters:

```bash
./nebulafinger -t example.com -w custom_web_fingerprints.json -s custom_service_fingerprints.json
```

### 并发控制 | Concurrency Control
通过 `-c` 参数控制并发扫描的线程数：

Control the number of concurrent scanning threads using the `-c` parameter:

```bash
./nebulafinger -l targets.txt -c 10
```

### 置信度系统 | Confidence System
NebulaFinger采用智能置信度系统，为不同类型的匹配项分配不同权重：

+ **Favicon匹配**：最高置信度(99%)
+ **标题相关的匹配**：高置信度(95%)
+ **包含服务器信息的正则表达式匹配**：高置信度(90%)
+ **普通正则表达式匹配**：中等置信度(85%)
+ **普通关键词匹配**：中等置信度(80%)
+ **其他匹配类型**：较低置信度(10%)

置信度系统有助于减少误报，提高识别准确率。在HTML报告中，可以按置信度级别（高、中、低）筛选结果。

您可以通过修改`configs/fingerprint_weights.json`文件自定义这些权重值：

```json
{
  "matcher_weights": {
    "favicon": 0.99,
    "regex": {
      "default": 0.85,
      "server": 0.90,
      "title": 0.95
    },
    "word": {
      "default": 0.80,
      "server": 0.85,
      "title": 0.90
    }
  },
  "combo_weights": {
    "multiple_matchers": 0.10,
    "favicon_with_others": 0.15,
    "server_regex_with_title": 0.20
  },
  "min_confidence": 0.10,
  "max_confidence": 1.0
}
```

### 自定义服务端口配置 
您可以通过修改`configs/tcp_ports.json`文件自定义服务扫描端口，不建议设置过多，3-5个即可。
```json
{
  "default_ports": [21, 22, 25, 80, 443, 1521, 3306, 5432, 6379, 8080, 8443, 9200, 27017],
  "service_ports": {
    "ftp": [21],
    "ssh": [22],
    "http": [80, 8080]
    // 更多服务端口...
  }
}
```

## 🔄 更新日志 | Changelog
### v1.0.1 (2025-06-20)
+ **新增**: 优化HTML报告界面，添加指纹类型、状态码和置信度筛选功能
+ **新增**: 改进指纹展示方式，每个指纹独立展示，不再合并
+ **新增**: 添加实时搜索功能，支持按关键词筛选结果
+ **新增**: 添加智能置信度系统，提高识别准确率
+ **新增**: 添加`BP-stat`参数，只显示有指纹匹配的结果
+ **优化**: 改进HTML报告的响应式设计和视觉效果
+ **修复**: 修复了一些已知问题和bug

### v1.0.0 (2025-06-15)
+ 首次发布

## 🙏 致谢 | Acknowledgments
本项目的开发学习了以下优秀开源指纹识别工具的实现思路。

+ [TideFinger](https://github.com/TideSec/TideFinger) - Web指纹识别工具
+ [observer_ward](https://github.com/emo-crab/observer_ward) - 基于Rust的快速指纹识别工具
+ [hfinger](https://github.com/hazcod/hfinger) - 轻量级HTTP指纹工具

---

<sub>Build with </sub><sub>❤️</sub><sub> by DrBlack</sub>


