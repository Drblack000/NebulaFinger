package utils

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"
)

// TLSVersion 定义TLS版本
type TLSVersion uint16

const (
	TLS10 TLSVersion = 0x0301
	TLS11 TLSVersion = 0x0302
	TLS12 TLSVersion = 0x0303
	TLS13 TLSVersion = 0x0304
)

// HTTPClientOptions 定义HTTP客户端选项
type HTTPClientOptions struct {
	// 请求超时
	Timeout time.Duration
	// TLS配置
	InsecureSkipVerify bool
	MinTLSVersion      TLSVersion
	// 重定向设置
	RedirectPolicy     string // "none", "follow", "custom"
	MaxRedirects       int
	AllowHostRedirects bool
	// Cookie设置
	EnableCookieJar bool
	// 用户代理
	UserAgent string
	// 默认请求头
	DefaultHeaders map[string]string
}

// DefaultHTTPClientOptions 返回默认的HTTP客户端选项
func DefaultHTTPClientOptions() HTTPClientOptions {
	return HTTPClientOptions{
		Timeout:            30 * time.Second,
		InsecureSkipVerify: true,
		MinTLSVersion:      TLS10,
		RedirectPolicy:     "follow",
		MaxRedirects:       5,
		AllowHostRedirects: true,
		EnableCookieJar:    true,
		UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		DefaultHeaders: map[string]string{
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
			"Accept-Encoding": "gzip, deflate, br",
			"Connection":      "keep-alive",
		},
	}
}

// NewHTTPClient 创建一个新的HTTP客户端
func NewHTTPClient(options HTTPClientOptions) (*http.Client, error) {
	// 配置TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: options.InsecureSkipVerify,
		MinVersion:         uint16(options.MinTLSVersion),
	}

	// 配置Transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// 配置Cookie Jar
	var jar http.CookieJar
	var err error
	if options.EnableCookieJar {
		jar, err = cookiejar.New(nil)
		if err != nil {
			return nil, err
		}
	}

	// 配置重定向策略
	var redirectPolicy func(req *http.Request, via []*http.Request) error
	switch options.RedirectPolicy {
	case "none":
		redirectPolicy = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	case "follow":
		redirectPolicy = func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}
	case "custom":
		redirectPolicy = func(req *http.Request, via []*http.Request) error {
			if len(via) >= options.MaxRedirects {
				return http.ErrUseLastResponse
			}

			// 检查是否允许主机重定向
			if !options.AllowHostRedirects {
				if len(via) > 0 {
					originalHost := via[0].URL.Host
					if req.URL.Host != originalHost {
						return http.ErrUseLastResponse
					}
				}
			}

			// 将原始请求的头信息复制到重定向请求
			for key, values := range via[0].Header {
				// 不复制某些特定的头部
				if key != "Authorization" && key != "Cookie" {
					for _, value := range values {
						req.Header.Add(key, value)
					}
				}
			}

			return nil
		}
	}

	// 创建HTTP客户端
	client := &http.Client{
		Timeout:       options.Timeout,
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: redirectPolicy,
	}

	return client, nil
}

// HTTPRequest 表示一个HTTP请求
type HTTPRequest struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        io.Reader
	QueryParams map[string]string
}

// NewHTTPRequest 创建一个新的HTTP请求
func NewHTTPRequest(request HTTPRequest, clientOptions HTTPClientOptions) (*http.Request, error) {
	// 处理URL查询参数
	reqURL, err := url.Parse(request.URL)
	if err != nil {
		return nil, err
	}

	if request.QueryParams != nil && len(request.QueryParams) > 0 {
		q := reqURL.Query()
		for k, v := range request.QueryParams {
			q.Set(k, v)
		}
		reqURL.RawQuery = q.Encode()
	}

	// 创建HTTP请求
	req, err := http.NewRequest(request.Method, reqURL.String(), request.Body)
	if err != nil {
		return nil, err
	}

	// 添加默认请求头
	for k, v := range clientOptions.DefaultHeaders {
		req.Header.Set(k, v)
	}

	// 添加User-Agent
	req.Header.Set("User-Agent", clientOptions.UserAgent)

	// 添加自定义请求头
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// SendRequest 发送HTTP请求
func SendRequest(client *http.Client, request HTTPRequest, clientOptions HTTPClientOptions) (*http.Response, error) {
	req, err := NewHTTPRequest(request, clientOptions)
	if err != nil {
		return nil, err
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	// 读取响应体内容
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	resp.Body.Close()

	// 创建一个新的响应，但替换Body为可重用的ReadCloser
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	return resp, nil
}

// PrintHTTPResponse 打印HTTP响应内容，方便调试
func PrintHTTPResponse(resp *http.Response) {
	if resp == nil {
		fmt.Println("HTTP响应为空")
		return
	}

	fmt.Printf("HTTP/%d.%d %d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status)

	// 打印所有响应头
	for name, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
		}
	}

	fmt.Println() // 添加一个空行分隔头部和正文

	// 读取并打印响应体
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应体失败: %v\n", err)
		return
	}

	// 重置响应体，以便后续可以再次读取
	resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// 打印响应体内容
	fmt.Println(string(bodyBytes))
}
