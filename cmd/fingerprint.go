package main

import (
	"encoding/json"
	"fmt"
	"nebulafinger/internal"
	"os"
)

// 加载指纹库和特征映射
func loadFingerprints() ([]internal.Fingerprint, []internal.Fingerprint, map[internal.FeatureKey][]string, error) {
	// 加载Web指纹库
	webData, err := os.ReadFile(webFPFlag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取Web指纹库失败: %v", err)
	}

	var webFingerprints []internal.Fingerprint
	if err := json.Unmarshal(webData, &webFingerprints); err != nil {
		return nil, nil, nil, fmt.Errorf("解析Web指纹库失败: %v", err)
	}

	// 加载服务指纹库
	serviceData, err := os.ReadFile(serviceFPFlag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("读取服务指纹库失败: %v", err)
	}

	var serviceFingerprints []internal.Fingerprint
	if err := json.Unmarshal(serviceData, &serviceFingerprints); err != nil {
		return nil, nil, nil, fmt.Errorf("解析服务指纹库失败: %v", err)
	}

	// 加载特征映射，如果不存在则生成
	featureMap, err := loadOrGenerateFeatureMap(webFingerprints, serviceFingerprints)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("处理特征映射失败: %v", err)
	}

	return webFingerprints, serviceFingerprints, featureMap, nil
}

// 加载或生成特征映射
func loadOrGenerateFeatureMap(webFPs []internal.Fingerprint, serviceFPs []internal.Fingerprint) (map[internal.FeatureKey][]string, error) {
	// 尝试加载现有特征映射
	if featureMapData, err := os.ReadFile(featureMapFlag); err == nil {
		var featureMap map[internal.FeatureKey][]string
		if err := json.Unmarshal(featureMapData, &featureMap); err == nil {
			return featureMap, nil
		}
	}

	// 如果加载失败，生成新的特征映射
	if !silentFlag {
		fmt.Printf(ColorYellow + "[!] 特征映射文件不存在或无效，正在生成新的映射...\n" + ColorReset)
	}

	// 导入buildFeatureFingerprintMap函数
	featureMap := buildFeatureFingerprintMap(webFPs, serviceFPs)

	// 保存新生成的特征映射
	if featureMapData, err := json.MarshalIndent(featureMap, "", "  "); err == nil {
		if err := os.WriteFile(featureMapFlag, featureMapData, 0644); err != nil && !silentFlag {
			fmt.Printf(ColorYellow+"[!] 警告: 无法保存特征映射文件: %v\n"+ColorReset, err)
		}
	}

	return featureMap, nil
}
