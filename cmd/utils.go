package main

import (
	"bufio"
	"os"
	"strings"
)

// 从文件加载目标
func loadTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		target := strings.TrimSpace(scanner.Text())
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return targets, nil
}

// 去重
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
