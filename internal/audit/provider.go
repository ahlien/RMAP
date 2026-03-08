/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package audit

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

var (
	asnDB  *geoip2.Reader
	cityDB *geoip2.Reader

	// threats acts as a unified in-memory set for both malicious domains and IPs.
	threats    = make(map[string]bool)
	threatLock sync.RWMutex
	once       sync.Once
)

// InitExternalData initializes all external data resources with strict validation.
// It mandates the successful loading of ASN and City databases but tolerates
// missing Threat Intelligence feeds, allowing the engine to run without them.
func InitExternalData(asnPath, cityPath, threatDomainPath, threatIPPath string) {
	once.Do(func() {
		// 1. Load ASN Database (Mandatory component, exits on failure)
		if reader, err := geoip2.Open(asnPath); err == nil {
			asnDB = reader
			fmt.Printf("✅ [Success] ASN database loaded successfully.\n")
		} else {
			fmt.Printf("❌ [FATAL] Failed to load ASN database: %v\n", err)
			os.Exit(1)
		}

		// 2. Load City Database (Mandatory component, exits on failure)
		if reader, err := geoip2.Open(cityPath); err == nil {
			cityDB = reader
			fmt.Printf("✅ [Success] City geolocation database loaded successfully.\n")
		} else {
			fmt.Printf("❌ [FATAL] Failed to load City database: %v\n", err)
			os.Exit(1)
		}

		// 3. Load Threat Intelligence Feeds (Loads Domains and IPs separately)
		domainCount := loadThreatIntel(threatDomainPath, "Domain")
		ipCount := loadThreatIntel(threatIPPath, "IP")
		fmt.Printf("✅ [Success] Threat Intel Feeds loaded. Parsed %d domain IOCs and %d IP IOCs.\n", domainCount, ipCount)
	})
}

// loadThreatIntel parses a text-based threat intelligence feed and returns the number of loaded records.
func loadThreatIntel(path string, intelType string) int {
	f, err := os.Open(path)
	if err != nil {
		// Tolerate missing individual intel feeds by printing a warning instead of a hard exit
		fmt.Printf("⚠️  [WARNING] Failed to open %s threat intel feed: %v\n", intelType, err)
		return 0
	}
	defer f.Close()

	threatLock.Lock()
	defer threatLock.Unlock()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		item := strings.TrimSpace(strings.ToLower(scanner.Text()))
		// Ignore empty lines and commented lines starting with '#'
		if item != "" && !strings.HasPrefix(item, "#") {
			// Normalize domains by removing the trailing root dot ('.').
			// This string manipulation is also safe for standard IPv4/IPv6 strings.
			threats[strings.TrimSuffix(item, ".")] = true
			count++
		}
	}
	return count
}

// =====================================================================
// 🌟 Exported Functions for the Engine & Auditors
// =====================================================================

// IsThreatDomain checks if the target domain or IP exists in the loaded threat intelligence blacklists.
func IsThreatDomain(target string) bool {
	threatLock.RLock()
	defer threatLock.RUnlock()
	cleanTarget := strings.TrimSuffix(strings.ToLower(target), ".")
	return threats[cleanTarget]
}

// GetASN retrieves the Autonomous System Organization name for a given IP address.
// Example return value: "AS4134 (ChinaNet)"
func GetASN(ip net.IP) string {
	if asnDB == nil {
		return ""
	}
	record, err := asnDB.ASN(ip)
	if err != nil {
		return ""
	}
	return record.AutonomousSystemOrganization
}

// GetCity retrieves the city name for a given IP address.
func GetCity(ip net.IP) string {
	if cityDB == nil {
		return ""
	}
	record, err := cityDB.City(ip)
	if err != nil {
		return ""
	}
	// Prefer the localized Chinese name if available, fallback to the default English name
	if name, ok := record.City.Names["zh-CN"]; ok {
		return name
	}
	return record.City.Names["en"]
}

// package audit

// import (
// 	"bufio"
// 	"fmt"
// 	"net"
// 	"os"
// 	"strings"
// 	"sync"

// 	"github.com/oschwald/geoip2-golang"
// )

// var (
// 	asnDB  *geoip2.Reader
// 	cityDB *geoip2.Reader
// 	// threats 统一存放恶意域名和恶意 IP
// 	threats    = make(map[string]bool)
// 	threatLock sync.RWMutex
// 	once       sync.Once
// )

// // InitExternalData 初始化所有外部资源 (带强校验)
// // 包含: ASN 库路径、City 库路径、恶意域名文件路径、恶意 IP 文件路径
// func InitExternalData(asnPath, cityPath, threatDomainPath, threatIPPath string) {
// 	once.Do(func() {
// 		// 1. 加载 ASN 数据库 (必备组件，失败则退出)
// 		if reader, err := geoip2.Open(asnPath); err == nil {
// 			asnDB = reader
// 			fmt.Printf("✅ [成功] ASN 归属地库加载完毕\n")
// 		} else {
// 			fmt.Printf("❌ [致命错误] 无法加载 ASN 库: %v\n", err)
// 			os.Exit(1)
// 		}

// 		// 2. 加载城市数据库 (必备组件，失败则退出)
// 		if reader, err := geoip2.Open(cityPath); err == nil {
// 			cityDB = reader
// 			fmt.Printf("✅ [成功] 城市地理库加载完毕\n")
// 		} else {
// 			fmt.Printf("❌ [致命错误] 无法加载城市库: %v\n", err)
// 			os.Exit(1)
// 		}

// 		// 3. 加载威胁情报黑名单 (分别加载域名和 IP)
// 		domainCount := loadThreatIntel(threatDomainPath, "域名")
// 		ipCount := loadThreatIntel(threatIPPath, "IP")
// 		fmt.Printf("✅ [成功] 威胁情报库加载完毕, 共载入 %d 条域名 IOCs, %d 条 IP IOCs\n", domainCount, ipCount)
// 	})
// }

// // loadThreatIntel 从文件加载威胁情报，并返回成功加载的条数
// func loadThreatIntel(path string, intelType string) int {
// 	f, err := os.Open(path)
// 	if err != nil {
// 		// 找不到文件时，打印警告但不直接退出，容忍单个情报库缺失
// 		fmt.Printf("⚠️  [警告] 无法打开%s情报库文件: %v\n", intelType, err)
// 		return 0
// 	}
// 	defer f.Close()

// 	threatLock.Lock()
// 	defer threatLock.Unlock()

// 	scanner := bufio.NewScanner(f)
// 	count := 0
// 	for scanner.Scan() {
// 		item := strings.TrimSpace(strings.ToLower(scanner.Text()))
// 		// 忽略空行和以 # 开头的注释行
// 		if item != "" && !strings.HasPrefix(item, "#") {
// 			// 如果是域名，去掉末尾可能存在的根点 "."；如果是 IP，去掉点也没影响
// 			threats[strings.TrimSuffix(item, ".")] = true
// 			count++
// 		}
// 	}
// 	return count
// }

// // =====================================================================
// // 🌟 供 engine 调用的导出函数
// // =====================================================================

// // IsThreatDomain 检查目标域名或 IP 是否存在于黑名单中
// func IsThreatDomain(target string) bool {
// 	threatLock.RLock()
// 	defer threatLock.RUnlock()
// 	cleanTarget := strings.TrimSuffix(strings.ToLower(target), ".")
// 	return threats[cleanTarget]
// }

// // GetASN 获取 IP 对应的自治系统名称 (如: "AS4134 (ChinaNet)")
// func GetASN(ip net.IP) string {
// 	if asnDB == nil {
// 		return ""
// 	}
// 	record, err := asnDB.ASN(ip)
// 	if err != nil {
// 		return ""
// 	}
// 	return record.AutonomousSystemOrganization
// }

// // GetCity 获取 IP 对应的城市名称
// func GetCity(ip net.IP) string {
// 	if cityDB == nil {
// 		return ""
// 	}
// 	record, err := cityDB.City(ip)
// 	if err != nil {
// 		return ""
// 	}
// 	// 默认返回中文名，如果不存在则退化返回英文名
// 	if name, ok := record.City.Names["zh-CN"]; ok {
// 		return name
// 	}
// 	return record.City.Names["en"]
// }
