/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package main

import (
	"bufio"
	"dns-analyzer/internal/audit"
	"dns-analyzer/internal/config"
	"dns-analyzer/internal/engine"
	"dns-analyzer/internal/model"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

// ReportData encapsulates the complete topology and audit report for a single domain.
type ReportData struct {
	Domain      string           `json:"domain"`
	Nodes       []model.Node     `json:"nodes"`
	Edges       []model.Edge     `json:"edges"`
	NSRecords   []model.NSRecord `json:"ns_records"`
	AuditReport []audit.Issue    `json:"audit_report"`
}

// Target represents a single probing task.
type Target struct {
	Domain string
	QType  uint16
}

// NodeMatch represents the details of a specific node that matched the search criteria.
type NodeMatch struct {
	NodeTriplet string   `json:"node_triplet"`
	Rcode       int      `json:"rcode"`
	Flags       string   `json:"flags,omitempty"`
	EDE         string   `json:"ede,omitempty"`
	Issues      []string `json:"issues,omitempty"`
}

// DomainSearchResult represents a single line of output in the JSONL search results,
// aggregating all matches for a target domain.
type DomainSearchResult struct {
	TargetDomain string      `json:"target_domain"`
	Matches      []NodeMatch `json:"matches"`
}

// Global variables and statistics trackers
var (
	searchResultFile *os.File
	searchMutex      sync.Mutex

	matchCount int32 // Total number of domains that triggered anomalies

	// Detailed statistics trackers (Maps protected by Mutex, broad counters use atomic operations)
	statDetailsLock sync.Mutex
	statRcodeHits   int32
	statEdeHits     int32
	statFlagsHits   int32
	statIssuesHits  int32

	statRcodeDetails  = make(map[int]int32)
	statEdeDetails    = make(map[string]int32)
	statFlagsDetails  = make(map[string]int32)
	statIssuesDetails = make(map[string]int32)
)

func main() {
	startTime := time.Now()

	// 1. Load base configuration
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Printf("❌ Config Error: %v\n", err)
		return
	}

	// 2. Initialize external data (GeoIP databases and Threat Intelligence feeds)
	audit.InitExternalData(
		"./assets/geo/GeoLite2-ASN.mmdb",
		"./assets/geo/GeoLite2-City.mmdb",
		"./assets/intel/threat_domains.txt", // Malicious domains feed
		"./assets/intel/threat_ips.txt",     // Malicious IPs feed
	)

	rootIP := cfg.Bootstrap.RootServers[0].IPv4
	if cfg.Engine.NetworkEnv == config.EnvIPv6 {
		rootIP = cfg.Bootstrap.RootServers[0].IPv6
	}

	os.MkdirAll(cfg.Output.ReportDir, 0755)

	// 3. Initialize search results output file (JSONL stream)
	if cfg.Search.Enabled && cfg.Output.SaveSearchResults {
		outPath := cfg.Search.OutputFile
		if outPath == "" {
			outPath = filepath.Join(cfg.Output.ReportDir, "search_results.jsonl")
		}
		os.MkdirAll(filepath.Dir(outPath), 0755)
		searchResultFile, err = os.Create(outPath)
		if err != nil {
			fmt.Printf("❌ Failed to create search results file: %v\n", err)
			return
		}
		defer searchResultFile.Close()
		fmt.Printf(">>> 💾 Search results streaming enabled (JSONL): %s\n", outPath)
	}

	// 4. Bootstrapping concurrent worker pool
	workerCount := cfg.Engine.MaxConcurrency
	if workerCount <= 0 {
		workerCount = 100
	}
	jobs := make(chan Target, workerCount*2)
	var wg sync.WaitGroup
	var completedCount int32

	fmt.Printf(">>> 🚀 Starting probing cluster... (Max Concurrency: %d)\n", workerCount)
	if cfg.Search.Enabled {
		fmt.Printf(">>> 🔎 Precision Search Mode -> Rcodes: %v | EDEs: %v | Issues: %v\n",
			cfg.Search.TargetRcodes, cfg.Search.TargetEDEs, cfg.Search.TargetIssues)
	}

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range jobs {
				processDomain(t, cfg, rootIP)
				atomic.AddInt32(&completedCount, 1)

				count := atomic.LoadInt32(&completedCount)
				if count%1000 == 0 {
					fmt.Printf("... Probed: %d domains (Elapsed: %v)\n", count, time.Since(startTime))
				}
			}
		}()
	}

	// 5. Read target domains (File stream or direct config targets)
	seen := make(map[string]bool)
	if cfg.Input.FileTargets.Enabled && cfg.Input.FileTargets.Path != "" {
		fmt.Printf("📂 Mode: Streaming targets from file -> %s\n", cfg.Input.FileTargets.Path)
		file, err := os.Open(cfg.Input.FileTargets.Path)
		if err == nil {
			defer file.Close()
			defaultQType := parseQType(cfg.Input.FileTargets.DefaultQType)
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				domain := formatDomain(scanner.Text())
				if domain == "" {
					continue
				}
				key := fmt.Sprintf("%s-%d", domain, defaultQType)
				if !seen[key] {
					seen[key] = true
					jobs <- Target{Domain: domain, QType: defaultQType}
				}
			}
		}
	} else {
		for _, t := range cfg.Input.DirectTargets {
			domain := formatDomain(t.Domain)
			qtype := parseQType(t.QType)
			key := fmt.Sprintf("%s-%d", domain, qtype)
			if !seen[key] {
				seen[key] = true
				jobs <- Target{Domain: domain, QType: qtype}
			}
		}
	}

	close(jobs)
	wg.Wait()

	// 6. Render final statistics dashboard
	renderStatistics(startTime, completedCount, cfg)
}

// renderStatistics renders the final tree-structured statistics dashboard.
func renderStatistics(startTime time.Time, totalDomains int32, cfg *config.Config) {
	totalElapsed := time.Since(startTime)
	qps := float64(totalDomains) / totalElapsed.Seconds()

	fmt.Printf("\n======================================================\n")
	fmt.Printf("✅ All tasks completed successfully!\n")
	fmt.Printf("📊 Total Domains Processed: %d\n", totalDomains)
	fmt.Printf("⏱️  Total Execution Time: %v\n", totalElapsed)
	if totalElapsed.Seconds() > 0 {
		fmt.Printf("🚀 Average Speed: %.2f domains/sec\n", qps)
	}

	if cfg.Search.Enabled && totalDomains > 0 {
		totalMatches := atomic.LoadInt32(&matchCount)
		matchRate := (float64(totalMatches) / float64(totalDomains)) * 100

		fmt.Printf("------------------------------------------------------\n")
		fmt.Printf("🎯 Total Hits: %d domains with anomalies (Pollution Rate: %.2f%%)\n", totalMatches, matchRate)

		if totalMatches > 0 {
			fmt.Printf("🔍 Anomaly Dimension Breakdown (Base: %d total domains):\n", totalDomains)

			statDetailsLock.Lock()
			defer statDetailsLock.Unlock()

			type TreeBlock struct {
				Title     string
				Hits      int32
				PrintFunc func(isLast bool)
			}

			var blocks []TreeBlock
			if cfg.Search.EnableRcodeCheck {
				blocks = append(blocks, TreeBlock{"[RCODE]: ", statRcodeHits, func(isLast bool) { printRcodeDetails(statRcodeDetails, totalDomains, isLast) }})
			}
			if cfg.Search.EnableEdeCheck {
				blocks = append(blocks, TreeBlock{"[EDE]:   ", statEdeHits, func(isLast bool) { printStrDetails(statEdeDetails, totalDomains, isLast) }})
			}
			if cfg.Search.EnableFlagsCheck {
				blocks = append(blocks, TreeBlock{"[Flags]: ", statFlagsHits, func(isLast bool) { printStrDetails(statFlagsDetails, totalDomains, isLast) }})
			}
			if cfg.Search.EnableIssueCheck {
				blocks = append(blocks, TreeBlock{"[Issues]:", statIssuesHits, func(isLast bool) { printStrDetails(statIssuesDetails, totalDomains, isLast) }})
			}

			for i, block := range blocks {
				isLast := (i == len(blocks)-1)
				treeChar := "├─"
				if isLast {
					treeChar = "└─"
				}
				fmt.Printf("   %s %s %5d domains (Ratio: %5.2f%%)\n", treeChar, block.Title, block.Hits, float64(block.Hits)/float64(totalDomains)*100)
				block.PrintFunc(isLast)
			}
		}
	}
	fmt.Printf("======================================================\n")
}

func printStrDetails(m map[string]int32, total int32, isParentLast bool) {
	if len(m) == 0 {
		return
	}
	type kv struct {
		K string
		V int32
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].V > s[j].V })

	prefix := "   │  "
	if isParentLast {
		prefix = "      "
	}
	for i, x := range s {
		branch := "├─"
		if i == len(s)-1 {
			branch = "└─"
		}
		fmt.Printf("%s%s %-25s : %5d (%6.2f%%)\n", prefix, branch, x.K, x.V, float64(x.V)/float64(total)*100)
	}
}

func printRcodeDetails(m map[int]int32, total int32, isParentLast bool) {
	if len(m) == 0 {
		return
	}
	type kv struct {
		K int
		V int32
	}
	var s []kv
	for k, v := range m {
		s = append(s, kv{k, v})
	}
	sort.Slice(s, func(i, j int) bool { return s[i].V > s[j].V })

	prefix := "   │  "
	if isParentLast {
		prefix = "      "
	}
	for i, x := range s {
		branch := "├─"
		if i == len(s)-1 {
			branch = "└─"
		}
		fmt.Printf("%s%s RCODE %-20d : %5d (%6.2f%%)\n", prefix, branch, x.K, x.V, float64(x.V)/float64(total)*100)
	}
}

// processDomain handles the complete lifecycle of probing, auditing, and saving a domain.
func processDomain(t Target, cfg *config.Config, rootIP string) {
	eng := engine.NewEngine(cfg)
	eng.Run("", model.EdgeReferral, rootIP, t.Domain, t.QType, 0)
	eng.WG.Wait()

	// Execute security and compliance audits
	issues := audit.RunAllAudits(eng.Graph, t.Domain)

	nodeIssuesMap := make(map[string][]string)
	for _, iss := range issues {
		for _, nodeID := range iss.NodeIDs {
			nodeIssuesMap[nodeID] = append(nodeIssuesMap[nodeID], iss.Type)
		}
	}

	if cfg.Search.Enabled {
		var localMatches []NodeMatch
		var dHitRcode, dHitEde, dHitFlags, dHitIssues bool
		dRcodes := make(map[int]bool)
		dEdes := make(map[string]bool)
		dFlags := make(map[string]bool)
		dIssues := make(map[string]bool)

		eng.Graph.Nodes.Range(func(_, v any) bool {
			n := v.(*model.Node)
			hRcode, hEde, hFlags, hIssues := false, false, false, false
			currentIssues := nodeIssuesMap[n.ID]

			// RCODE matching logic
			if cfg.Search.EnableRcodeCheck {
				for _, r := range cfg.Search.TargetRcodes {
					if n.Rcode == r {
						hRcode = true
					}
				}
				if cfg.Search.MatchInvalidRcode && ((n.Rcode >= 11 && n.Rcode <= 15) || n.Rcode >= 25) {
					hRcode = true
				}
				if hRcode {
					dRcodes[n.Rcode] = true
				}
			}

			// EDE matching logic
			if cfg.Search.EnableEdeCheck {
				for _, target := range cfg.Search.TargetEDEs {
					if (target == "*" && n.EDE != "") || (target != "" && strings.Contains(n.EDE, target)) {
						hEde = true
					}
				}
				if hEde && n.EDE != "" {
					for _, p := range strings.Split(n.EDE, " | ") {
						dEdes[strings.TrimSpace(p)] = true
					}
				}
			}

			// Flags matching logic
			if cfg.Search.EnableFlagsCheck {
				nodeF := " " + n.Flags + " "
				for _, tf := range cfg.Search.TargetFlags {
					if strings.Contains(nodeF, " "+strings.ToLower(tf)+" ") {
						hFlags = true
					}
				}
				if hFlags {
					for _, f := range strings.Fields(n.Flags) {
						dFlags[strings.ToLower(f)] = true
					}
				}
			}

			// Security Issues matching logic
			if cfg.Search.EnableIssueCheck {
				for _, actual := range currentIssues {
					for _, target := range cfg.Search.TargetIssues {
						if target == "*" || strings.EqualFold(actual, target) {
							hIssues = true
							dIssues[actual] = true
						}
					}
				}
			}

			if hRcode || hEde || hFlags || hIssues {
				if hRcode {
					dHitRcode = true
				}
				if hEde {
					dHitEde = true
				}
				if hFlags {
					dHitFlags = true
				}
				if hIssues {
					dHitIssues = true
				}
				localMatches = append(localMatches, NodeMatch{n.ID, n.Rcode, n.Flags, n.EDE, currentIssues})
			}
			return true
		})

		if len(localMatches) > 0 {
			atomic.AddInt32(&matchCount, 1)
			statDetailsLock.Lock()
			if dHitRcode {
				statRcodeHits++
				for k := range dRcodes {
					statRcodeDetails[k]++
				}
			}
			if dHitEde {
				statEdeHits++
				for k := range dEdes {
					statEdeDetails[k]++
				}
			}
			if dHitFlags {
				statFlagsHits++
				for k := range dFlags {
					statFlagsDetails[k]++
				}
			}
			if dHitIssues {
				statIssuesHits++
				for k := range dIssues {
					statIssuesDetails[k]++
				}
			}
			statDetailsLock.Unlock()

			if searchResultFile != nil {
				jsonData, _ := json.Marshal(DomainSearchResult{t.Domain, localMatches})
				searchMutex.Lock()
				searchResultFile.Write(jsonData)
				searchResultFile.WriteString("\n")
				searchMutex.Unlock()
			}
		}
	}

	// Save individual topology report
	if cfg.Output.SaveIndividualReports {
		saveReport(eng.Graph, t, issues, cfg.Output.ReportDir)
	}
}

func saveReport(g *model.Graph, t Target, issues []audit.Issue, dir string) {
	export := g.Export()
	final := ReportData{t.Domain, export.Nodes, export.Edges, export.NSRecords, issues}
	fileName := fmt.Sprintf("%s_%s.json", strings.TrimSuffix(t.Domain, "."), dns.TypeToString[t.QType])
	f, err := os.Create(filepath.Join(dir, fileName))
	if err == nil {
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		enc.Encode(final)
	}
}

func formatDomain(d string) string {
	d = strings.TrimSpace(d)
	if d == "" || strings.HasPrefix(d, "#") {
		return ""
	}
	if !strings.HasSuffix(d, ".") {
		d += "."
	}
	return d
}

func parseQType(qStr string) uint16 {
	switch strings.ToUpper(strings.TrimSpace(qStr)) {
	case "AAAA":
		return dns.TypeAAAA
	case "CNAME":
		return dns.TypeCNAME
	case "NS":
		return dns.TypeNS
	default:
		return dns.TypeA
	}
}

// package main

// import (
// 	"bufio"
// 	"dns-analyzer/internal/audit"
// 	"dns-analyzer/internal/config"
// 	"dns-analyzer/internal/engine"
// 	"dns-analyzer/internal/model"
// 	"encoding/json"
// 	"fmt"
// 	"os"
// 	"path/filepath"
// 	"sort"
// 	"strings"
// 	"sync"
// 	"sync/atomic"
// 	"time"

// 	"github.com/miekg/dns"
// )

// // ReportData 用于保存单域名完整拓扑报告
// type ReportData struct {
// 	Domain      string           `json:"domain"`
// 	Nodes       []model.Node     `json:"nodes"`
// 	Edges       []model.Edge     `json:"edges"`
// 	NSRecords   []model.NSRecord `json:"ns_records"`
// 	AuditReport []audit.Issue    `json:"audit_report"`
// }

// type Target struct {
// 	Domain string
// 	QType  uint16
// }

// // NodeMatch 用于检索结果中的节点详情
// type NodeMatch struct {
// 	NodeTriplet string   `json:"node_triplet"`
// 	Rcode       int      `json:"rcode"`
// 	Flags       string   `json:"flags,omitempty"`
// 	EDE         string   `json:"ede,omitempty"`
// 	Issues      []string `json:"issues,omitempty"`
// }

// // DomainSearchResult 用于 JSONL 的一行输出（单域名聚合）
// type DomainSearchResult struct {
// 	TargetDomain string      `json:"target_domain"`
// 	Matches      []NodeMatch `json:"matches"`
// }

// // 全局变量与统计模块
// var (
// 	searchResultFile *os.File
// 	searchMutex      sync.Mutex

// 	matchCount int32 // 命中异常的域名总数

// 	// 统计详情追踪器 (Map 使用锁保护，大类计数使用原子操作)
// 	statDetailsLock sync.Mutex
// 	statRcodeHits   int32
// 	statEdeHits     int32
// 	statFlagsHits   int32
// 	statIssuesHits  int32

// 	statRcodeDetails  = make(map[int]int32)
// 	statEdeDetails    = make(map[string]int32)
// 	statFlagsDetails  = make(map[string]int32)
// 	statIssuesDetails = make(map[string]int32)
// )

// func main() {
// 	startTime := time.Now()

// 	// 1. 加载基础配置
// 	cfg, err := config.LoadConfig("config.yaml")
// 	if err != nil {
// 		fmt.Printf("❌ Config Error: %v\n", err)
// 		return
// 	}

// 	// 2. 🌟 初始化外部数据 (GeoIP 库与威胁情报黑名单)
// 	audit.InitExternalData(
// 		"./assets/geo/GeoLite2-ASN.mmdb",
// 		"./assets/geo/GeoLite2-City.mmdb",
// 		"./assets/intel/threat_domains.txt", // 域名黑名单
// 		"./assets/intel/threat_ips.txt",
// 	)

// 	rootIP := cfg.Bootstrap.RootServers[0].IPv4
// 	if cfg.Engine.NetworkEnv == config.EnvIPv6 {
// 		rootIP = cfg.Bootstrap.RootServers[0].IPv6
// 	}

// 	os.MkdirAll(cfg.Output.ReportDir, 0755)

// 	// 3. 初始化检索结果输出文件 (JSONL)
// 	if cfg.Search.Enabled && cfg.Output.SaveSearchResults {
// 		outPath := cfg.Search.OutputFile
// 		if outPath == "" {
// 			outPath = filepath.Join(cfg.Output.ReportDir, "search_results.jsonl")
// 		}
// 		os.MkdirAll(filepath.Dir(outPath), 0755)
// 		searchResultFile, err = os.Create(outPath)
// 		if err != nil {
// 			fmt.Printf("❌ 无法创建检索结果文件: %v\n", err)
// 			return
// 		}
// 		defer searchResultFile.Close()
// 		fmt.Printf(">>> 💾 检索结果流式落盘已开启 (JSONL): %s\n", outPath)
// 	}

// 	// 4. 启动并发工作池
// 	workerCount := cfg.Engine.MaxConcurrency
// 	if workerCount <= 0 {
// 		workerCount = 100
// 	}
// 	jobs := make(chan Target, workerCount*2)
// 	var wg sync.WaitGroup
// 	var completedCount int32

// 	fmt.Printf(">>> 🚀 启动探测集群... (并发上限: %d)\n", workerCount)
// 	if cfg.Search.Enabled {
// 		fmt.Printf(">>> 🔎 精准检索模式 -> Rcodes: %v | EDEs: %v | Issues: %v\n",
// 			cfg.Search.TargetRcodes, cfg.Search.TargetEDEs, cfg.Search.TargetIssues)
// 	}

// 	for i := 0; i < workerCount; i++ {
// 		wg.Add(1)
// 		go func() {
// 			defer wg.Done()
// 			for t := range jobs {
// 				processDomain(t, cfg, rootIP)
// 				atomic.AddInt32(&completedCount, 1)

// 				count := atomic.LoadInt32(&completedCount)
// 				if count%1000 == 0 {
// 					fmt.Printf("... 已完成探测: %d 个域名 (当前耗时: %v)\n", count, time.Since(startTime))
// 				}
// 			}
// 		}()
// 	}

// 	// 5. 读取任务目标 (文件流式读取或直接读取)
// 	seen := make(map[string]bool)
// 	if cfg.Input.FileTargets.Enabled && cfg.Input.FileTargets.Path != "" {
// 		fmt.Printf("📂 模式: 从文件流式读取 -> %s\n", cfg.Input.FileTargets.Path)
// 		file, err := os.Open(cfg.Input.FileTargets.Path)
// 		if err == nil {
// 			defer file.Close()
// 			defaultQType := parseQType(cfg.Input.FileTargets.DefaultQType)
// 			scanner := bufio.NewScanner(file)
// 			for scanner.Scan() {
// 				domain := formatDomain(scanner.Text())
// 				if domain == "" {
// 					continue
// 				}
// 				key := fmt.Sprintf("%s-%d", domain, defaultQType)
// 				if !seen[key] {
// 					seen[key] = true
// 					jobs <- Target{Domain: domain, QType: defaultQType}
// 				}
// 			}
// 		}
// 	} else {
// 		for _, t := range cfg.Input.DirectTargets {
// 			domain := formatDomain(t.Domain)
// 			qtype := parseQType(t.QType)
// 			key := fmt.Sprintf("%s-%d", domain, qtype)
// 			if !seen[key] {
// 				seen[key] = true
// 				jobs <- Target{Domain: domain, QType: qtype}
// 			}
// 		}
// 	}

// 	close(jobs)
// 	wg.Wait()

// 	// 6. 🌟 最终统计看板 (完美树形结构)
// 	renderStatistics(startTime, completedCount, cfg)
// }

// // renderStatistics 负责打印最终的树形统计结果
// func renderStatistics(startTime time.Time, totalDomains int32, cfg *config.Config) {
// 	totalElapsed := time.Since(startTime)
// 	qps := float64(totalDomains) / totalElapsed.Seconds()

// 	fmt.Printf("\n======================================================\n")
// 	fmt.Printf("✅ 全部任务执行完毕!\n")
// 	fmt.Printf("📊 总计处理域名: %d 个\n", totalDomains)
// 	fmt.Printf("⏱️  程序运行耗时: %v\n", totalElapsed)
// 	if totalElapsed.Seconds() > 0 {
// 		fmt.Printf("🚀 平均处理速度: %.2f 域名/秒\n", qps)
// 	}

// 	if cfg.Search.Enabled && totalDomains > 0 {
// 		totalMatches := atomic.LoadInt32(&matchCount)
// 		matchRate := (float64(totalMatches) / float64(totalDomains)) * 100

// 		fmt.Printf("------------------------------------------------------\n")
// 		fmt.Printf("🎯 检索总命中数: %d 个域名存在异常 (总污染率: %.2f%%)\n", totalMatches, matchRate)

// 		if totalMatches > 0 {
// 			fmt.Printf("🔍 异常维度拆解分析 (占比基数为总探测数 %d 个):\n", totalDomains)

// 			statDetailsLock.Lock()
// 			defer statDetailsLock.Unlock()

// 			type TreeBlock struct {
// 				Title     string
// 				Hits      int32
// 				PrintFunc func(isLast bool)
// 			}

// 			var blocks []TreeBlock
// 			if cfg.Search.EnableRcodeCheck {
// 				blocks = append(blocks, TreeBlock{"[RCODE]: ", statRcodeHits, func(isLast bool) { printRcodeDetails(statRcodeDetails, totalDomains, isLast) }})
// 			}
// 			if cfg.Search.EnableEdeCheck {
// 				blocks = append(blocks, TreeBlock{"[EDE]:   ", statEdeHits, func(isLast bool) { printStrDetails(statEdeDetails, totalDomains, isLast) }})
// 			}
// 			if cfg.Search.EnableFlagsCheck {
// 				blocks = append(blocks, TreeBlock{"[Flags]: ", statFlagsHits, func(isLast bool) { printStrDetails(statFlagsDetails, totalDomains, isLast) }})
// 			}
// 			if cfg.Search.EnableIssueCheck {
// 				blocks = append(blocks, TreeBlock{"[Issues]:", statIssuesHits, func(isLast bool) { printStrDetails(statIssuesDetails, totalDomains, isLast) }})
// 			}

// 			for i, block := range blocks {
// 				isLast := (i == len(blocks)-1)
// 				treeChar := "├─"
// 				if isLast {
// 					treeChar = "└─"
// 				}
// 				fmt.Printf("   %s %s %5d 个域名 (占比: %5.2f%%)\n", treeChar, block.Title, block.Hits, float64(block.Hits)/float64(totalDomains)*100)
// 				block.PrintFunc(isLast)
// 			}
// 		}
// 	}
// 	fmt.Printf("======================================================\n")
// }

// func printStrDetails(m map[string]int32, total int32, isParentLast bool) {
// 	if len(m) == 0 {
// 		return
// 	}
// 	type kv struct {
// 		K string
// 		V int32
// 	}
// 	var s []kv
// 	for k, v := range m {
// 		s = append(s, kv{k, v})
// 	}
// 	sort.Slice(s, func(i, j int) bool { return s[i].V > s[j].V })

// 	prefix := "   │  "
// 	if isParentLast {
// 		prefix = "      "
// 	}
// 	for i, x := range s {
// 		branch := "├─"
// 		if i == len(s)-1 {
// 			branch = "└─"
// 		}
// 		fmt.Printf("%s%s %-25s : %5d 个 (%6.2f%%)\n", prefix, branch, x.K, x.V, float64(x.V)/float64(total)*100)
// 	}
// }

// func printRcodeDetails(m map[int]int32, total int32, isParentLast bool) {
// 	if len(m) == 0 {
// 		return
// 	}
// 	type kv struct {
// 		K int
// 		V int32
// 	}
// 	var s []kv
// 	for k, v := range m {
// 		s = append(s, kv{k, v})
// 	}
// 	sort.Slice(s, func(i, j int) bool { return s[i].V > s[j].V })

// 	prefix := "   │  "
// 	if isParentLast {
// 		prefix = "      "
// 	}
// 	for i, x := range s {
// 		branch := "├─"
// 		if i == len(s)-1 {
// 			branch = "└─"
// 		}
// 		fmt.Printf("%s%s RCODE %-20d : %5d 个 (%6.2f%%)\n", prefix, branch, x.K, x.V, float64(x.V)/float64(total)*100)
// 	}
// }

// func processDomain(t Target, cfg *config.Config, rootIP string) {
// 	eng := engine.NewEngine(cfg)
// 	eng.Run("", model.EdgeReferral, rootIP, t.Domain, t.QType, 0)
// 	eng.WG.Wait()

// 	// 执行审计
// 	issues := audit.RunAllAudits(eng.Graph, t.Domain)

// 	nodeIssuesMap := make(map[string][]string)
// 	for _, iss := range issues {
// 		for _, nodeID := range iss.NodeIDs {
// 			nodeIssuesMap[nodeID] = append(nodeIssuesMap[nodeID], iss.Type)
// 		}
// 	}

// 	if cfg.Search.Enabled {
// 		var localMatches []NodeMatch
// 		var dHitRcode, dHitEde, dHitFlags, dHitIssues bool
// 		dRcodes := make(map[int]bool)
// 		dEdes := make(map[string]bool)
// 		dFlags := make(map[string]bool)
// 		dIssues := make(map[string]bool)

// 		eng.Graph.Nodes.Range(func(_, v any) bool {
// 			n := v.(*model.Node)
// 			hRcode, hEde, hFlags, hIssues := false, false, false, false
// 			currentIssues := nodeIssuesMap[n.ID]

// 			// RCODE 逻辑
// 			if cfg.Search.EnableRcodeCheck {
// 				for _, r := range cfg.Search.TargetRcodes {
// 					if n.Rcode == r {
// 						hRcode = true
// 					}
// 				}
// 				if cfg.Search.MatchInvalidRcode && ((n.Rcode >= 11 && n.Rcode <= 15) || n.Rcode >= 25) {
// 					hRcode = true
// 				}
// 				if hRcode {
// 					dRcodes[n.Rcode] = true
// 				}
// 			}
// 			// EDE 逻辑
// 			if cfg.Search.EnableEdeCheck {
// 				for _, target := range cfg.Search.TargetEDEs {
// 					if (target == "*" && n.EDE != "") || (target != "" && strings.Contains(n.EDE, target)) {
// 						hEde = true
// 					}
// 				}
// 				if hEde && n.EDE != "" {
// 					for _, p := range strings.Split(n.EDE, " | ") {
// 						dEdes[strings.TrimSpace(p)] = true
// 					}
// 				}
// 			}
// 			// Flags 逻辑
// 			if cfg.Search.EnableFlagsCheck {
// 				nodeF := " " + n.Flags + " "
// 				for _, tf := range cfg.Search.TargetFlags {
// 					if strings.Contains(nodeF, " "+strings.ToLower(tf)+" ") {
// 						hFlags = true
// 					}
// 				}
// 				if hFlags {
// 					for _, f := range strings.Fields(n.Flags) {
// 						dFlags[strings.ToLower(f)] = true
// 					}
// 				}
// 			}
// 			// Issues 逻辑
// 			if cfg.Search.EnableIssueCheck {
// 				for _, actual := range currentIssues {
// 					for _, target := range cfg.Search.TargetIssues {
// 						if target == "*" || strings.EqualFold(actual, target) {
// 							hIssues = true
// 							dIssues[actual] = true
// 						}
// 					}
// 				}
// 			}

// 			if hRcode || hEde || hFlags || hIssues {
// 				if hRcode {
// 					dHitRcode = true
// 				}
// 				if hEde {
// 					dHitEde = true
// 				}
// 				if hFlags {
// 					dHitFlags = true
// 				}
// 				if hIssues {
// 					dHitIssues = true
// 				}
// 				localMatches = append(localMatches, NodeMatch{n.ID, n.Rcode, n.Flags, n.EDE, currentIssues})
// 			}
// 			return true
// 		})

// 		if len(localMatches) > 0 {
// 			atomic.AddInt32(&matchCount, 1)
// 			statDetailsLock.Lock()
// 			if dHitRcode {
// 				statRcodeHits++
// 				for k := range dRcodes {
// 					statRcodeDetails[k]++
// 				}
// 			}
// 			if dHitEde {
// 				statEdeHits++
// 				for k := range dEdes {
// 					statEdeDetails[k]++
// 				}
// 			}
// 			if dHitFlags {
// 				statFlagsHits++
// 				for k := range dFlags {
// 					statFlagsDetails[k]++
// 				}
// 			}
// 			if dHitIssues {
// 				statIssuesHits++
// 				for k := range dIssues {
// 					statIssuesDetails[k]++
// 				}
// 			}
// 			statDetailsLock.Unlock()

// 			if searchResultFile != nil {
// 				jsonData, _ := json.Marshal(DomainSearchResult{t.Domain, localMatches})
// 				searchMutex.Lock()
// 				searchResultFile.Write(jsonData)
// 				searchResultFile.WriteString("\n")
// 				searchMutex.Unlock()
// 			}
// 		}
// 	}

// 	// 保存个体报告
// 	if cfg.Output.SaveIndividualReports {
// 		saveReport(eng.Graph, t, issues, cfg.Output.ReportDir)
// 	}
// }

// func saveReport(g *model.Graph, t Target, issues []audit.Issue, dir string) {
// 	export := g.Export()
// 	final := ReportData{t.Domain, export.Nodes, export.Edges, export.NSRecords, issues}
// 	fileName := fmt.Sprintf("%s_%s.json", strings.TrimSuffix(t.Domain, "."), dns.TypeToString[t.QType])
// 	f, err := os.Create(filepath.Join(dir, fileName))
// 	if err == nil {
// 		defer f.Close()
// 		enc := json.NewEncoder(f)
// 		enc.SetIndent("", "  ")
// 		enc.Encode(final)
// 	}
// }

// func formatDomain(d string) string {
// 	d = strings.TrimSpace(d)
// 	if d == "" || strings.HasPrefix(d, "#") {
// 		return ""
// 	}
// 	if !strings.HasSuffix(d, ".") {
// 		d += "."
// 	}
// 	return d
// }

// func parseQType(qStr string) uint16 {
// 	switch strings.ToUpper(strings.TrimSpace(qStr)) {
// 	case "AAAA":
// 		return dns.TypeAAAA
// 	case "CNAME":
// 		return dns.TypeCNAME
// 	case "NS":
// 		return dns.TypeNS
// 	default:
// 		return dns.TypeA
// 	}
// }
