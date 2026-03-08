/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package engine

import (
	"dns-analyzer/internal/audit"
	"dns-analyzer/internal/config"
	"dns-analyzer/internal/model"
	"dns-analyzer/internal/probe"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Engine is the core orchestrator for the DNS recursive resolution and graph-building process.
type Engine struct {
	Cfg   *config.Config
	Graph *model.Graph
	Pool  *model.RecordPool
	WG    sync.WaitGroup
	Limit chan struct{} // Concurrency limiter based on max_concurrency
}

// NewEngine initializes a new resolution engine with the specified configuration.
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		Cfg:   cfg,
		Graph: &model.Graph{},
		Pool:  &model.RecordPool{},
		Limit: make(chan struct{}, cfg.Engine.MaxConcurrency),
	}
}

// Run is the recursive entry point. It dispatches a DNS probe, parses the response,
// injects threat intelligence and GeoIP tags, evaluates basic compliance,
// and recursively spawns child jobs for CNAMEs or Referrals.
func (e *Engine) Run(parentID, edgeType, ip, domain string, qtype uint16, depth int) {
	// Prevent infinite loops or excessively deep resolution chains
	if depth > e.Cfg.Engine.MaxDepth {
		return
	}

	nodeID := fmt.Sprintf("%s-%s-%d", ip, domain, qtype)

	// Add the structural relationship (Edge) connecting the parent to this new probe
	if parentID != "" {
		e.Graph.AddEdge(parentID, nodeID, edgeType)
	}

	// Deduplication: If this exact query has already been dispatched/processed, return immediately.
	if _, loaded := e.Graph.Nodes.LoadOrStore(nodeID, &model.Node{ID: nodeID, Status: "PENDING"}); loaded {
		return
	}

	e.WG.Add(1)
	go func() {
		defer e.WG.Done()

		// Acquire concurrency token
		e.Limit <- struct{}{}
		defer func() { <-e.Limit }()

		// 1. Execute the underlying network probe
		res := probe.Execute(
			ip,
			domain,
			qtype,
			e.Cfg.Engine.NetworkEnv,
			e.Cfg.Engine.TimeoutMS,
			e.Cfg.Engine.Retries,
			e.Cfg.Engine.RetryDelay,
			e.Cfg.Engine.UDPBufferSize,
			e.Cfg.Engine.EnableCookie,
			e.Cfg.Engine.CookieValue,
		)

		node := &model.Node{
			ID:     nodeID,
			IP:     ip,
			Domain: domain,
			Type:   qtype,
			Depth:  depth,
		}

		// 🌟 [Feature] Threat Intelligence Enrichment: Check if the queried domain is blacklisted.
		cleanDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
		if audit.IsThreatDomain(cleanDomain) {
			node.IsThreat = true
		}

		// 🌟 [Feature] GeoIP Fingerprinting: Query ASN and City location for the target IP.
		if ip != "" {
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				node.ASName = audit.GetASN(parsedIP)
				node.City = audit.GetCity(parsedIP)
			}
		}

		// Handle network-level errors (e.g., dial timeout, i/o timeout)
		if res.Err != nil {
			node.Status = "NETWORK_ERROR"
			node.Rcode = -1
			e.Graph.Nodes.Store(nodeID, node)
			return
		}

		node.Rcode = res.Msg.Rcode
		node.MsgSize = res.Msg.Len()

		// Map numerical RCODEs to readable string representations
		if statusStr, ok := dns.RcodeToString[res.Msg.Rcode]; ok {
			node.Status = statusStr
		} else {
			node.Status = fmt.Sprintf("UNKNOWN_RCODE_%d", res.Msg.Rcode)
		}

		// 2. Extract DNS Header Flags
		var flags []string
		if res.Msg.Response {
			flags = append(flags, "qr")
		}
		if res.Msg.Authoritative {
			flags = append(flags, "aa")
		}
		if res.Msg.Truncated {
			flags = append(flags, "tc")
		}
		if res.Msg.RecursionDesired {
			flags = append(flags, "rd")
		}
		if res.Msg.RecursionAvailable {
			flags = append(flags, "ra")
		}
		if res.Msg.AuthenticatedData {
			flags = append(flags, "ad")
		}
		if res.Msg.CheckingDisabled {
			flags = append(flags, "cd")
		}
		node.Flags = strings.Join(flags, " ")

		// 3. Extract EDNS0 Extended DNS Errors (EDE)
		if opt := res.Msg.IsEdns0(); opt != nil {
			var edeList []string
			for _, option := range opt.Option {
				if ede, ok := option.(*dns.EDNS0_EDE); ok {
					node.EDECodes = append(node.EDECodes, ede.InfoCode)
					edeMsg := fmt.Sprintf("Code %d", ede.InfoCode)
					if ede.ExtraText != "" {
						edeMsg += fmt.Sprintf(":%s", ede.ExtraText)
					}
					edeList = append(edeList, edeMsg)
				}
			}
			if len(edeList) > 0 {
				node.EDE = strings.Join(edeList, " | ")
				node.Status = fmt.Sprintf("%s [EDE: %s]", node.Status, node.EDE)
			}
		}

		// 4. Extract and persist NS records (Infrastructure Discovery)
		e.extractAndStoreNS(res.Msg)

		// 5. Basic Node Compliance Diagnosis (Private IPs, CNAME violations, etc.)
		e.diagnoseNode(node, res.Msg)

		// 6. Commit the fully populated node back to the Graph
		e.Graph.Nodes.Store(nodeID, node)

		// 7. Recursive processing depending on response type
		if len(res.Msg.Answer) > 0 {
			e.processCNAMEs(nodeID, domain, res.Msg, qtype, depth)
		} else {
			e.processReferrals(nodeID, domain, res.Msg, qtype, depth)
		}
	}()
}

// extractAndStoreNS parses the Answer and Authority sections to extract NS delegations and their Glue IPs.
func (e *Engine) extractAndStoreNS(msg *dns.Msg) {
	helper := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if ns, ok := rr.(*dns.NS); ok {
				zone := ns.Header().Name
				nsName := ns.Ns
				foundIP := false

				// Look for Glue IPs in the Additional (Extra) section
				for _, extra := range msg.Extra {
					if strings.EqualFold(extra.Header().Name, nsName) {
						if a, isA := extra.(*dns.A); isA {
							e.Graph.AddNSRecord(zone, nsName, a.A.String())
							foundIP = true
						} else if aaaa, isAAAA := extra.(*dns.AAAA); isAAAA {
							e.Graph.AddNSRecord(zone, nsName, aaaa.AAAA.String())
							foundIP = true
						}
					}
				}
				if !foundIP {
					e.Graph.AddNSRecord(zone, nsName, "No Glue IP")
				}
			}
		}
	}
	helper(msg.Answer)
	helper(msg.Ns)
}

// diagnoseNode runs foundational RFC checks on the raw DNS message and appends violation tags to the node's Status.
func (e *Engine) diagnoseNode(node *model.Node, msg *dns.Msg) {
	// 1. Detect pure NODATA responses (NOERROR but all sections are empty)
	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
		if !strings.Contains(node.Status, "[NODATA_RAW]") {
			node.Status += " [NODATA_RAW]"
		}
	}

	// 🌟 Group Resource Records by their Owner Name for strict CNAME exclusivity checks
	rrTypesByName := make(map[string]map[uint16]bool)

	for _, rr := range msg.Answer {
		rrType := rr.Header().Rrtype
		rrName := strings.ToLower(rr.Header().Name) // Normalize for map keys

		if rrTypesByName[rrName] == nil {
			rrTypesByName[rrName] = make(map[uint16]bool)
		}
		rrTypesByName[rrName][rrType] = true

		// 2. Check for Private IP Leakage
		var ipStr string
		if a, ok := rr.(*dns.A); ok {
			ipStr = a.A.String()
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			ipStr = aaaa.AAAA.String()
		}

		if ipStr != "" {
			parsedIP := net.ParseIP(ipStr)
			if parsedIP != nil && (parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()) {
				if !strings.Contains(node.Status, "[PRIVATE_IP]") {
					node.Status += " [PRIVATE_IP]"
				}
			}
		}

		// 3. Check for Zone Apex CNAME Violation
		// (Ensures the queried domain exactly matches the CNAME owner name to avoid false positives on subdomains)
		if rrType == dns.TypeCNAME {
			if node.Depth <= 1 && strings.EqualFold(rrName, strings.ToLower(node.Domain)) {
				if !strings.Contains(node.Status, "[CNAME_AT_APEX]") {
					node.Status += " [CNAME_AT_APEX]"
				}
			}
		}
	}

	// 🌟 4. Strict CNAME Exclusivity Verification
	for _, types := range rrTypesByName {
		if types[dns.TypeCNAME] {
			hasOther := false
			for t := range types {
				// Exclude CNAME itself, and legally co-existing DNSSEC records
				if t != dns.TypeCNAME && t != dns.TypeRRSIG && t != dns.TypeNSEC && t != dns.TypeNSEC3 {
					hasOther = true
					break
				}
			}
			// If a CNAME co-exists with an incompatible record type, flag the violation
			if hasOther {
				if !strings.Contains(node.Status, "[CNAME_EXCL]") {
					node.Status += " [CNAME_EXCL]"
				}
				break // Mark the node as tainted and exit the loop
			}
		}
	}

	// 5. Check for redundant/duplicate resource records
	if hasDuplicateRRs(msg.Answer) || hasDuplicateRRs(msg.Ns) {
		if !strings.Contains(node.Status, "[DUP_RRS]") {
			node.Status += " [DUP_RRS]"
		}
	}
}

// hasDuplicateRRs detects if a slice of Resource Records contains exact string duplicates.
func hasDuplicateRRs(rrs []dns.RR) bool {
	seen := make(map[string]bool)
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue // Exclude EDNS0 OPT records from duplication checks
		}
		if seen[rr.String()] {
			return true
		}
		seen[rr.String()] = true
	}
	return false
}

// processCNAMEs handles the Answer section. If final IPs are found, it terminates the chain.
// If a CNAME is found, it spawns a new resolution task starting from the Root Servers.
func (e *Engine) processCNAMEs(nodeID, domain string, msg *dns.Msg, qtype uint16, depth int) {
	hasFinalAnswer := false
	var finalIPs []string

	for _, rr := range msg.Answer {
		if a, ok := rr.(*dns.A); ok {
			finalIPs = append(finalIPs, a.A.String())
			hasFinalAnswer = true
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			finalIPs = append(finalIPs, aaaa.AAAA.String())
			hasFinalAnswer = true
		}
	}

	// If a final A/AAAA record is reached, mark as success and terminate this branch.
	if hasFinalAnswer {
		for _, ip := range finalIPs {
			leafID := fmt.Sprintf("ANS-%s-%s-%d", ip, domain, qtype)
			e.Graph.AddEdge(nodeID, leafID, model.EdgeAnswer)
			e.Graph.Nodes.LoadOrStore(leafID, &model.Node{
				ID: leafID, IP: ip, Domain: domain, Type: qtype, Status: "ANSWER_IP", Rcode: 0, Depth: depth + 1,
			})
		}
		return
	}

	// Chase CNAME chains cross-zone by restarting resolution from the Root Servers
	for _, rr := range msg.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			e.Run(nodeID, model.EdgeCnameDep, e.getRootIP(), cn.Target, qtype, depth+1)
		}
	}
}

// processReferrals handles downward delegation by extracting NS records and their Glue IPs.
// It also intelligently handles missing Glue scenarios.
func (e *Engine) processReferrals(nodeID, domain string, msg *dns.Msg, qtype uint16, depth int) {
	var fallbackTypes []uint16
	switch e.Cfg.Engine.NetworkEnv {
	case config.EnvIPv4:
		fallbackTypes = []uint16{dns.TypeA}
	case config.EnvIPv6:
		fallbackTypes = []uint16{dns.TypeAAAA}
	case config.EnvDual:
		fallbackTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	default:
		fallbackTypes = []uint16{dns.TypeA}
	}

	seenNS := make(map[string]bool)
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			nsDomain := ns.Ns
			if seenNS[nsDomain] {
				continue
			}
			seenNS[nsDomain] = true

			ips := extractGlueIPs(msg, nsDomain)

			// Handle Glueless Delegations (Missing Glue IPs)
			// Spawn a sub-query from the Root Servers to actively resolve the NS hostname.
			if len(ips) == 0 {
				for _, t := range fallbackTypes {
					e.Run(nodeID, model.EdgeNsDep, e.getRootIP(), nsDomain, t, depth+1)
				}
			} else {
				// Follow the delegation using the provided Glue IPs, respecting the IP stack environment.
				for _, ip := range ips {
					isV6 := strings.Contains(ip, ":")
					if (e.Cfg.Engine.NetworkEnv == config.EnvIPv4 && !isV6) ||
						(e.Cfg.Engine.NetworkEnv == config.EnvIPv6 && isV6) ||
						e.Cfg.Engine.NetworkEnv == config.EnvDual {
						e.Run(nodeID, model.EdgeReferral, ip, domain, qtype, depth+1)
					}
				}
			}
		}
	}
}

// getRootIP returns the appropriate root server IP based on the configured network environment.
func (e *Engine) getRootIP() string {
	if e.Cfg.Engine.NetworkEnv == config.EnvIPv6 {
		return e.Cfg.Bootstrap.RootServers[0].IPv6
	}
	return e.Cfg.Bootstrap.RootServers[0].IPv4
}

// package engine

// import (
// 	"dns-analyzer/internal/audit" // 🌟 引入审计模块以访问外部数据加载器
// 	"dns-analyzer/internal/config"
// 	"dns-analyzer/internal/model"
// 	"dns-analyzer/internal/probe"
// 	"fmt"
// 	"net"
// 	"strings"
// 	"sync"

// 	"github.com/miekg/dns"
// )

// type Engine struct {
// 	Cfg   *config.Config
// 	Graph *model.Graph
// 	Pool  *model.RecordPool
// 	WG    sync.WaitGroup
// 	Limit chan struct{}
// }

// func NewEngine(cfg *config.Config) *Engine {
// 	return &Engine{
// 		Cfg:   cfg,
// 		Graph: &model.Graph{},
// 		Pool:  &model.RecordPool{},
// 		Limit: make(chan struct{}, cfg.Engine.MaxConcurrency),
// 	}
// }

// func (e *Engine) Run(parentID, edgeType, ip, domain string, qtype uint16, depth int) {
// 	if depth > e.Cfg.Engine.MaxDepth {
// 		return
// 	}

// 	nodeID := fmt.Sprintf("%s-%s-%d", ip, domain, qtype)

// 	if parentID != "" {
// 		e.Graph.AddEdge(parentID, nodeID, edgeType)
// 	}

// 	if _, loaded := e.Graph.Nodes.LoadOrStore(nodeID, &model.Node{ID: nodeID, Status: "PENDING"}); loaded {
// 		return
// 	}

// 	e.WG.Add(1)
// 	go func() {
// 		defer e.WG.Done()

// 		e.Limit <- struct{}{}
// 		defer func() { <-e.Limit }()

// 		// 1. 调用底层探测引擎执行发包
// 		res := probe.Execute(
// 			ip,
// 			domain,
// 			qtype,
// 			e.Cfg.Engine.NetworkEnv,
// 			e.Cfg.Engine.TimeoutMS,
// 			e.Cfg.Engine.Retries,
// 			e.Cfg.Engine.RetryDelay,
// 			e.Cfg.Engine.UDPBufferSize,
// 			e.Cfg.Engine.EnableCookie,
// 			e.Cfg.Engine.CookieValue,
// 		)

// 		node := &model.Node{
// 			ID:     nodeID,
// 			IP:     ip,
// 			Domain: domain,
// 			Type:   qtype,
// 			Depth:  depth,
// 		}

// 		// 🌟 [新增] 威胁情报检测：检查当前探测的域名是否在黑名单中
// 		cleanDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
// 		if audit.IsThreatDomain(cleanDomain) {
// 			node.IsThreat = true
// 		}

// 		// 🌟 [新增] GeoIP 属性画像：查询 IP 的 ASN 和 城市信息
// 		if ip != "" {
// 			parsedIP := net.ParseIP(ip)
// 			if parsedIP != nil {
// 				node.ASName = audit.GetASN(parsedIP)
// 				node.City = audit.GetCity(parsedIP)
// 			}
// 		}

// 		if res.Err != nil {
// 			node.Status = "NETWORK_ERROR"
// 			node.Rcode = -1
// 			e.Graph.Nodes.Store(nodeID, node)
// 			return
// 		}

// 		node.Rcode = res.Msg.Rcode
// 		node.MsgSize = res.Msg.Len()

// 		if statusStr, ok := dns.RcodeToString[res.Msg.Rcode]; ok {
// 			node.Status = statusStr
// 		} else {
// 			node.Status = fmt.Sprintf("UNKNOWN_RCODE_%d", res.Msg.Rcode)
// 		}

// 		// 2. 提取 DNS 头部 Flags
// 		var flags []string
// 		if res.Msg.Response {
// 			flags = append(flags, "qr")
// 		}
// 		if res.Msg.Authoritative {
// 			flags = append(flags, "aa")
// 		}
// 		if res.Msg.Truncated {
// 			flags = append(flags, "tc")
// 		}
// 		if res.Msg.RecursionDesired {
// 			flags = append(flags, "rd")
// 		}
// 		if res.Msg.RecursionAvailable {
// 			flags = append(flags, "ra")
// 		}
// 		if res.Msg.AuthenticatedData {
// 			flags = append(flags, "ad")
// 		}
// 		if res.Msg.CheckingDisabled {
// 			flags = append(flags, "cd")
// 		}
// 		node.Flags = strings.Join(flags, " ")

// 		// 3. 提取 EDNS0 扩展错误 (EDE)
// 		if opt := res.Msg.IsEdns0(); opt != nil {
// 			var edeList []string
// 			for _, option := range opt.Option {
// 				if ede, ok := option.(*dns.EDNS0_EDE); ok {
// 					node.EDECodes = append(node.EDECodes, ede.InfoCode)
// 					edeMsg := fmt.Sprintf("Code %d", ede.InfoCode)
// 					if ede.ExtraText != "" {
// 						edeMsg += fmt.Sprintf(":%s", ede.ExtraText)
// 					}
// 					edeList = append(edeList, edeMsg)
// 				}
// 			}
// 			if len(edeList) > 0 {
// 				node.EDE = strings.Join(edeList, " | ")
// 				node.Status = fmt.Sprintf("%s [EDE: %s]", node.Status, node.EDE)
// 			}
// 		}

// 		// 4. 提取并持久化 NS 记录 (资产发现)
// 		e.extractAndStoreNS(res.Msg)

// 		// 5. 节点合规性诊断 (私有IP、CNAME违规等)
// 		e.diagnoseNode(node, res.Msg)

// 		// 6. 存储完善后的节点
// 		e.Graph.Nodes.Store(nodeID, node)

// 		// 7. 递归递归处理 Answer (CNAME) 或 Authority (Referral)
// 		if len(res.Msg.Answer) > 0 {
// 			e.processCNAMEs(nodeID, domain, res.Msg, qtype, depth)
// 		} else {
// 			e.processReferrals(nodeID, domain, res.Msg, qtype, depth)
// 		}
// 	}()
// }

// // 辅助：提取 NS 并存入 Graph
// func (e *Engine) extractAndStoreNS(msg *dns.Msg) {
// 	helper := func(rrs []dns.RR) {
// 		for _, rr := range rrs {
// 			if ns, ok := rr.(*dns.NS); ok {
// 				zone := ns.Header().Name
// 				nsName := ns.Ns
// 				foundIP := false
// 				for _, extra := range msg.Extra {
// 					if strings.EqualFold(extra.Header().Name, nsName) {
// 						if a, isA := extra.(*dns.A); isA {
// 							e.Graph.AddNSRecord(zone, nsName, a.A.String())
// 							foundIP = true
// 						} else if aaaa, isAAAA := extra.(*dns.AAAA); isAAAA {
// 							e.Graph.AddNSRecord(zone, nsName, aaaa.AAAA.String())
// 							foundIP = true
// 						}
// 					}
// 				}
// 				if !foundIP {
// 					e.Graph.AddNSRecord(zone, nsName, "无 Glue IP")
// 				}
// 			}
// 		}
// 	}
// 	helper(msg.Answer)
// 	helper(msg.Ns)
// }

// func (e *Engine) diagnoseNode(node *model.Node, msg *dns.Msg) {
// 	// 1. NoData 判定
// 	if msg.Rcode == dns.RcodeSuccess && len(msg.Answer) == 0 && len(msg.Ns) == 0 && len(msg.Extra) == 0 {
// 		if !strings.Contains(node.Status, "[NODATA_RAW]") {
// 			node.Status += " [NODATA_RAW]"
// 		}
// 	}

// 	// 🌟 核心修复：按资源记录的主机名 (Owner Name) 进行分组
// 	rrTypesByName := make(map[string]map[uint16]bool)

// 	for _, rr := range msg.Answer {
// 		rrType := rr.Header().Rrtype
// 		// 标准化域名，方便作为 map 的 key
// 		rrName := strings.ToLower(rr.Header().Name)

// 		if rrTypesByName[rrName] == nil {
// 			rrTypesByName[rrName] = make(map[uint16]bool)
// 		}
// 		rrTypesByName[rrName][rrType] = true

// 		// 2. 检查私有 IP 泄露
// 		var ipStr string
// 		if a, ok := rr.(*dns.A); ok {
// 			ipStr = a.A.String()
// 		} else if aaaa, ok := rr.(*dns.AAAA); ok {
// 			ipStr = aaaa.AAAA.String()
// 		}

// 		if ipStr != "" {
// 			parsedIP := net.ParseIP(ipStr)
// 			if parsedIP != nil && (parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()) {
// 				if !strings.Contains(node.Status, "[PRIVATE_IP]") {
// 					node.Status += " [PRIVATE_IP]"
// 				}
// 			}
// 		}

// 		// 3. 检查 Zone Apex 违规 (增加了域名对比，防止误判子域的 CNAME)
// 		if rrType == dns.TypeCNAME {
// 			if node.Depth <= 1 && strings.EqualFold(rrName, strings.ToLower(node.Domain)) {
// 				if !strings.Contains(node.Status, "[CNAME_AT_APEX]") {
// 					node.Status += " [CNAME_AT_APEX]"
// 				}
// 			}
// 		}
// 	}

// 	// 🌟 4. 精准判定 CNAME 排他性违规 (基于相同的 Owner Name)
// 	for _, types := range rrTypesByName {
// 		// 如果这个特定域名配置了 CNAME
// 		if types[dns.TypeCNAME] {
// 			hasOther := false
// 			for t := range types {
// 				// 排除 CNAME 自身，以及 DNSSEC 相关的合法共存记录 (RRSIG, NSEC, NSEC3)
// 				if t != dns.TypeCNAME && t != dns.TypeRRSIG && t != dns.TypeNSEC && t != dns.TypeNSEC3 {
// 					hasOther = true
// 					break
// 				}
// 			}
// 			// 只有同一个域名既有 CNAME 又有别的记录时，才打违规标签！
// 			if hasOther {
// 				if !strings.Contains(node.Status, "[CNAME_EXCL]") {
// 					node.Status += " [CNAME_EXCL]"
// 				}
// 				break // 只要发现一组违规，节点就脏了，直接跳出
// 			}
// 		}
// 	}

// 	// 5. 检查记录重复
// 	if hasDuplicateRRs(msg.Answer) || hasDuplicateRRs(msg.Ns) {
// 		if !strings.Contains(node.Status, "[DUP_RRS]") {
// 			node.Status += " [DUP_RRS]"
// 		}
// 	}
// }

// func hasDuplicateRRs(rrs []dns.RR) bool {
// 	seen := make(map[string]bool)
// 	for _, rr := range rrs {
// 		if rr.Header().Rrtype == dns.TypeOPT {
// 			continue
// 		}
// 		if seen[rr.String()] {
// 			return true
// 		}
// 		seen[rr.String()] = true
// 	}
// 	return false
// }

// func (e *Engine) processCNAMEs(nodeID, domain string, msg *dns.Msg, qtype uint16, depth int) {
// 	hasFinalAnswer := false
// 	var finalIPs []string

// 	for _, rr := range msg.Answer {
// 		if a, ok := rr.(*dns.A); ok {
// 			finalIPs = append(finalIPs, a.A.String())
// 			hasFinalAnswer = true
// 		} else if aaaa, ok := rr.(*dns.AAAA); ok {
// 			finalIPs = append(finalIPs, aaaa.AAAA.String())
// 			hasFinalAnswer = true
// 		}
// 	}

// 	if hasFinalAnswer {
// 		for _, ip := range finalIPs {
// 			leafID := fmt.Sprintf("ANS-%s-%s-%d", ip, domain, qtype)
// 			e.Graph.AddEdge(nodeID, leafID, model.EdgeAnswer)
// 			e.Graph.Nodes.LoadOrStore(leafID, &model.Node{
// 				ID: leafID, IP: ip, Domain: domain, Type: qtype, Status: "ANSWER_IP", Rcode: 0, Depth: depth + 1,
// 			})
// 		}
// 		return
// 	}

// 	for _, rr := range msg.Answer {
// 		if cn, ok := rr.(*dns.CNAME); ok {
// 			e.Run(nodeID, model.EdgeCnameDep, e.getRootIP(), cn.Target, qtype, depth+1)
// 		}
// 	}
// }

// func (e *Engine) processReferrals(nodeID, domain string, msg *dns.Msg, qtype uint16, depth int) {
// 	var fallbackTypes []uint16
// 	switch e.Cfg.Engine.NetworkEnv {
// 	case config.EnvIPv4:
// 		fallbackTypes = []uint16{dns.TypeA}
// 	case config.EnvIPv6:
// 		fallbackTypes = []uint16{dns.TypeAAAA}
// 	case config.EnvDual:
// 		fallbackTypes = []uint16{dns.TypeA, dns.TypeAAAA}
// 	default:
// 		fallbackTypes = []uint16{dns.TypeA}
// 	}

// 	seenNS := make(map[string]bool)
// 	for _, rr := range msg.Ns {
// 		if ns, ok := rr.(*dns.NS); ok {
// 			nsDomain := ns.Ns
// 			if seenNS[nsDomain] {
// 				continue
// 			}
// 			seenNS[nsDomain] = true

// 			ips := extractGlueIPs(msg, nsDomain)
// 			if len(ips) == 0 {
// 				for _, t := range fallbackTypes {
// 					e.Run(nodeID, model.EdgeNsDep, e.getRootIP(), nsDomain, t, depth+1)
// 				}
// 			} else {
// 				for _, ip := range ips {
// 					isV6 := strings.Contains(ip, ":")
// 					if (e.Cfg.Engine.NetworkEnv == config.EnvIPv4 && !isV6) ||
// 						(e.Cfg.Engine.NetworkEnv == config.EnvIPv6 && isV6) ||
// 						e.Cfg.Engine.NetworkEnv == config.EnvDual {
// 						e.Run(nodeID, model.EdgeReferral, ip, domain, qtype, depth+1)
// 					}
// 				}
// 			}
// 		}
// 	}
// }

// func (e *Engine) getRootIP() string {
// 	if e.Cfg.Engine.NetworkEnv == config.EnvIPv6 {
// 		return e.Cfg.Bootstrap.RootServers[0].IPv6
// 	}
// 	return e.Cfg.Bootstrap.RootServers[0].IPv4
// }
