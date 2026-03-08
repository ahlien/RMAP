/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package audit

import (
	"dns-analyzer/internal/model"
	"fmt"
	"strings"
)

// LameAuditor detects delegation failures and network unreachability issues.
type LameAuditor struct{}

// CNAMEAuditor ensures strict compliance with RFC standards regarding CNAME records.
type CNAMEAuditor struct{}

// SecurityAuditor flags potential security risks like private IP leaks and extracts EDEs.
type SecurityAuditor struct{}

// ProtocolAuditor identifies protocol anomalies such as redundant packets and NODATA anomalies.
type ProtocolAuditor struct{}

// DanglingAuditor detects Dangling DNS (NXDOMAIN) risks and split-brain resolution inconsistencies.
type DanglingAuditor struct{}

// ConsistencyAuditor is a reserved placeholder for future strict consistency checks.
type ConsistencyAuditor struct{}

// -----------------------------------------------------------------------------
// 1. Delegation & Response Anomalies (DELEGATION_ISSUE)
// -----------------------------------------------------------------------------

// Check inspects the graph for unreachable servers, SERVFAIL, and REFUSED statuses.
func (l *LameAuditor) Check(g *model.Graph, target string) []Issue {
	var servfailNodes []string
	var refusedNodes []string
	var networkErrNodes []string

	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)

		// Collect different types of anomalies independently
		if strings.Contains(n.Status, "NETWORK_ERROR") {
			networkErrNodes = append(networkErrNodes, n.ID)
		} else if n.Rcode == 2 { // SERVFAIL
			servfailNodes = append(servfailNodes, n.ID)
		} else if n.Rcode == 5 { // REFUSED
			refusedNodes = append(refusedNodes, n.ID)
		}
		return true
	})

	var issues []Issue
	// Output Network Errors independently
	if len(networkErrNodes) > 0 {
		issues = append(issues, Issue{
			Category: "DELEGATION_ISSUE",
			Type:     "NETWORK_UNREACHABLE",
			Severity: "CRITICAL",
			Message:  "Network Failure: Unable to connect to the authoritative server (timeout, connection reset, or packet loss).",
			NodeIDs:  networkErrNodes,
		})
	}
	// Output SERVFAIL independently
	if len(servfailNodes) > 0 {
		issues = append(issues, Issue{
			Category: "DELEGATION_ISSUE",
			Type:     "LAME_SERVFAIL",
			Severity: "CRITICAL",
			Message:  "Lame Delegation: Server returned SERVFAIL (typically due to upstream timeout or DNSSEC validation failure).",
			NodeIDs:  servfailNodes,
		})
	}
	// Output REFUSED independently
	if len(refusedNodes) > 0 {
		issues = append(issues, Issue{
			Category: "DELEGATION_ISSUE",
			Type:     "LAME_REFUSED",
			Severity: "CRITICAL",
			Message:  "Lame Delegation: Server returned REFUSED (the server refused to provide resolution for this domain).",
			NodeIDs:  refusedNodes,
		})
	}
	return issues
}

// -----------------------------------------------------------------------------
// 2. Protocol Violations (RFC_VIOLATION) - CNAME Specifics
// -----------------------------------------------------------------------------

// Check inspects the graph for RFC 1034 and RFC 1912 CNAME violations.
func (c *CNAMEAuditor) Check(g *model.Graph, target string) []Issue {
	var exclusivityNodes []string
	var toIPNodes []string
	var apexNodes []string

	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)
		if strings.Contains(n.Status, "[CNAME_EXCL]") {
			exclusivityNodes = append(exclusivityNodes, n.ID)
		}
		if strings.Contains(n.Status, "[CNAME_TO_IP]") {
			toIPNodes = append(toIPNodes, n.ID)
		}
		if strings.Contains(n.Status, "[CNAME_AT_APEX]") {
			apexNodes = append(apexNodes, n.ID)
		}
		return true
	})

	var issues []Issue
	if len(exclusivityNodes) > 0 {
		issues = append(issues, Issue{
			Category: "RFC_VIOLATION",
			Type:     "CNAME_EXCLUSIVITY_VIOLATION",
			Severity: "HIGH",
			Message:  "CNAME Violation: A CNAME record cannot co-exist with other record types on the same owner name (RFC 1034).",
			NodeIDs:  exclusivityNodes,
		})
	}
	if len(toIPNodes) > 0 {
		issues = append(issues, Issue{
			Category: "RFC_VIOLATION",
			Type:     "CNAME_TARGET_IS_IP",
			Severity: "HIGH",
			Message:  "CNAME Violation: The CNAME target field must be a domain name, not a direct IP address (RFC 1034).",
			NodeIDs:  toIPNodes,
		})
	}
	if len(apexNodes) > 0 {
		issues = append(issues, Issue{
			Category: "RFC_VIOLATION",
			Type:     "CNAME_AT_ZONE_APEX",
			Severity: "HIGH",
			Message:  "CNAME Violation: A CNAME record is not permitted at the Zone Apex (RFC 1912).",
			NodeIDs:  apexNodes,
		})
	}
	return issues
}

// -----------------------------------------------------------------------------
// 3. Protocol Anomalies (PROTOCOL_ANOMALY)
// -----------------------------------------------------------------------------

// Check evaluates the graph for redundant responses and raw NODATA occurrences.
func (p *ProtocolAuditor) Check(g *model.Graph, target string) []Issue {
	var dupNodes []string
	var noDataNodes []string

	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)

		// Check 1: Redundant/Duplicate records in the packet
		if strings.Contains(n.Status, "[DUP_RRS]") {
			dupNodes = append(dupNodes, n.ID)
		}

		// Check 2: Genuine NODATA anomalies based on raw packet content
		if strings.Contains(n.Status, "[NODATA_RAW]") {
			noDataNodes = append(noDataNodes, n.ID)
		}
		return true
	})

	var issues []Issue
	if len(dupNodes) > 0 {
		issues = append(issues, Issue{
			Category: "RFC_VIOLATION",
			Type:     "DUPLICATE_RESOURCE_RECORD",
			Severity: "LOW",
			Message:  "Redundant Response: The server returned completely duplicate resource records in the same section (RFC 2181).",
			NodeIDs:  dupNodes,
		})
	}
	if len(noDataNodes) > 0 {
		issues = append(issues, Issue{
			Category: "PROTOCOL_ANOMALY",
			Type:     "NODATA_RESPONSE",
			Severity: "MEDIUM",
			// Embed the affected node IDs directly into the message for easier triage
			Message: fmt.Sprintf("Empty Response: The following nodes returned NOERROR, but Answer/Authority/Additional sections are entirely empty: [%s]", strings.Join(noDataNodes, " | ")),
			NodeIDs: noDataNodes,
		})
	}
	return issues
}

// -----------------------------------------------------------------------------
// 4. General Security Risks (SECURITY_RISK)
// -----------------------------------------------------------------------------

// Check looks for explicit security vulnerabilities like internal IP leakage.
func (s *SecurityAuditor) Check(g *model.Graph, target string) []Issue {
	var privateNodes []string
	var edeNodes []string

	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)
		if strings.Contains(n.Status, "[PRIVATE_IP]") {
			privateNodes = append(privateNodes, n.ID)
		}
		if n.EDE != "" {
			edeNodes = append(edeNodes, n.ID)
		}
		return true
	})

	var issues []Issue
	if len(privateNodes) > 0 {
		issues = append(issues, Issue{
			Category: "SECURITY_RISK",
			Type:     "PRIVATE_IP_LEAKAGE",
			Severity: "MEDIUM",
			Message:  "Private IP Leakage: The public domain resolution returned a private/internal IP address (RFC 1918).",
			NodeIDs:  privateNodes,
		})
	}
	if len(edeNodes) > 0 {
		issues = append(issues, Issue{
			Category: "DIAGNOSTIC_INFO",
			Type:     "EXTENDED_DNS_ERROR",
			Severity: "INFO",
			Message:  "Diagnostic Info: The server attached an Extended DNS Error (EDE) code in the OPT record (RFC 8914).",
			NodeIDs:  edeNodes,
		})
	}
	return issues
}

// -----------------------------------------------------------------------------
// 5. Hijacking & Consistency Risks (Dangling NS / Split-Brain)
// -----------------------------------------------------------------------------

// Check identifies Dangling DNS risks and authoritative inconsistencies (Split-Brain).
func (d *DanglingAuditor) Check(g *model.Graph, target string) []Issue {
	var nxNodes []string
	var inconsistentNodes []string

	// Used to collect the IPs returned by each parent node (authoritative server) for the target domain
	// Structure: map[Domain]map[ParentNodeID][]IPs
	answerSets := make(map[string]map[string][]string)

	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)

		// Dedicated check for NXDOMAIN (RCODE 3)
		if n.Rcode == 3 {
			nxNodes = append(nxNodes, n.ID)
		}

		// Collect final resolution results
		if n.Status == "ANSWER_IP" {
			if answerSets[n.Domain] == nil {
				answerSets[n.Domain] = make(map[string][]string)
			}

			// Find the parent node that provided this ANSWER_IP
			parentID := "unknown"
			// 🌟 The probe is finished and the graph is read-only, so iterating over edges is safe here.
			for _, edge := range g.Edges {
				if edge.To == n.ID {
					parentID = edge.From
					break
				}
			}

			answerSets[n.Domain][parentID] = append(answerSets[n.Domain][parentID], n.IP)
		}
		return true
	})

	// 🌟 Deep verification for genuine resolution inconsistency (Split-Brain)
	for domain, parentMap := range answerSets {
		// If there is only 1 source or 0 sources, inconsistency is impossible
		if len(parentMap) <= 1 {
			continue
		}

		var firstSetFingerprint string
		var isFirst = true
		hasInconsistency := false

		// Store all related ANSWER_IP Node IDs for this domain
		var relatedNodes []string

		for parentID, ips := range parentMap {
			fingerprint := strings.Join(ips, ",")

			// Retrieve the NodeIDs corresponding to these IPs
			for _, ip := range ips {
				g.Nodes.Range(func(k, v any) bool {
					node := v.(*model.Node)
					if node.Status == "ANSWER_IP" && node.Domain == domain && node.IP == ip {
						for _, edge := range g.Edges {
							if edge.To == node.ID && edge.From == parentID {
								relatedNodes = append(relatedNodes, node.ID)
								break
							}
						}
					}
					return true
				})
			}

			if isFirst {
				firstSetFingerprint = fingerprint
				isFirst = false
			} else {
				// If the IP set returned by another authoritative server differs from the first one, it's inconsistent!
				if fingerprint != firstSetFingerprint {
					hasInconsistency = true
				}
			}
		}

		if hasInconsistency {
			inconsistentNodes = append(inconsistentNodes, relatedNodes...)
		}
	}

	// ------------------------------
	// Pack and return the Issues
	// ------------------------------
	var issues []Issue
	if len(nxNodes) > 0 {
		issues = append(issues, Issue{
			Category: "SECURITY_RISK",
			Type:     "NXDOMAIN_ABORT",
			Severity: "CRITICAL",
			Message:  "Resolution Aborted: The resolution chain ended with NXDOMAIN, indicating a potential dangling record or subdomain takeover risk.",
			NodeIDs:  nxNodes,
		})
	}
	if len(inconsistentNodes) > 0 {
		issues = append(issues, Issue{
			Category: "CONSISTENCY_ISSUE",
			Type:     "INCONSISTENT_ANSWERS",
			Severity: "HIGH",
			Message:  "Split-Brain Resolution: Different authoritative servers in the same zone returned entirely inconsistent IP sets for the same domain.",
			NodeIDs:  inconsistentNodes,
		})
	}
	return issues
}

// -----------------------------------------------------------------------------
// 6. Infrastructure Diversity Auditor (Geo & ASN)
// -----------------------------------------------------------------------------

// GeoAuditor evaluates the physical and logical redundancy of authoritative servers.
type GeoAuditor struct{}

// Check inspects the geographical and topological distribution of NS records.
func (g *GeoAuditor) Check(graph *model.Graph, target string) []Issue {
	// Storage structure: zone -> Attribute Type(AS/City) -> Attribute Value -> []NodeIDs
	// Used to compute the distribution of physical/logical properties under the same Zone.
	type ZoneInfo struct {
		ASNodes   map[string][]string
		CityNodes map[string][]string
		AllNodes  []string
	}
	zoneStats := make(map[string]*ZoneInfo)

	graph.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)
		// Exclude final answer nodes (ANS-); only audit NS nodes on the authoritative delegation path.
		if n.IP != "" && !strings.HasPrefix(n.ID, "ANS-") {
			zone := n.Domain
			if zoneStats[zone] == nil {
				zoneStats[zone] = &ZoneInfo{
					ASNodes:   make(map[string][]string),
					CityNodes: make(map[string][]string),
				}
			}

			// Record ASN distribution
			if n.ASName != "" {
				zoneStats[zone].ASNodes[n.ASName] = append(zoneStats[zone].ASNodes[n.ASName], n.ID)
			}
			// Record City distribution
			if n.City != "" {
				zoneStats[zone].CityNodes[n.City] = append(zoneStats[zone].CityNodes[n.City], n.ID)
			}
			zoneStats[zone].AllNodes = append(zoneStats[zone].AllNodes, n.ID)
		}
		return true
	})

	var issues []Issue
	for zone, info := range zoneStats {
		nodeCount := len(info.AllNodes)
		if nodeCount <= 1 {
			continue // A single NS naturally lacks redundancy; it is not considered "fake high-availability" here.
		}

		// 🌟 Logic A: AS-Level Single Point of Failure (SINGLE_AS_EXPOSURE)
		// Triggered if the user configured multiple NS nodes, but they all share the same ASN.
		if len(info.ASNodes) == 1 {
			for asName, nodes := range info.ASNodes {
				issues = append(issues, Issue{
					Category: "INFRA_RISK",
					Type:     "SINGLE_AS_EXPOSURE",
					Severity: "HIGH",
					Message:  fmt.Sprintf("Single-Point-of-Failure Risk: Zone [%s] configured %d NS nodes, but all are routed through the same ISP/ASN [%s], lacking logical network redundancy.", zone, nodeCount, asName),
					NodeIDs:  nodes,
				})
			}
		}

		// 🌟 Logic B: City-Level Single Point of Failure (SINGLE_CITY_EXPOSURE)
		// Triggered if multiple NS nodes exist (possibly cross-AS), but they are physically located in the same city.
		if len(info.CityNodes) == 1 {
			for cityName, nodes := range info.CityNodes {
				issues = append(issues, Issue{
					Category: "INFRA_RISK",
					Type:     "SINGLE_CITY_EXPOSURE",
					Severity: "MEDIUM",
					Message:  fmt.Sprintf("Geographic Concentration Risk: All NS nodes for Zone [%s] are physically located in [%s]. A regional disaster (e.g., earthquake, backbone fiber cut) will cause a complete resolution outage.", zone, cityName),
					NodeIDs:  nodes,
				})
			}
		}
	}
	return issues
}

// -----------------------------------------------------------------------------
// 7. Threat Intel Auditor (Malicious Hijacking & Infected Paths)
// -----------------------------------------------------------------------------

// ThreatAuditor correlates resolution paths with global threat intelligence IOCs.
type ThreatAuditor struct{}

// Check cross-references domains, IPs, CNAMEs, and NS records against the blacklists.
func (t *ThreatAuditor) Check(graph *model.Graph, target string) []Issue {
	infectedNSMap := make(map[string]bool)
	infectedCNAMEMap := make(map[string]bool)

	// Global read lock ensuring safe concurrent access to the IOCs dictionary
	threatLock.RLock()
	defer threatLock.RUnlock()

	// ==========================================
	// Route 1: Check node target domains and returned IPs
	// ==========================================
	graph.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)
		cleanDomain := strings.TrimSuffix(strings.ToLower(n.Domain), ".")

		// 🌟 Dual verification: The node's domain OR its IP hit the blacklist
		if threats[cleanDomain] || (n.IP != "" && threats[n.IP]) {
			n.IsThreat = true

			isCNAME := false
			for _, edge := range graph.Edges {
				if edge.To == n.ID && edge.Type == model.EdgeCnameDep {
					isCNAME = true
					break
				}
			}

			if isCNAME {
				infectedCNAMEMap[n.ID] = true
			} else {
				infectedNSMap[n.ID] = true
			}
		}
		return true
	})

	// ==========================================
	// Route 2: Check authoritative asset records (Uncover malicious backend NS)
	// ==========================================
	for _, nsRec := range graph.NSRecords {
		cleanNS := strings.TrimSuffix(strings.ToLower(nsRec.NSName), ".")

		// 🌟 Dual verification: Check the NS hostname and its associated Glue IP
		if threats[cleanNS] || (nsRec.IP != "" && threats[nsRec.IP]) {
			// Find out which nodes in the graph ended up relying on this infected NS
			graph.Nodes.Range(func(_, v any) bool {
				n := v.(*model.Node)
				// Match either by the requested IP or the targeted NS hostname
				if n.IP == nsRec.IP || strings.TrimSuffix(strings.ToLower(n.Domain), ".") == cleanNS {
					n.IsThreat = true
					infectedNSMap[n.ID] = true
				}
				return true
			})
		}
	}

	// ==========================================
	// Pack and return the Issues
	// ==========================================
	var issues []Issue

	if len(infectedCNAMEMap) > 0 {
		var nodes []string
		for k := range infectedCNAMEMap {
			nodes = append(nodes, k)
		}
		issues = append(issues, Issue{
			Category: "SECURITY_RISK",
			Type:     "MALICIOUS_CNAME_HIJACK",
			Severity: "CRITICAL",
			Message:  "Malicious CNAME Hijacking: A CNAME redirection occurred within the resolution chain where the target domain or IP is flagged in the threat intelligence blacklist.",
			NodeIDs:  nodes,
		})
	}

	if len(infectedNSMap) > 0 {
		var nodes []string
		for k := range infectedNSMap {
			nodes = append(nodes, k)
		}
		issues = append(issues, Issue{
			Category: "SECURITY_RISK",
			Type:     "INFECTED_DELEGATION_PATH",
			Severity: "CRITICAL",
			Message:  "Infected Delegation Path: An authoritative server (NS) hostname or its IP in the resolution path is blacklisted. Traffic is subject to an extreme risk of hijacking or eavesdropping.",
			NodeIDs:  nodes,
		})
	}

	return issues
}

// -----------------------------------------------------------------------------
// Core Orchestrator
// -----------------------------------------------------------------------------

// RunAllAudits aggregates and executes all registered audit rules sequentially.
func RunAllAudits(g *model.Graph, target string) []Issue {
	auditors := []Auditor{
		&LameAuditor{},
		&CNAMEAuditor{},
		&ProtocolAuditor{},
		&SecurityAuditor{},
		&DanglingAuditor{},
		&GeoAuditor{},
		&ThreatAuditor{},
	}

	var allIssues []Issue
	for _, a := range auditors {
		allIssues = append(allIssues, a.Check(g, target)...)
	}
	return allIssues
}

// package audit

// import (
// 	"dns-analyzer/internal/model"
// 	"fmt"
// 	"strings"
// )

// type LameAuditor struct{}
// type CNAMEAuditor struct{}
// type SecurityAuditor struct{}
// type ProtocolAuditor struct{}
// type DanglingAuditor struct{}
// type ConsistencyAuditor struct{}

// // 1. 委派与响应异常大类 (DELEGATION_ISSUE) - 彻底拆分
// func (l *LameAuditor) Check(g *model.Graph, target string) []Issue {
// 	var servfailNodes []string
// 	var refusedNodes []string
// 	var networkErrNodes []string

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)

// 		// 每一类异常单独收集
// 		if strings.Contains(n.Status, "NETWORK_ERROR") {
// 			networkErrNodes = append(networkErrNodes, n.ID)
// 		} else if n.Rcode == 2 { // SERVFAIL
// 			servfailNodes = append(servfailNodes, n.ID)
// 		} else if n.Rcode == 5 { // REFUSED
// 			refusedNodes = append(refusedNodes, n.ID)
// 		}
// 		return true
// 	})

// 	var issues []Issue
// 	// 网络层错误独立输出
// 	if len(networkErrNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "DELEGATION_ISSUE",
// 			Type:     "NETWORK_UNREACHABLE",
// 			Severity: "CRITICAL",
// 			Message:  "网络故障: 无法连接至该权威服务器 (超时、连接重置或包丢失)",
// 			NodeIDs:  networkErrNodes,
// 		})
// 	}
// 	// SERVFAIL 独立输出
// 	if len(servfailNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "DELEGATION_ISSUE",
// 			Type:     "LAME_SERVFAIL",
// 			Severity: "CRITICAL",
// 			Message:  "委派失效: 服务器返回 SERVFAIL (通常为上游查询超时或 DNSSEC 校验失败)",
// 			NodeIDs:  servfailNodes,
// 		})
// 	}
// 	// REFUSED 独立输出
// 	if len(refusedNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "DELEGATION_ISSUE",
// 			Type:     "LAME_REFUSED",
// 			Severity: "CRITICAL",
// 			Message:  "委派失效: 服务器返回 REFUSED (服务器拒绝为该域名提供解析服务)",
// 			NodeIDs:  refusedNodes,
// 		})
// 	}
// 	return issues
// }

// // 2. 协议违规大类 (RFC_VIOLATION) - CNAME 专项细分
// func (c *CNAMEAuditor) Check(g *model.Graph, target string) []Issue {
// 	var exclusivityNodes []string
// 	var toIPNodes []string
// 	var apexNodes []string

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)
// 		if strings.Contains(n.Status, "[CNAME_EXCL]") {
// 			exclusivityNodes = append(exclusivityNodes, n.ID)
// 		}
// 		if strings.Contains(n.Status, "[CNAME_TO_IP]") {
// 			toIPNodes = append(toIPNodes, n.ID)
// 		}
// 		if strings.Contains(n.Status, "[CNAME_AT_APEX]") {
// 			apexNodes = append(apexNodes, n.ID)
// 		}
// 		return true
// 	})

// 	var issues []Issue
// 	if len(exclusivityNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "RFC_VIOLATION",
// 			Type:     "CNAME_EXCLUSIVITY_VIOLATION",
// 			Severity: "HIGH",
// 			Message:  "CNAME 违规: 同一节点不允许同时存在 CNAME 和其他记录 (RFC 1034)",
// 			NodeIDs:  exclusivityNodes,
// 		})
// 	}
// 	if len(toIPNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "RFC_VIOLATION",
// 			Type:     "CNAME_TARGET_IS_IP",
// 			Severity: "HIGH",
// 			Message:  "CNAME 违规: CNAME 目标字段不能直接填写 IP 地址 (RFC 1034)",
// 			NodeIDs:  toIPNodes,
// 		})
// 	}
// 	if len(apexNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "RFC_VIOLATION",
// 			Type:     "CNAME_AT_ZONE_APEX",
// 			Severity: "HIGH",
// 			Message:  "CNAME 违规: 主域名 (Zone Apex) 不允许配置 CNAME (RFC 1912)",
// 			NodeIDs:  apexNodes,
// 		})
// 	}
// 	return issues
// }

// // 3. 协议违规与异常响应 (PROTOCOL_ANOMALY)
// func (p *ProtocolAuditor) Check(g *model.Graph, target string) []Issue {
// 	var dupNodes []string
// 	var noDataNodes []string

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)

// 		// 判定 1: 报文冗余
// 		if strings.Contains(n.Status, "[DUP_RRS]") {
// 			dupNodes = append(dupNodes, n.ID)
// 		}

// 		// 判定 2: 真正的 NoData 异常 (基于报文原始内容判断)
// 		if strings.Contains(n.Status, "[NODATA_RAW]") {
// 			noDataNodes = append(noDataNodes, n.ID)
// 		}
// 		return true
// 	})

// 	var issues []Issue
// 	if len(dupNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "RFC_VIOLATION",
// 			Type:     "DUPLICATE_RESOURCE_RECORD",
// 			Severity: "LOW",
// 			Message:  "报文冗余: 服务器返回了完全重复的资源记录 (RFC 2181)",
// 			NodeIDs:  dupNodes,
// 		})
// 	}
// 	if len(noDataNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "PROTOCOL_ANOMALY",
// 			Type:     "NODATA_RESPONSE",
// 			Severity: "MEDIUM",
// 			// 🌟 在 Message 中直接列出受影响的节点 ID
// 			Message: fmt.Sprintf("解析空响应: 以下节点返回 NOERROR 但 Answer/Authority/Additional 全空 (空节点): [%s]", strings.Join(noDataNodes, " | ")),
// 			NodeIDs: noDataNodes,
// 		})
// 	}
// 	return issues
// }

// // 4. 安全隐患大类 (SECURITY_RISK)
// func (s *SecurityAuditor) Check(g *model.Graph, target string) []Issue {
// 	var privateNodes []string
// 	var edeNodes []string

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)
// 		if strings.Contains(n.Status, "[PRIVATE_IP]") {
// 			privateNodes = append(privateNodes, n.ID)
// 		}
// 		if n.EDE != "" {
// 			edeNodes = append(edeNodes, n.ID)
// 		}
// 		return true
// 	})

// 	var issues []Issue
// 	if len(privateNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "SECURITY_RISK",
// 			Type:     "PRIVATE_IP_LEAKAGE",
// 			Severity: "MEDIUM",
// 			Message:  "内网泄露: 探测发现公网域名指向了私有 IP (RFC 1918)",
// 			NodeIDs:  privateNodes,
// 		})
// 	}
// 	if len(edeNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "DIAGNOSTIC_INFO",
// 			Type:     "EXTENDED_DNS_ERROR",
// 			Severity: "INFO",
// 			Message:  "诊断详情: 服务器返回了 EDE 扩展错误码 (RFC 8914)",
// 			NodeIDs:  edeNodes,
// 		})
// 	}
// 	return issues
// }

// // 5. 劫持与一致性风险
// func (d *DanglingAuditor) Check(g *model.Graph, target string) []Issue {
// 	var nxNodes []string
// 	var inconsistentNodes []string

// 	// 用于收集每个父节点(权威服务器)针对目标域名返回的 IP 列表
// 	// 结构: map[Domain]map[ParentNodeID][]IPs
// 	answerSets := make(map[string]map[string][]string)

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)

// 		// NXDOMAIN 专项
// 		if n.Rcode == 3 {
// 			nxNodes = append(nxNodes, n.ID)
// 		}

// 		// 收集解析结果
// 		if n.Status == "ANSWER_IP" {
// 			if answerSets[n.Domain] == nil {
// 				answerSets[n.Domain] = make(map[string][]string)
// 			}

// 			// 查找这个 ANSWER_IP 节点的父节点是谁
// 			parentID := "unknown"
// 			// 🌟 修复：探测已结束，数据处于静态只读状态，直接遍历，无需再调用 g.mu.Lock()
// 			for _, edge := range g.Edges {
// 				if edge.To == n.ID {
// 					parentID = edge.From
// 					break
// 				}
// 			}

// 			answerSets[n.Domain][parentID] = append(answerSets[n.Domain][parentID], n.IP)
// 		}
// 		return true
// 	})

// 	// 🌟 深度校验真正的解析不一致 (脑裂)
// 	for domain, parentMap := range answerSets {
// 		// 如果只有 1 个来源，或者 0 个来源，不存在不一致的问题
// 		if len(parentMap) <= 1 {
// 			continue
// 		}

// 		var firstSetFingerprint string
// 		var isFirst = true
// 		hasInconsistency := false

// 		// 存储这个域名下所有相关的 ANSWER_IP 节点 ID
// 		var relatedNodes []string

// 		for parentID, ips := range parentMap {
// 			fingerprint := strings.Join(ips, ",")

// 			// 找回这些 IP 对应的 NodeID
// 			for _, ip := range ips {
// 				g.Nodes.Range(func(k, v any) bool {
// 					node := v.(*model.Node)
// 					if node.Status == "ANSWER_IP" && node.Domain == domain && node.IP == ip {
// 						// 🌟 修复：同样移除这里的并发锁
// 						for _, edge := range g.Edges {
// 							if edge.To == node.ID && edge.From == parentID {
// 								relatedNodes = append(relatedNodes, node.ID)
// 								break
// 							}
// 						}
// 					}
// 					return true
// 				})
// 			}

// 			if isFirst {
// 				firstSetFingerprint = fingerprint
// 				isFirst = false
// 			} else {
// 				// 如果其它权威服务器返回的 IP 集合，和第一个服务器不同，判定为不一致！
// 				if fingerprint != firstSetFingerprint {
// 					hasInconsistency = true
// 				}
// 			}
// 		}

// 		if hasInconsistency {
// 			inconsistentNodes = append(inconsistentNodes, relatedNodes...)
// 		}
// 	}

// 	// ------------------------------
// 	// 打包 Issues 返回
// 	// ------------------------------
// 	var issues []Issue
// 	if len(nxNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "SECURITY_RISK",
// 			Type:     "NXDOMAIN_ABORT",
// 			Severity: "CRITICAL",
// 			Message:  "解析中断: 解析链以 NXDOMAIN 异常结束，存在悬挂记录或接管风险",
// 			NodeIDs:  nxNodes,
// 		})
// 	}
// 	if len(inconsistentNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "CONSISTENCY_ISSUE",
// 			Type:     "INCONSISTENT_ANSWERS",
// 			Severity: "HIGH",
// 			Message:  "解析脑裂: 不同权威服务器对同一域名返回了截然不同的 IP 集合",
// 			NodeIDs:  inconsistentNodes,
// 		})
// 	}
// 	return issues
// }

// // 6. 地理与单点故障审计 (Infrastructure Diversity Auditor)
// type GeoAuditor struct{}

// func (g *GeoAuditor) Check(graph *model.Graph, target string) []Issue {
// 	// 存储结构：zone -> 属性类型(AS/City) -> 属性值 -> []NodeIDs
// 	// 用于统计同一个 Zone 下不同物理/逻辑属性的分布情况
// 	type ZoneInfo struct {
// 		ASNodes   map[string][]string
// 		CityNodes map[string][]string
// 		AllNodes  []string
// 	}
// 	zoneStats := make(map[string]*ZoneInfo)

// 	graph.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)
// 		// 排除最终答案节点 (ANS-)，只审计权威委派路径上的 NS 节点
// 		if n.IP != "" && !strings.HasPrefix(n.ID, "ANS-") {
// 			zone := n.Domain
// 			if zoneStats[zone] == nil {
// 				zoneStats[zone] = &ZoneInfo{
// 					ASNodes:   make(map[string][]string),
// 					CityNodes: make(map[string][]string),
// 				}
// 			}

// 			// 记录 AS 分布
// 			if n.ASName != "" {
// 				zoneStats[zone].ASNodes[n.ASName] = append(zoneStats[zone].ASNodes[n.ASName], n.ID)
// 			}
// 			// 记录城市分布
// 			if n.City != "" {
// 				zoneStats[zone].CityNodes[n.City] = append(zoneStats[zone].CityNodes[n.City], n.ID)
// 			}
// 			zoneStats[zone].AllNodes = append(zoneStats[zone].AllNodes, n.ID)
// 		}
// 		return true
// 	})

// 	var issues []Issue
// 	for zone, info := range zoneStats {
// 		nodeCount := len(info.AllNodes)
// 		if nodeCount <= 1 {
// 			continue // 只有一个 NS 的情况不属于“虚假高可用”，本身就是单点
// 		}

// 		// 🌟 [修复] 逻辑 A：AS 级单点故障 (SINGLE_AS_EXPOSURE)
// 		// 如果该 Zone 下所有节点都在同一个 AS，但用户配了多个节点
// 		if len(info.ASNodes) == 1 {
// 			for asName, nodes := range info.ASNodes {
// 				issues = append(issues, Issue{
// 					Category: "INFRA_RISK",
// 					Type:     "SINGLE_AS_EXPOSURE",
// 					Severity: "HIGH",
// 					Message:  fmt.Sprintf("单点故障风险: 区域 [%s] 配置了 %d 个 NS，但全部位于同一运营商 [%s]，缺乏运营商级容灾能力。", zone, nodeCount, asName),
// 					NodeIDs:  nodes,
// 				})
// 			}
// 		}

// 		// 🌟 [新增] 逻辑 B：城市级单点故障 (SINGLE_CITY_EXPOSURE)
// 		// 如果运营商不同，但物理位置全在同一个城市
// 		if len(info.CityNodes) == 1 {
// 			for cityName, nodes := range info.CityNodes {
// 				issues = append(issues, Issue{
// 					Category: "INFRA_RISK",
// 					Type:     "SINGLE_CITY_EXPOSURE",
// 					Severity: "MEDIUM",
// 					Message:  fmt.Sprintf("地理集中风险: 区域 [%s] 的所有 NS 节点均物理位于 [%s]，若该地区发生灾难性断网（如地震、主干光缆事故），解析将彻底中断。", zone, cityName),
// 					NodeIDs:  nodes,
// 				})
// 			}
// 		}
// 	}
// 	return issues
// }

// // 7. 恶意链路审计 (Threat Intel Auditor)
// type ThreatAuditor struct{}

// func (t *ThreatAuditor) Check(graph *model.Graph, target string) []Issue {
// 	infectedNSMap := make(map[string]bool)
// 	infectedCNAMEMap := make(map[string]bool)

// 	// 全局读锁，确保安全访问 threats 黑名单字典 (包含恶意域名和恶意 IP)
// 	threatLock.RLock()
// 	defer threatLock.RUnlock()

// 	// ==========================================
// 	// 侦查路线 1：检查节点查询目标 Domain 和 返回的 IP
// 	// ==========================================
// 	graph.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)
// 		cleanDomain := strings.TrimSuffix(strings.ToLower(n.Domain), ".")

// 		// 🌟 双重校验：节点的域名命中了黑名单，或者节点的 IP 命中了黑名单
// 		if threats[cleanDomain] || (n.IP != "" && threats[n.IP]) {
// 			n.IsThreat = true

// 			isCNAME := false
// 			for _, edge := range graph.Edges {
// 				if edge.To == n.ID && edge.Type == model.EdgeCnameDep {
// 					isCNAME = true
// 					break
// 				}
// 			}

// 			if isCNAME {
// 				infectedCNAMEMap[n.ID] = true
// 			} else {
// 				infectedNSMap[n.ID] = true
// 			}
// 		}
// 		return true
// 	})

// 	// ==========================================
// 	// 侦查路线 2：检查权威资产记录 (挖掘幕后的恶意 NS 域名或恶意 NS IP)
// 	// ==========================================
// 	for _, nsRec := range graph.NSRecords {
// 		// 🌟 修复：使用你的准确字段名 NSName
// 		cleanNS := strings.TrimSuffix(strings.ToLower(nsRec.NSName), ".")

// 		// 🌟 双重校验：检查该 NS 的主机名，以及它的 Glue IP 是否在黑名单里
// 		if threats[cleanNS] || (nsRec.IP != "" && threats[nsRec.IP]) {
// 			// 找出到底是哪个倒霉的节点，用了这个被感染的 NS 服务器
// 			graph.Nodes.Range(func(_, v any) bool {
// 				n := v.(*model.Node)
// 				// 如果节点的请求目标 IP 是这个恶意 IP，或者查的就是这个恶意 NS 域名
// 				if n.IP == nsRec.IP || strings.TrimSuffix(strings.ToLower(n.Domain), ".") == cleanNS {
// 					n.IsThreat = true
// 					infectedNSMap[n.ID] = true
// 				}
// 				return true
// 			})
// 		}
// 	}

// 	// ==========================================
// 	// 打包审判结果
// 	// ==========================================
// 	var issues []Issue

// 	if len(infectedCNAMEMap) > 0 {
// 		var nodes []string
// 		for k := range infectedCNAMEMap {
// 			nodes = append(nodes, k)
// 		}
// 		issues = append(issues, Issue{
// 			Category: "SECURITY_RISK",
// 			Type:     "MALICIOUS_CNAME_HIJACK",
// 			Severity: "CRITICAL",
// 			Message:  "CNAME 劫持/恶意解析: 解析链中发生了 CNAME 跳转，且其目标域名或 IP 命中了威胁情报黑名单。",
// 			NodeIDs:  nodes,
// 		})
// 	}

// 	if len(infectedNSMap) > 0 {
// 		var nodes []string
// 		for k := range infectedNSMap {
// 			nodes = append(nodes, k)
// 		}
// 		issues = append(issues, Issue{
// 			Category: "SECURITY_RISK",
// 			Type:     "INFECTED_DELEGATION_PATH",
// 			Severity: "CRITICAL",
// 			Message:  "恶意委派路径: 解析链路中的权威服务器(NS)的主机名或 IP 命中了威胁情报黑名单，流量面临极高的劫持风险。",
// 			NodeIDs:  nodes,
// 		})
// 	}

// 	return issues
// }

// // RunAllAudits 聚合执行所有的审计规则
// func RunAllAudits(g *model.Graph, target string) []Issue {
// 	auditors := []Auditor{
// 		&LameAuditor{},
// 		&CNAMEAuditor{},
// 		&ProtocolAuditor{},
// 		&SecurityAuditor{},
// 		&DanglingAuditor{},
// 		&GeoAuditor{},
// 		&ThreatAuditor{},
// 	}

// 	var allIssues []Issue
// 	for _, a := range auditors {
// 		allIssues = append(allIssues, a.Check(g, target)...)
// 	}
// 	return allIssues
// }
