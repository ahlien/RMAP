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

// // Check identifies Dangling DNS risks and authoritative inconsistencies (Split-Brain).
// func (d *DanglingAuditor) Check(g *model.Graph, target string) []Issue {
// 	var nxNodes []string
// 	var inconsistentNodes []string

// 	// Used to collect the IPs returned by each parent node (authoritative server) for the target domain
// 	// Structure: map[Domain]map[ParentNodeID][]IPs
// 	answerSets := make(map[string]map[string][]string)

// 	g.Nodes.Range(func(_, v any) bool {
// 		n := v.(*model.Node)

// 		// Dedicated check for NXDOMAIN (RCODE 3)
// 		if n.Rcode == 3 {
// 			nxNodes = append(nxNodes, n.ID)
// 		}

// 		// Collect final resolution results
// 		if n.Status == "ANSWER_IP" {
// 			if answerSets[n.Domain] == nil {
// 				answerSets[n.Domain] = make(map[string][]string)
// 			}

// 			// Find the parent node that provided this ANSWER_IP
// 			parentID := "unknown"
// 			// 🌟 The probe is finished and the graph is read-only, so iterating over edges is safe here.
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

// 	// 🌟 Deep verification for genuine resolution inconsistency (Split-Brain)
// 	for domain, parentMap := range answerSets {
// 		// If there is only 1 source or 0 sources, inconsistency is impossible
// 		if len(parentMap) <= 1 {
// 			continue
// 		}

// 		var firstSetFingerprint string
// 		var isFirst = true
// 		hasInconsistency := false

// 		// Store all related ANSWER_IP Node IDs for this domain
// 		var relatedNodes []string

// 		for parentID, ips := range parentMap {
// 			fingerprint := strings.Join(ips, ",")

// 			// Retrieve the NodeIDs corresponding to these IPs
// 			for _, ip := range ips {
// 				g.Nodes.Range(func(k, v any) bool {
// 					node := v.(*model.Node)
// 					if node.Status == "ANSWER_IP" && node.Domain == domain && node.IP == ip {
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
// 				// If the IP set returned by another authoritative server differs from the first one, it's inconsistent!
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
// 	// Pack and return the Issues
// 	// ------------------------------
// 	var issues []Issue
// 	if len(nxNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "SECURITY_RISK",
// 			Type:     "NXDOMAIN_ABORT",
// 			Severity: "CRITICAL",
// 			Message:  "Resolution Aborted: The resolution chain ended with NXDOMAIN, indicating a potential dangling record or subdomain takeover risk.",
// 			NodeIDs:  nxNodes,
// 		})
// 	}
// 	if len(inconsistentNodes) > 0 {
// 		issues = append(issues, Issue{
// 			Category: "CONSISTENCY_ISSUE",
// 			Type:     "INCONSISTENT_ANSWERS",
// 			Severity: "HIGH",
// 			Message:  "Split-Brain Resolution: Different authoritative servers in the same zone returned entirely inconsistent IP sets for the same domain.",
// 			NodeIDs:  inconsistentNodes,
// 		})
// 	}
// 	return issues
// }

func (d *DanglingAuditor) Check(g *model.Graph, target string) []Issue {
	var nxNodes []string
	var inconsistentNodes []string

	answerSets := make(map[string]map[string][]string)

	// ==========================================
	// 🌟 Fix v2.0: Graph-based Upward Traceback (Upward BFS)
	// Accurately targets "dangling pointers" hidden deep within the resolution chain.
	// ==========================================

	// 1. Build a reverse graph mapping (child node -> set of parent edges) for efficient upward traceback.
	type incomingEdge struct {
		From string
		Type string
	}
	reverseGraph := make(map[string][]incomingEdge)
	for _, edge := range g.Edges {
		reverseGraph[edge.To] = append(reverseGraph[edge.To], incomingEdge{
			From: edge.From,
			Type: edge.Type,
		})
	}

	// 2. Collect all initial NXDOMAIN nodes (dead nodes).
	var initialNXNodes []string
	g.Nodes.Range(func(_, v any) bool {
		n := v.(*model.Node)
		if n.Rcode == 3 { // RCODE 3 represents NXDOMAIN
			initialNXNodes = append(initialNXNodes, n.ID)
		}

		// (Simultaneously collect final Answer IPs for subsequent Split-Brain analysis)
		if n.Status == "ANSWER_IP" {
			if answerSets[n.Domain] == nil {
				answerSets[n.Domain] = make(map[string][]string)
			}
			parentID := "unknown"
			for _, inEdge := range reverseGraph[n.ID] {
				parentID = inEdge.From
				break
			}
			answerSets[n.Domain][parentID] = append(answerSets[n.Domain][parentID], n.IP)
		}
		return true
	})

	// 3. Core logic: Execute Breadth-First Search (BFS) upwards starting from dead nodes.
	var vulnerableNodes []string // Records the vulnerable starting and ending points

	for _, nxNodeID := range initialNXNodes {
		// BFS queue and visited record (to prevent infinite loops/cycles)
		queue := []string{nxNodeID}
		visited := make(map[string]bool)
		visited[nxNodeID] = true

		for len(queue) > 0 {
			curr := queue[0]
			queue = queue[1:]

			// Inspect all parent edges pointing to the current node
			for _, inEdge := range reverseGraph[curr] {
				if inEdge.Type == model.EdgeCnameDep || inEdge.Type == model.EdgeNsDep {
					// 🚨 Caught it! Traced back to the exact CNAME or NS dependency that triggered this NXDOMAIN.
					// inEdge.From is the node configured with the dead CNAME/NS (the victim).
					// nxNodeID is the ultimate dead node (the takeover target).
					vulnerableNodes = append(vulnerableNodes, inEdge.From, nxNodeID)

					// Finding the direct misconfiguration point is enough; no need to trace further up this specific branch.
					continue
				} else {
					// If it's a standard REFERRAL edge, we are still in the normal recursive path.
					// Add the parent to the queue and continue tracing upwards.
					if !visited[inEdge.From] {
						visited[inEdge.From] = true
						queue = append(queue, inEdge.From)
					}
				}
			}
		}
	}

	// Deduplication (prevents multiple dead leaf nodes from the same CNAME chain being recorded repeatedly)
	nxNodes = uniqueStrings(vulnerableNodes)

	// ==========================================
	// 🌟 Deep verification for Split-Brain resolution (remains unchanged)
	// ==========================================
	for domain, parentMap := range answerSets {
		if len(parentMap) <= 1 {
			continue
		}

		var firstSetFingerprint string
		var isFirst = true
		hasInconsistency := false
		var relatedNodes []string

		for parentID, ips := range parentMap {
			fingerprint := strings.Join(ips, ",")
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
			Message:  "Dangling DNS Record: A CNAME or NS delegation points to an unregistered domain (NXDOMAIN), posing a critical Subdomain Takeover risk.",
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

// Helper function: Deduplicate string slice
func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
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
