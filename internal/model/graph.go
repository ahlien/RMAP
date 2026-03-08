/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Package model defines the core data structures used to represent
// the DNS resolution topology and security audit results.
package model

import (
	"sync"
)

// Edge types representing the relationships between DNS nodes.
const (
	EdgeReferral = "REFERRAL"  // Downward delegation to a child zone
	EdgeCnameDep = "CNAME_DEP" // Alias redirection to another domain
	EdgeNsDep    = "NS_DEP"    // Dependency on an NS record resolution (e.g., glueless delegations)
	EdgeAnswer   = "ANSWER"    // Final resolution to an A/AAAA record
)

// AnomalyDiagnosis encapsulates specific protocol violations and anomalies
// detected within a single DNS response.
type AnomalyDiagnosis struct {
	CNAMEExclusivityViolated  bool     `json:"cname_exclusivity_violated"`
	CNAMEPointsToIP           bool     `json:"cname_points_to_ip"`
	HasDuplicateAnswerRRs     bool     `json:"has_duplicate_answer_rrs"`
	HasDuplicateAuthorityRRs  bool     `json:"has_duplicate_authority_rrs"`
	HasDuplicateAdditionalRRs bool     `json:"has_duplicate_additional_rrs"`
	ReturnsPrivateIP          bool     `json:"returns_private_ip"`
	HasEDE                    bool     `json:"has_ede"`
	EDECodes                  []uint16 `json:"ede_codes,omitempty"`
	EDEMsgs                   []string `json:"ede_msgs,omitempty"`
}

// Node represents a single DNS probe state within the resolution graph.
type Node struct {
	ID        string   `json:"id"`
	IP        string   `json:"ip"`
	Domain    string   `json:"domain"`
	Type      uint16   `json:"type"`
	Status    string   `json:"status"`
	EDE       string   `json:"ede,omitempty"`
	EDECodes  []uint16 `json:"ede_codes,omitempty"` // Stores the numerical Extended DNS Error codes
	Flags     string   `json:"flags,omitempty"`
	Rcode     int      `json:"rcode"`
	MsgSize   int      `json:"msg_size"`
	OutDegree int      `json:"out_degree"`
	Role      string   `json:"role"`
	Depth     int      `json:"depth"`

	ASName   string `json:"as_name,omitempty"`   // Autonomous System Organization name
	City     string `json:"city,omitempty"`      // Geographic city location
	IsThreat bool   `json:"is_threat,omitempty"` // Indicates if the node triggered a Threat Intel blacklist
}

// Edge represents a directional dependency between two DNS Nodes.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// NSRecord stores infrastructure assets discovered during resolution.
type NSRecord struct {
	Zone   string `json:"zone"`
	NSName string `json:"ns_name"`
	IP     string `json:"ip"`
}

// ExportableGraph is a lock-free, serializable snapshot of the graph topology.
type ExportableGraph struct {
	Nodes     []Node     `json:"nodes"`
	Edges     []Edge     `json:"edges"`
	NSRecords []NSRecord `json:"ns_records"`
}

// Graph is a concurrency-safe directed graph storing the DNS resolution topology.
type Graph struct {
	Nodes     sync.Map   // Concurrent map storing all probed Nodes
	Edges     []Edge     // Slice storing all directional Edges
	NSRecords []NSRecord // Discovered NS infrastructure assets
	mu        sync.Mutex // Mutex protecting Edges and NSRecords arrays
}

// AddEdge safely injects a new directional edge into the graph.
func (g *Graph) AddEdge(from, to, etype string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Edges = append(g.Edges, Edge{From: from, To: to, Type: etype})
}

// AddNSRecord safely adds a newly discovered NS asset, avoiding duplicates.
func (g *Graph) AddNSRecord(zone, nsName, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Deduplication check
	for _, r := range g.NSRecords {
		if r.Zone == zone && r.NSName == nsName && r.IP == ip {
			return
		}
	}
	g.NSRecords = append(g.NSRecords, NSRecord{Zone: zone, NSName: nsName, IP: ip})
}

// Export creates a static, lock-free snapshot of the Graph, calculating
// the final topological roles (e.g., START, LEAF) for all nodes.
func (g *Graph) Export() ExportableGraph {
	g.mu.Lock()
	defer g.mu.Unlock()

	inDegreeMap := make(map[string]int)
	outDegreeMap := make(map[string]int)

	// Calculate in/out degrees to determine node topology roles
	for _, edge := range g.Edges {
		outDegreeMap[edge.From]++
		inDegreeMap[edge.To]++
	}

	res := ExportableGraph{
		Edges:     g.Edges,
		NSRecords: g.NSRecords,
		Nodes:     []Node{},
	}

	g.Nodes.Range(func(_, value interface{}) bool {
		if node, ok := value.(*Node); ok {
			node.OutDegree = outDegreeMap[node.ID]
			inDeg := inDegreeMap[node.ID]

			// Determine topological role
			if inDeg == 0 && node.OutDegree == 0 {
				node.Role = "START_LEAF"
			} else if inDeg == 0 {
				node.Role = "START"
			} else if node.OutDegree == 0 {
				node.Role = "LEAF"
			} else {
				node.Role = "INTERMEDIATE"
			}

			res.Nodes = append(res.Nodes, *node)
		}
		return true
	})

	return res
}

// package model

// import (
// 	"sync"
// )

// const (
// 	EdgeReferral = "REFERRAL"
// 	EdgeCnameDep = "CNAME_DEP"
// 	EdgeNsDep    = "NS_DEP"
// 	EdgeAnswer   = "ANSWER"
// )

// type AnomalyDiagnosis struct {
// 	CNAMEExclusivityViolated  bool     `json:"cname_exclusivity_violated"`
// 	CNAMEPointsToIP           bool     `json:"cname_points_to_ip"`
// 	HasDuplicateAnswerRRs     bool     `json:"has_duplicate_answer_rrs"`
// 	HasDuplicateAuthorityRRs  bool     `json:"has_duplicate_authority_rrs"`
// 	HasDuplicateAdditionalRRs bool     `json:"has_duplicate_additional_rrs"`
// 	ReturnsPrivateIP          bool     `json:"returns_private_ip"`
// 	HasEDE                    bool     `json:"has_ede"`
// 	EDECodes                  []uint16 `json:"ede_codes,omitempty"`
// 	EDEMsgs                   []string `json:"ede_msgs,omitempty"`
// }

// type Node struct {
// 	ID        string   `json:"id"`
// 	IP        string   `json:"ip"`
// 	Domain    string   `json:"domain"`
// 	Type      uint16   `json:"type"`
// 	Status    string   `json:"status"`
// 	EDE       string   `json:"ede,omitempty"`
// 	EDECodes  []uint16 `json:"ede_codes,omitempty"` // 🌟 修复报错：增加存储数字码的切片
// 	Flags     string   `json:"flags,omitempty"`
// 	Rcode     int      `json:"rcode"`
// 	MsgSize   int      `json:"msg_size"`
// 	OutDegree int      `json:"out_degree"`
// 	Role      string   `json:"role"`
// 	Depth     int      `json:"depth"`

// 	ASName   string `json:"as_name,omitempty"`   // 🌟 新增：自治系统名称
// 	City     string `json:"city,omitempty"`      // 🌟 新增：城市名称
// 	IsThreat bool   `json:"is_threat,omitempty"` // 🌟 新增：是否命中情报库
// }

// type Edge struct {
// 	From string `json:"from"`
// 	To   string `json:"to"`
// 	Type string `json:"type"`
// }

// type NSRecord struct {
// 	Zone   string `json:"zone"`
// 	NSName string `json:"ns_name"`
// 	IP     string `json:"ip"`
// }

// type ExportableGraph struct {
// 	Nodes     []Node     `json:"nodes"`
// 	Edges     []Edge     `json:"edges"`
// 	NSRecords []NSRecord `json:"ns_records"`
// }

// type Graph struct {
// 	Nodes     sync.Map
// 	Edges     []Edge
// 	NSRecords []NSRecord
// 	mu        sync.Mutex
// }

// func (g *Graph) AddEdge(from, to, etype string) {
// 	g.mu.Lock()
// 	defer g.mu.Unlock()
// 	g.Edges = append(g.Edges, Edge{From: from, To: to, Type: etype})
// }

// func (g *Graph) AddNSRecord(zone, nsName, ip string) {
// 	g.mu.Lock()
// 	defer g.mu.Unlock()
// 	for _, r := range g.NSRecords {
// 		if r.Zone == zone && r.NSName == nsName && r.IP == ip {
// 			return
// 		}
// 	}
// 	g.NSRecords = append(g.NSRecords, NSRecord{Zone: zone, NSName: nsName, IP: ip})
// }

// func (g *Graph) Export() ExportableGraph {
// 	g.mu.Lock()
// 	defer g.mu.Unlock()

// 	inDegreeMap := make(map[string]int)
// 	outDegreeMap := make(map[string]int)

// 	for _, edge := range g.Edges {
// 		outDegreeMap[edge.From]++
// 		inDegreeMap[edge.To]++
// 	}

// 	res := ExportableGraph{
// 		Edges:     g.Edges,
// 		NSRecords: g.NSRecords,
// 		Nodes:     []Node{},
// 	}

// 	g.Nodes.Range(func(_, value interface{}) bool {
// 		if node, ok := value.(*Node); ok {
// 			node.OutDegree = outDegreeMap[node.ID]
// 			inDeg := inDegreeMap[node.ID]

// 			if inDeg == 0 && node.OutDegree == 0 {
// 				node.Role = "START_LEAF"
// 			} else if inDeg == 0 {
// 				node.Role = "START"
// 			} else if node.OutDegree == 0 {
// 				node.Role = "LEAF"
// 			} else {
// 				node.Role = "INTERMEDIATE"
// 			}

// 			res.Nodes = append(res.Nodes, *node)
// 		}
// 		return true
// 	})
// 	return res
// }
