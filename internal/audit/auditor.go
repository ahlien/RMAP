/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package audit

import "dns-analyzer/internal/model"

// Issue aggregates a specific type of vulnerability, protocol violation,
// or infrastructure fault, along with all the nodes involved.
type Issue struct {
	Category string   `json:"category"` // High-level classification (e.g., SECURITY_RISK, RFC_VIOLATION)
	Type     string   `json:"type"`     // Specific vulnerability/fault type (e.g., LAME_SERVFAIL, SINGLE_AS_EXPOSURE)
	Severity string   `json:"severity"` // Risk level: CRITICAL, HIGH, MEDIUM, LOW, INFO
	Message  string   `json:"message"`  // Detailed description of the issue
	NodeIDs  []string `json:"node_ids"` // IDs of the nodes affected by or causing this specific issue
}

// Auditor defines the interface for all vulnerability and compliance checking modules.
// Each specific auditor (e.g., ThreatAuditor, GeoAuditor) implements this interface
// to evaluate the generated DNS dependency graph against specific rule sets.
type Auditor interface {
	// Check inspects the provided dependency graph for the target domain
	// and returns a list of identified Issues.
	Check(g *model.Graph, target string) []Issue
}

// // auditor.go
// package audit

// import "dns-analyzer/internal/model"

// // Issue 汇总一类特定的故障及其涉及的所有节点
// type Issue struct {
// 	Category string   `json:"category"` // 新增：一级大类 (如 SECURITY_RISK, RFC_VIOLATION)
// 	Type     string   `json:"type"`     // 二级小类：具体的故障类别 (如 LAME_SERVFAIL)
// 	Severity string   `json:"severity"` // 严重程度：CRITICAL, HIGH, MEDIUM, LOW, INFO
// 	Message  string   `json:"message"`  // 详细描述
// 	NodeIDs  []string `json:"node_ids"` // 出问题的节点集合
// }

// type Auditor interface {
// 	Check(g *model.Graph, target string) []Issue
// }
