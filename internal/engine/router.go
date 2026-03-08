/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package engine

import (
	"strings"

	"github.com/miekg/dns"
)

// extractGlueIPs indiscriminately extracts all A and AAAA records (Glue IPs)
// from the Additional section of a DNS message that match the given NS hostname.
// Note: It intentionally ignores the network environment (IPv4/IPv6) at this stage;
// all matching IPs are extracted and delegated to the upper-level caller for filtering.
func extractGlueIPs(msg *dns.Msg, nsName string) []string {
	var ips []string

	for _, extra := range msg.Extra {
		// 1. Prioritize name validation (case-insensitive) to prevent missing
		//    records due to inconsistent casing in upstream DNS responses.
		if !strings.EqualFold(extra.Header().Name, nsName) {
			continue
		}

		// 2. Extract all A and AAAA records indiscriminately.
		if a, ok := extra.(*dns.A); ok {
			ips = append(ips, a.A.String())
		} else if aaaa, ok := extra.(*dns.AAAA); ok {
			ips = append(ips, aaaa.AAAA.String())
		}
	}

	return ips
}

// package engine

// import (
// 	"strings"

// 	"github.com/miekg/dns"
// )

// // extractGlueIPs 无差别提取 Additional 段中所有的 A 和 AAAA 记录 (忽略大小写匹配)
// // 注意：这里已经去掉了 env 参数，提取所有记录，交由上层逻辑独立判断
// func extractGlueIPs(msg *dns.Msg, nsName string) []string {
// 	var ips []string

// 	for _, extra := range msg.Extra {
// 		// 1. 优先校验名称，忽略大小写 (避免 DNS 响应大小写不一致导致漏抓)
// 		if !strings.EqualFold(extra.Header().Name, nsName) {
// 			continue
// 		}

// 		// 2. 无差别提取所有的 A 和 AAAA
// 		if a, ok := extra.(*dns.A); ok {
// 			ips = append(ips, a.A.String())
// 		} else if aaaa, ok := extra.(*dns.AAAA); ok {
// 			ips = append(ips, aaaa.AAAA.String())
// 		}
// 	}

// 	return ips
// }
