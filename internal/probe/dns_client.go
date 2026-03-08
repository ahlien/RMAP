/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

package probe

import (
	"crypto/rand"
	"dns-analyzer/internal/config"
	"encoding/hex"
	mrand "math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Result encapsulates the outcome of a single DNS probe attempt.
type Result struct {
	Msg     *dns.Msg
	Latency time.Duration
	Err     error
}

func init() {
	// Initialize the math/rand seed for jittered retry delays
	mrand.Seed(time.Now().UnixNano())
}

/*
=============================================================================
🛠️ Probe Engine Query Fingerprint
The DNS query message constructed and sent by this function, when Cookie is enabled
and BufSize is 1232, is structurally equivalent to the output of the following dig command:

$ dig @{ip} {domain} {qtype} +norecurse +bufsize=1232 +cookie

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: ; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;;       ^
;;       └─ Note the deliberate absence of the 'rd' (Recursion Desired) flag,
;;          forcing a strict, single-tier authoritative probe.

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
; COOKIE: a1b2c3d4e5f6g7h8 (client)  <-- Injected dynamically if enable_cookie is true
;; QUESTION SECTION:
;{domain}.                     IN      {qtype}
=============================================================================
*/

// Execute dispatches a highly resilient DNS probe.
// Core Features: UDP probing, EDNS0 buffer tuning, DNS Cookie injection (RFC 7873),
// packet loss retransmission, randomized jitter delays, and automatic TCP fallback.
func Execute(ip, domain string, qtype uint16, env config.NetworkEnv, timeout, retries int, retryDelay string, bufSize uint16, enableCookie bool, cookieValue string) *Result {
	// 1. Select the underlying network protocol stack
	network := "udp"
	tcpNetwork := "tcp"
	if env == config.EnvIPv4 {
		network = "udp4"
		tcpNetwork = "tcp4"
	} else if env == config.EnvIPv6 {
		network = "udp6"
		tcpNetwork = "tcp6"
	}

	client := dns.Client{
		Net:     network,
		Timeout: time.Duration(timeout) * time.Millisecond,
	}

	// 2. Construct the core query message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = false // Enforce strict authoritative traversal

	// ==========================================
	// 🌟 Core Defense 1: Dynamic EDNS0 Buffer Size
	// ==========================================
	if bufSize == 0 {
		bufSize = 1232 // Safe default to prevent IP fragmentation (DNS Flag Day 2020)
	}
	m.SetEdns0(bufSize, false)

	// ==========================================
	// 🌟 Core Defense 2: DNS Client Cookie Injection
	// ==========================================
	if enableCookie {
		opt := m.IsEdns0()
		if opt != nil {
			var finalCookieStr string
			val := strings.ToLower(strings.TrimSpace(cookieValue))

			// Use a random 8-byte Client Cookie to bypass strict rate-limiting policies
			if val == "random" || val == "" {
				cookieBytes := make([]byte, 8)
				rand.Read(cookieBytes)
				finalCookieStr = hex.EncodeToString(cookieBytes)
			} else {
				// Use a fixed Cookie for debugging and reproducibility
				finalCookieStr = val
			}

			cookieOpt := new(dns.EDNS0_COOKIE)
			cookieOpt.Code = dns.EDNS0COOKIE
			cookieOpt.Cookie = finalCookieStr

			opt.Option = append(opt.Option, cookieOpt)
		}
	}

	addr := net.JoinHostPort(ip, "53")

	var r *dns.Msg
	var rtt time.Duration
	var err error
	var totalLatency time.Duration

	// ==========================================
	// 🌟 Core Defense 3: Retransmission & Randomized Jitter
	// ==========================================
	for attempt := 0; attempt <= retries; attempt++ {
		// Initial or retry UDP query
		r, rtt, err = client.Exchange(m, addr)
		totalLatency += rtt

		// If err == nil, a valid DNS response packet was received (even if it is REFUSED or SERVFAIL)
		if err == nil {
			// ==========================================
			// 🌟 Core Defense 4: Automatic TCP Fallback
			// ==========================================
			if r != nil && r.Truncated {
				tcpClient := dns.Client{
					Net:     tcpNetwork,
					Timeout: time.Duration(timeout) * time.Millisecond,
				}
				var tcpRtt time.Duration
				r, tcpRtt, err = tcpClient.Exchange(m, addr)
				totalLatency += tcpRtt
			}
			break // Packet successfully received, exit retry loop immediately!
		}

		// If a genuine network exception occurs (Timeout, Connection Reset),
		// sleep for the configured jitter duration before retrying.
		if attempt < retries {
			sleepFor(retryDelay)
		}
	}

	return &Result{
		Msg:     r,
		Latency: totalLatency, // Return cumulative latency across all attempts
		Err:     err,
	}
}

// sleepFor pauses execution based on a fixed duration (e.g., "2s") or a
// randomized interval (e.g., "1s-3s") to prevent synchronized probing spikes.
func sleepFor(delayStr string) {
	delayStr = strings.TrimSpace(delayStr)
	if delayStr == "" {
		return
	}

	// 1. Handle randomized interval mode (e.g., "1s-3s", "500ms-1500ms")
	if strings.Contains(delayStr, "-") {
		parts := strings.Split(delayStr, "-")
		if len(parts) == 2 {
			minD, err1 := time.ParseDuration(strings.TrimSpace(parts[0]))
			maxD, err2 := time.ParseDuration(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil && maxD > minD {
				delta := int64(maxD - minD)
				sleepTime := minD + time.Duration(mrand.Int63n(delta))
				time.Sleep(sleepTime)
				return
			}
		}
	}

	// 2. Fallback to fixed duration mode (e.g., "2s")
	if fixed, err := time.ParseDuration(delayStr); err == nil {
		time.Sleep(fixed)
	}
}

// package probe

// import (
// 	"crypto/rand"
// 	"dns-analyzer/internal/config"
// 	"encoding/hex"
// 	mrand "math/rand"
// 	"net"
// 	"strings"
// 	"time"

// 	"github.com/miekg/dns"
// )

// type Result struct {
// 	Msg     *dns.Msg
// 	Latency time.Duration
// 	Err     error
// }

// func init() {
// 	// 初始化随机数种子，用于后续的随机延迟
// 	mrand.Seed(time.Now().UnixNano())
// }

// /*
// =============================================================================
// 🛠️ 探测引擎发包指纹 (Query Fingerprint)
// 本函数构造并发送的 DNS 查询报文，如果启用了 Cookie 且 BufSize 为 1232，
// 等效于以下 dig 命令的输出格式：
// $ dig @{ip} {domain} {qtype} +norecurse +bufsize=1232 +cookie

// ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
// ;; flags: ; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
// ;;       ^
// ;;       └─ 注意这里没有 'rd' 标志，强制只进行一层权威探测

// ;; OPT PSEUDOSECTION:
// ; EDNS: version: 0, flags:; udp: 1232
// ; COOKIE: a1b2c3d4e5f6g7h8 (client)  <-- 开启 enable_cookie 后会多出这个
// ;; QUESTION SECTION:
// ;{domain}.                     IN      {qtype}
// =============================================================================
// */

// /*
// =============================================================================
// 🛠️ 探测引擎发包指纹与容错
// 包含: UDP 探测、EDNS0 缓冲区、Cookie 注入、丢包重传、随机防抖延迟、TCP 回退
// =============================================================================
// */

// func Execute(ip, domain string, qtype uint16, env config.NetworkEnv, timeout, retries int, retryDelay string, bufSize uint16, enableCookie bool, cookieValue string) *Result {
// 	// 1. 选择底层网络协议栈
// 	network := "udp"
// 	tcpNetwork := "tcp"
// 	if env == config.EnvIPv4 {
// 		network = "udp4"
// 		tcpNetwork = "tcp4"
// 	} else if env == config.EnvIPv6 {
// 		network = "udp6"
// 		tcpNetwork = "tcp6"
// 	}

// 	client := dns.Client{
// 		Net:     network,
// 		Timeout: time.Duration(timeout) * time.Millisecond,
// 	}

// 	// 2. 构造查询报文
// 	m := new(dns.Msg)
// 	m.SetQuestion(dns.Fqdn(domain), qtype)
// 	m.RecursionDesired = false

// 	// ==========================================
// 	// 🌟 核心防御 1：动态 EDNS0 缓冲区设置
// 	// ==========================================
// 	if bufSize == 0 {
// 		bufSize = 1232 // 防 IP 分片的安全默认值
// 	}
// 	m.SetEdns0(bufSize, false)

// 	// ==========================================
// 	// 🌟 核心防御 2：灵活的 DNS Client Cookie 注入
// 	// ==========================================
// 	if enableCookie {
// 		opt := m.IsEdns0()
// 		if opt != nil {
// 			var finalCookieStr string
// 			val := strings.ToLower(strings.TrimSpace(cookieValue))

// 			// 随机 Cookie 绕过限速策略
// 			if val == "random" || val == "" {
// 				cookieBytes := make([]byte, 8)
// 				rand.Read(cookieBytes)
// 				finalCookieStr = hex.EncodeToString(cookieBytes)
// 			} else {
// 				// 固定 Cookie 用于复现与调试
// 				finalCookieStr = val
// 			}

// 			cookieOpt := new(dns.EDNS0_COOKIE)
// 			cookieOpt.Code = dns.EDNS0COOKIE
// 			cookieOpt.Cookie = finalCookieStr

// 			opt.Option = append(opt.Option, cookieOpt)
// 		}
// 	}

// 	addr := net.JoinHostPort(ip, "53")

// 	var r *dns.Msg
// 	var rtt time.Duration
// 	var err error
// 	var totalLatency time.Duration

// 	// ==========================================
// 	// 🌟 核心防御 3：丢包重传与随机防抖 (Jitter)
// 	// ==========================================
// 	for attempt := 0; attempt <= retries; attempt++ {
// 		// 首次或重试查询 (UDP)
// 		r, rtt, err = client.Exchange(m, addr)
// 		totalLatency += rtt

// 		// err == nil 说明成功收到了响应包（即使是 REFUSED 也是成功响应）
// 		if err == nil {
// 			// ==========================================
// 			// 🌟 核心防御 4：TCP 自动回退 (TCP Fallback)
// 			// ==========================================
// 			if r != nil && r.Truncated {
// 				tcpClient := dns.Client{
// 					Net:     tcpNetwork,
// 					Timeout: time.Duration(timeout) * time.Millisecond,
// 				}
// 				var tcpRtt time.Duration
// 				r, tcpRtt, err = tcpClient.Exchange(m, addr)
// 				totalLatency += tcpRtt
// 			}
// 			break // 拿到包了，立刻跳出重试循环！
// 		}

// 		// 如果发生真正的网络异常 (Timeout, Connection Reset)，且还没达到最大重试次数，就休息一下再发
// 		if attempt < retries {
// 			sleepFor(retryDelay)
// 		}
// 	}

// 	return &Result{
// 		Msg:     r,
// 		Latency: totalLatency, // 返回累计耗时
// 		Err:     err,
// 	}
// }

// // 辅助函数：处理 "1s-3s" 区间随机等待 或 "2s" 固定等待
// func sleepFor(delayStr string) {
// 	delayStr = strings.TrimSpace(delayStr)
// 	if delayStr == "" {
// 		return
// 	}

// 	// 1. 处理区间随机模式 (如 "1s-3s", "500ms-1500ms")
// 	if strings.Contains(delayStr, "-") {
// 		parts := strings.Split(delayStr, "-")
// 		if len(parts) == 2 {
// 			minD, err1 := time.ParseDuration(strings.TrimSpace(parts[0]))
// 			maxD, err2 := time.ParseDuration(strings.TrimSpace(parts[1]))
// 			if err1 == nil && err2 == nil && maxD > minD {
// 				delta := int64(maxD - minD)
// 				sleepTime := minD + time.Duration(mrand.Int63n(delta))
// 				time.Sleep(sleepTime)
// 				return
// 			}
// 		}
// 	}

// 	// 2. 降级处理固定等待模式 (如 "2s")
// 	if fixed, err := time.ParseDuration(delayStr); err == nil {
// 		time.Sleep(fixed)
// 	}
// }
