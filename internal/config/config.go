/*
 * Copyright (c) 2026 Fasheng Miao, Tsinghua University.
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Package config handles the loading and parsing of the global configuration
// file (config.yaml) used to orchestrate the RMap engine and auditing modules.
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// NetworkEnv defines the IP stack environment used for DNS probing.
type NetworkEnv string

const (
	EnvIPv4 NetworkEnv = "ipv4"
	EnvIPv6 NetworkEnv = "ipv6"
	EnvDual NetworkEnv = "dual"
)

// Config represents the complete structure of the config.yaml file.
type Config struct {
	Engine struct {
		MaxConcurrency int        `yaml:"max_concurrency"`
		TimeoutMS      int        `yaml:"timeout_ms"`
		MaxDepth       int        `yaml:"max_depth"`
		NetworkEnv     NetworkEnv `yaml:"network_env"`

		Retries    int    `yaml:"retries"`     // Number of query retries upon failure
		RetryDelay string `yaml:"retry_delay"` // Delay between retries (e.g., "500ms")

		UDPBufferSize uint16 `yaml:"udp_buffer_size"`
		EnableCookie  bool   `yaml:"enable_cookie"`
		CookieValue   string `yaml:"cookie_value"`
	} `yaml:"engine"`

	Bootstrap struct {
		RootServers []struct {
			Name string `yaml:"name"`
			IPv4 string `yaml:"ipv4"`
			IPv6 string `yaml:"ipv6"`
		} `yaml:"root_servers"`
	} `yaml:"bootstrap"`

	Input struct {
		DirectTargets []struct {
			Domain string `yaml:"domain"`
			QType  string `yaml:"q_type"`
		} `yaml:"direct_targets"`

		FileTargets struct {
			Enabled      bool   `yaml:"enabled"`
			Path         string `yaml:"path"`
			DefaultQType string `yaml:"default_q_type"`
		} `yaml:"file_targets"`
	} `yaml:"input"`

	Output struct {
		ReportDir             string `yaml:"report_dir"`
		SaveIndividualReports bool   `yaml:"save_individual_reports"`
		SaveSearchResults     bool   `yaml:"save_search_results"`
	} `yaml:"output"`

	Search struct {
		Enabled bool `yaml:"enabled"`

		// RCODE matching controls
		EnableRcodeCheck  bool  `yaml:"enable_rcode_check"`
		TargetRcodes      []int `yaml:"target_rcodes"`
		MatchInvalidRcode bool  `yaml:"match_invalid_rcode"`

		// EDE (Extended DNS Error) matching controls
		EnableEdeCheck  bool     `yaml:"enable_ede_check"`
		TargetEDEs      []string `yaml:"target_edes"`
		MatchInvalidEDE bool     `yaml:"match_invalid_ede"`

		// Flags matching controls
		EnableFlagsCheck bool     `yaml:"enable_flags_check"`
		TargetFlags      []string `yaml:"target_flags"`

		// Security & Anomaly Issue matching controls
		EnableIssueCheck bool     `yaml:"enable_issue_check"`
		TargetIssues     []string `yaml:"target_issues"`

		OutputFile string `yaml:"output_file"`
	} `yaml:"search"`
}

// LoadConfig reads the configuration file from the specified path and unmarshals
// it into the Config struct.
func LoadConfig(path string) (*Config, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(buf, &cfg)
	return &cfg, err
}

// package config

// import (
// 	"os"

// 	"gopkg.in/yaml.v3"
// )

// type NetworkEnv string

// const (
// 	EnvIPv4 NetworkEnv = "ipv4"
// 	EnvIPv6 NetworkEnv = "ipv6"
// 	EnvDual NetworkEnv = "dual"
// )

// type Config struct {
//     Engine struct {
// 		MaxConcurrency int        `yaml:"max_concurrency"`
// 		TimeoutMS      int        `yaml:"timeout_ms"`
// 		MaxDepth       int        `yaml:"max_depth"`
// 		NetworkEnv     NetworkEnv `yaml:"network_env"`

// 		Retries        int        `yaml:"retries"`        // 重试次数
// 		RetryDelay     string     `yaml:"retry_delay"`   // 🌟 新增：重试间隔

// 		UDPBufferSize  uint16     `yaml:"udp_buffer_size"`
// 		EnableCookie   bool       `yaml:"enable_cookie"`
// 		CookieValue    string     `yaml:"cookie_value"`
// 	} `yaml:"engine"`

// 	Bootstrap struct {
// 		RootServers []struct {
// 			Name string `yaml:"name"`
// 			IPv4 string `yaml:"ipv4"`
// 			IPv6 string `yaml:"ipv6"`
// 		} `yaml:"root_servers"`
// 	} `yaml:"bootstrap"`

// 	Input struct {
// 		DirectTargets []struct {
// 			Domain string `yaml:"domain"`
// 			QType  string `yaml:"q_type"`
// 		} `yaml:"direct_targets"`
// 		FileTargets struct {
// 			Enabled      bool   `yaml:"enabled"`
// 			Path         string `yaml:"path"`
// 			DefaultQType string `yaml:"default_q_type"`
// 		} `yaml:"file_targets"`
// 	} `yaml:"input"`

// 	Output struct {
// 		ReportDir             string `yaml:"report_dir"`
// 		SaveIndividualReports bool   `yaml:"save_individual_reports"`
// 		SaveSearchResults     bool   `yaml:"save_search_results"`
// 	} `yaml:"output"`

//     Search struct {
// 		Enabled bool `yaml:"enabled"`

// 		// RCODE 控制
// 		EnableRcodeCheck  bool  `yaml:"enable_rcode_check"`
// 		TargetRcodes      []int `yaml:"target_rcodes"`
// 		MatchInvalidRcode bool  `yaml:"match_invalid_rcode"`

// 		// EDE 控制
// 		EnableEdeCheck  bool     `yaml:"enable_ede_check"`
// 		TargetEDEs      []string `yaml:"target_edes"`
// 		MatchInvalidEDE bool     `yaml:"match_invalid_ede"`

// 		// Flags 控制
// 		EnableFlagsCheck bool     `yaml:"enable_flags_check"`
// 		TargetFlags      []string `yaml:"target_flags"`

// 		// 🌟 故障诊断 Issue 控制
// 		EnableIssueCheck bool     `yaml:"enable_issue_check"`
// 		TargetIssues     []string `yaml:"target_issues"`

// 		OutputFile string `yaml:"output_file"`
// 	} `yaml:"search"`
// }

// func LoadConfig(path string) (*Config, error) {
// 	buf, err := os.ReadFile(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var cfg Config
// 	err = yaml.Unmarshal(buf, &cfg)
// 	return &cfg, err
// }
