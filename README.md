# 🌐 RMap: Recursive DNS Mapping & Vulnerability Auditing Engine

[![Go Report Card](https://goreportcard.com/badge/github.com/ahlien/Rmap-Recursive-Mapping-)](https://goreportcard.com/report/github.com/ahlien/Rmap-Recursive-Mapping-)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ahlien/Rmap-Recursive-Mapping-)](https://golang.org/)

**RMap** is a high-performance, distributed DNS trust-chain graph engine and vulnerability scanner. Designed for Internet-scale reconnaissance, it goes beyond simple DNS probing by performing deep recursive topology traversal, dynamic graph modeling, and multi-dimensional zero-trust security auditing.

Whether you are a security researcher tracking malicious CNAME hijackings, a network engineer analyzing infrastructure Single-Points-of-Failure (SPOF), or an academic studying DNS ecosystem resilience, RMap provides the ultimate topological mapping framework.

## ✨ Key Features

* 🕸️ **Dynamic Directed Graph Engine**: Performs strict recursive resolution, tracking complex CNAME/DNAME chains, extracting hidden Glue IPs, and building a complete topological dependency graph (DAG) for each target.
* 🛡️ **Zero-Trust Audit Matrix**: Integrates multiple vulnerability models:
    * **Infrastructure Risk**: Detects physical (Single-City) and logical (Single-AS) cascading failure risks.
    * **Protocol Compliance**: Identifies strict RFC violations (e.g., CNAME exclusivity, Zone Apex conflicts, NODATA anomalies).
    * **Security & Hijacking**: Traces infected delegation paths, Dangling NS (NXDOMAIN) takeover risks, and internal IP leaks.
* 🧠 **Heterogeneous Data Enrichment**: In-memory mapping of Threat Intelligence IOCs (malicious domains/IPs) and MaxMind GeoIP/ASN databases for real-time node fingerprinting.
* ⚡ **High-Concurrency Architecture**: Built on Go with a lock-free goroutine worker pool, capable of handling millions of domains smoothly.
* 📊 **Interactive Visualizer**: Includes a standalone tool to render the JSON topology data into a beautiful, interactive HTML graph using `vis.js`.

---

## 🏗️ Getting Started

### 1. Prerequisites

* **Go 1.25+** installed.
* **MaxMind GeoLite2 Databases**: Download `GeoLite2-ASN.mmdb` and `GeoLite2-City.mmdb` (Free from MaxMind).
* **Threat Intelligence Feeds**: Prepare plain text files containing known malicious domains and IPs (one per line).

### 2. Directory Setup

Clone the repository and place your external assets in the `asset` directory:

```text
RMap/
├── asset/
│   ├── geo/
│   │   ├── GeoLite2-ASN.mmdb
│   │   └── GeoLite2-City.mmdb
│   └── intel/
│       ├── threat_domains.txt
│       └── threat_ips.txt
├── cmd/
│   ├── analyzer/main.go    # Core Engine
│   └── visualizer/main.go  # HTML Report Generator
├── internal/               # Engine, Audit, Model, Config packages
└── config.yaml             # Global Configuration

```
### 3. Installation

Download dependencies and compile the tools (optional, you can also use `go run` directly):

```bash
git clone https://github.com/ahlien/Rmap-Recursive-Mapping-.git
cd Rmap-Recursive-Mapping-
go mod tidy
```

## 🚀 Usage
### Phase 1: Running the Analyzer Engine

The Analyzer reads your `config.yaml`, dispatches the probes, runs the security audits, and saves the topology data to the `./reports` directory.

```bash
go run cmd/analyzer/main.go
```
#### Example Output:

```bash
✅ [Success] ASN database loaded successfully.
✅ [Success] City geolocation database loaded successfully.
✅ [Success] Threat Intel Feeds loaded. Parsed 3 domain IOCs and 0 IP IOCs.
>>> 🔎 Precision Search Mode -> Rcodes: [3 5] | EDEs: [*] | Issues: [*]
======================================================
✅ All tasks completed successfully!
📊 Total Domains Processed: 1
⏱️  Total Execution Time: 4.94s
🚀 Average Speed: 0.20 domains/sec
------------------------------------------------------
🎯 Total Hits: 1 domains with anomalies (Pollution Rate: 100.00%)
🔍 Anomaly Dimension Breakdown (Base: 1 total domains):
   ├─ [RCODE]:      0 domains (Ratio:  0.00%)
   ├─ [EDE]:        0 domains (Ratio:  0.00%)
   ├─ [Flags]:      1 domains (Ratio: 100.00%)
   │  ├─ qr                        :     1 (100.00%)
   │  └─ aa                        :     1 (100.00%)
   └─ [Issues]:     1 domains (Ratio: 100.00%)
      ├─ INFECTED_DELEGATION_PATH  :     1 (100.00%)
      └─ SINGLE_CITY_EXPOSURE      :     1 (100.00%)
======================================================
```

The engine will generate JSON reports (e.g., reports/www.baidu.com_A.json) containing the full graph topology and audit findings.

### Phase 2: Generating the Visual Dashboard
*Once the analyzer completes, use the Visualizer tool to convert the raw JSON topology into an interactive, standalone HTML report.

```bash
# You can pass the domain name directly
go run cmd/visualizer/main.go www.baidu.com
```

#### Example Output:

```bash
>>> ✅ Success! Visualizer HTML generated at: reports\www.baidu.com_A.html
```
*Open the generated HTML file in your browser to explore the interactive Dependency Tree, the Security Audit Panel, and the Discovered Infrastructure Assets.*

---

## ⚙️ Configuration (`config.yaml`)

RMap is highly customizable. The `config.yaml` file controls concurrency, IPv4/IPv6 environments, targeted vulnerability tracking, and protocol fingerprint masking.

Key parameters include:

* **`network_env`**: Supports `ipv4`, `ipv6`, or `dual` (Dual-stack).
* **`enable_cookie`**: Injects DNS Client Cookies (RFC 7873) to disguise probes and bypass basic DDoS rate-limiting.
* **`target_issues`**: Define exactly which vulnerabilities to flag (e.g., `["NXDOMAIN_ABORT", "SINGLE_AS_EXPOSURE"]` or `["*"]` for everything).

*(Refer to the Reference Guide at the bottom of the `config.yaml` file for a complete dictionary of RCODEs, EDEs, and Vulnerability Types).*

---

## 🧩 Audit Modules

RMap comes pre-loaded with an extensible auditing matrix:

* **LameAuditor**: Detects broken delegations, network unreachability, and SERVFAIL/REFUSED anomalies.
* **CNAMEAuditor**: Strict RFC 1034/1912 compliance checker (detects Exclusivity and Zone Apex violations).
* **ProtocolAuditor**: Identifies ghost responses (NODATA anomalies) and redundant packet RRs.
* **SecurityAuditor**: Catches Private IP leaks (RFC 1918) and extracts Extended DNS Errors (EDE).
* **DanglingAuditor**: Detects vulnerable delegations (NXDOMAIN) pointing to unregistered endpoints and catches Split-Brain resolution inconsistencies.