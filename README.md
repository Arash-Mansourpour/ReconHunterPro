<div align="center">

# Recon Hunter Pro
### Enterprise-Grade Reconnaissance & OSINT Framework — 2025 Edition

**The most advanced open-source recon tool with full GUI • 20+ passive sources • intelligent bruteforce • CDN/WAF bypass • tech fingerprinting • async port scanning • SSL analysis**

[![License](https://img.shields.io/badge/License-Apache_2.0-00d4ff.svg?style=for-the-badge&logo=apache&logoColor=white)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Stars](https://img.shields.io/github/stars/Arash-Mansourpour/ReconHunterPro?style=for-the-badge&logo=github&color=181717)](https://github.com/Arash-Mansourpour/ReconHunterPro)
[![Downloads](https://img.shields.io/github/downloads/Arash-Mansourpour/ReconHunterPro/total?style=for-the-badge&color=28a745)](https://github.com/Arash-Mansourpour/ReconHunterPro/releases)

</div>

<br>

### Real Screenshots (Dark Professional Theme)

<div align="center">

**Main Dashboard & Live Logging**  
<img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(652).png" width="95%"/>

<br><br>

**Summary Tab – Metrics & Top Findings**  
<img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(653).png" width="95%"/>

<br><br>

**Detailed Subdomain Analysis**  
<img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(654).png" width="95%"/>

<br><br>

**Security Assessment Tab – Exposed Panels & Risks**  
<img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(655).png" width="95%"/>

</div>

<br>

### Core Features

| Module                        | Technology                          | Key Capabilities                                      |
|-------------------------------|-------------------------------------|-------------------------------------------------------|
| Passive Recon Engine          | `aiohttp` + `aiodns`                | 20+ sources (crt.sh, ThreatCrowd, HackerTarget, Wayback, VirusTotal public, AlienVault OTX, URLScan, RapidDNS, etc.) |
| DNS Bruteforce & Permutations | Custom engine            | Custom + Amass-style logic          | 100k+ wordlist • prefix/suffix/number/leetspeak permutations |
| CDN & Cloud Detection         | IP ranges + ASN + headers           | Cloudflare • Akamai • AWS • Fastly • Incapsula • Sucuri • Azure |
| WAF Detection Engine          | Payload triggering + 50+ signatures | Cloudflare • AWS WAF • Sucuri • ModSecurity • Wordfence • F5 |
| Technology Fingerprinting     | 100+ Wappalyzer-style signatures   | WordPress • Laravel • React • Vue • Django • Shopify • Node.js • Nginx • Apache |
| Real-IP Bypass                | Direct connect when no CDN          | Automatic fallback to origin IP                       |
| SSL/TLS Certificate Analysis  | `OpenSSL.py` + native `ssl`         | SANs, issuer, expiry, self-signed, serial number     |
| Async Port Scanner            | Raw sockets (asyncio)               | 20 high-value ports (21,22,80,443,3306,3389,6379…)   |
| Export Engine                 | JSON • CSV • HTML                   | Professional reports (PDF coming soon)                |

<br>

### Scan Modes

| Mode       | Active Probing | Speed   | Recommended For                       |
|------------|-------------------|---------|---------------------------------------|
| Passive    | No                | Fast    | Safe recon • Bug bounty initial phase |
| Normal     | DNS only          | Fast    | Standard reconnaissance              |
| Aggressive | Full (ports+WAF)  | Fast    | Pentest • Red team                    |
| Stealth    | Full + random delays | Slow | OPSEC-critical operations            |

<br>

### Quick Installation

```bash
git clone https://github.com/Arash-Mansourpour/ReconHunterPro.git
cd ReconHunterPro
pip install -r requirements.txt
python recon_hunter_pro.py
