<div align="center">

<img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/assets/banner.png" alt="Recon Hunter Pro - Enterprise Recon Framework" width="100%"/>

# Recon Hunter Pro
### Enterprise-Grade Reconnaissance & OSINT Framework — 2025 Edition

**The most advanced open-source reconnaissance framework with full GUI — 20+ passive sources • intelligent bruteforce • CDN/WAF bypass • tech stack fingerprinting • async port scanning • SSL transparency**

[![License](https://img.shields.io/badge/License-Apache_2.0-00d4ff.svg?style=for-the-badge&logo=apache&logoColor=white)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?style=for-the-badge)]()
[![Stars](https://img.shields.io/github/stars/Arash-Mansourpour/ReconHunterPro?style=for-the-badge&logo=github&color=181717)](https://github.com/Arash-Mansourpour/ReconHunterPro/stargazers)
[![Downloads](https://img.shields.io/github/downloads/Arash-Mansourpour/ReconHunterPro/total?color=28a745&style=for-the-badge)](https://github.com/Arash-Mansourpour/ReconHunterPro/releases)

</div>

<br>

## Real-Time GUI — Dark Professional Theme

<div align="center">
  <img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(652).png" alt="Main Dashboard"/>
  <p><strong>Main Dashboard — Live Logging & Controls</strong></p>
  <br>
  <img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(653).png" alt="Scan Results Summary"/>
  <p><strong>Summary Tab — Metrics & Top Findings</strong></p>
  <br>
  <img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(654).png" alt="Detailed Subdomain Analysis"/>
  <p><strong>Detailed View — IP, Tech Stack, WAF, Ports, SSL</strong></p>
  <br>
  <img src="https://raw.githubusercontent.com/Arash-Mansourpour/ReconHunterPro/main/Screenshot%20(655).png" alt="Security Assessment Tab"/>
  <p><strong>Security Tab — Exposed Panels, Open Ports, SSL Issues</strong></p>
</div>

<br>

## Core Features & Technical Details

| Module                        | Technology Used                    | Key Capabilities |
|-------------------------------|------------------------------------|------------------------|
| **Passive Recon Engine**      | `aiohttp`, `aiodns`                | 20+ sources: crt.sh, ThreatCrowd, HackerTarget, Wayback, VirusTotal (public), AlienVault OTX, URLScan, RapidDNS |
| **DNS Bruteforce & Permutations** | Custom wordlist + Amass-style engine | 100k+ built-in words • prefix/suffix/number/leetspeak permutations |
| **CDN & Cloud Detection**     | IP range + ASN + HTTP headers      | Cloudflare, Akamai, AWS CloudFront, Fastly, Incapsula, Azure, Sucuri |
| **WAF Detection Engine**      | Payload triggering + signature DB  | Cloudflare, AWS WAF, Sucuri, ModSecurity, Wordfence, F5 BIG-IP |
| **Technology Fingerprinting** | Wappalyzer-style regex + headers   | 100+ signatures: WordPress, Laravel, React, Vue, Django, Shopify, Node.js, Nginx, Apache |
| **HTTP Probing**              | `aiohttp` + real IP bypass         | Title, server header, redirects, tech detection, response time |
| **SSL/TLS Analysis**          | `OpenSSL.py` + `ssl` module        | Issuer, SANs, expiration, self-signed, serial, version |
| **Port Scanner**              | Async raw sockets                  | 20 high-value ports (21,22,23,25,53,80,443,3306,3389,6379...) |
| **Export Engine**             | JSON • CSV • HTML (PDF planned)    | Professional reports with branding |

<br>

## Installation & Usage

```bash
git clone https://github.com/Arash-Mansourpour/ReconHunterPro.git
cd ReconHunterPro
pip install -r requirements.txt
python recon_hunter_pro.py
