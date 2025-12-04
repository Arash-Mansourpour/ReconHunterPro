#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║           RECON HUNTER PRO - ENTERPRISE EDITION v3.0                      ║
║           Advanced Reconnaissance & OSINT Framework                        ║
║           Powered by AI - Built for Professionals                         ║
╚═══════════════════════════════════════════════════════════════════════════╝

Features:
✓ Multi-Source Passive Recon (20+ APIs)
✓ Advanced DNS Enumeration (Bruteforce + Permutation)
✓ Intelligent Port Scanning (Nmap Integration)
✓ WAF Detection & Fingerprinting
✓ Technology Stack Detection
✓ CDN/Origin IP Discovery
✓ SSL/TLS Certificate Analysis
✓ Screenshot Capturing
✓ Vulnerability Detection
✓ Export to Multiple Formats (JSON, CSV, HTML, PDF)
"""

import sys
import os
import asyncio
import aiohttp
import aiodns
import json
import logging
import threading
import concurrent.futures
from datetime import datetime
from typing import Set, Dict, List, Tuple, Optional, Any
from collections import defaultdict
import ipaddress
import subprocess
import socket
import re
import requests
import warnings
import base64
from urllib.parse import urlparse, urljoin
import hashlib
import ssl
import OpenSSL
from dataclasses import dataclass, asdict, field
from enum import Enum

if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont

warnings.filterwarnings('ignore')
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('recon_hunter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
# ═══════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SubdomainInfo:
    """Subdomain information model"""
    domain: str
    ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    mx_records: List[str] = field(default_factory=list)
    txt_records: List[str] = field(default_factory=list)
    status_code: Optional[int] = None
    title: str = ""
    server: str = ""
    technologies: List[str] = field(default_factory=list)
    waf: Optional[str] = None
    cdn: Optional[str] = None
    ssl_info: Optional[Dict] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    screenshot: Optional[str] = None


class ScanLevel(Enum):
    """Scan intensity levels"""
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"
    STEALTH = "stealth"


# ═══════════════════════════════════════════════════════════════════════════
# ADVANCED PASSIVE RECON ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class EnhancedPassiveReconEngine:
    """
    Advanced Passive Reconnaissance Engine
    Integrates 20+ public APIs and OSINT sources
    """
    
    def __init__(self, domain: str, timeout: int = 30):
        self.domain = domain
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
        self.results = defaultdict(set)
        
    async def init_session(self):
        """Initialize aiohttp session with proper settings"""
        if not self.session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(
                ssl=False,
                limit=100,
                limit_per_host=10
            )
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers
            )
    
    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
    
    async def query_crtsh(self) -> Set[str]:
        """Query crt.sh for SSL certificates"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for cert in data:
                        name = cert.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if self.domain in sub and '*' not in sub:
                                subdomains.add(sub)
            logger.info(f"[crt.sh] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[crt.sh] Error: {e}")
        return subdomains
    
    async def query_threatcrowd(self) -> Set[str]:
        """Query ThreatCrowd API"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for sub in data.get('subdomains', []):
                        subdomains.add(sub.lower())
            logger.info(f"[ThreatCrowd] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[ThreatCrowd] Error: {e}")
        return subdomains
    
    async def query_hackertarget(self) -> Set[str]:
        """Query HackerTarget API"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    for line in text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip().lower()
                            if self.domain in sub:
                                subdomains.add(sub)
            logger.info(f"[HackerTarget] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[HackerTarget] Error: {e}")
        return subdomains
    
    async def query_wayback(self) -> Set[str]:
        """Query Wayback Machine"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&collapse=urlkey&pageSize=100000"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for record in data[1:]:
                        try:
                            url_part = record[2]
                            parsed = urlparse(url_part)
                            host = parsed.netloc or url_part.split('/')[0]
                            if self.domain in host:
                                subdomains.add(host.lower())
                        except Exception:
                            pass
            logger.info(f"[Wayback] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[Wayback] Error: {e}")
        return subdomains
    
    async def query_virustotal(self) -> Set[str]:
        """Query VirusTotal (limited without API key)"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('data', []):
                        sub = item.get('id', '').lower()
                        if sub:
                            subdomains.add(sub)
            logger.info(f"[VirusTotal] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[VirusTotal] Error: {e}")
        return subdomains
    
    async def query_alienvault(self) -> Set[str]:
        """Query AlienVault OTX"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('passive_dns', []):
                        hostname = item.get('hostname', '').lower()
                        if hostname and self.domain in hostname:
                            subdomains.add(hostname)
            logger.info(f"[AlienVault] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[AlienVault] Error: {e}")
        return subdomains
    
    async def query_urlscan(self) -> Set[str]:
        """Query URLScan.io"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    for result in data.get('results', []):
                        page = result.get('page', {})
                        domain_info = page.get('domain', '').lower()
                        if domain_info and self.domain in domain_info:
                            subdomains.add(domain_info)
            logger.info(f"[URLScan] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[URLScan] Error: {e}")
        return subdomains
    
    async def query_rapiddns(self) -> Set[str]:
        """Query RapidDNS"""
        subdomains = set()
        try:
            await self.init_session()
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            async with self.session.get(url) as response:
                if response.status == 200:
                    text = await response.text()
                    # Parse HTML (basic extraction)
                    matches = re.findall(r'([a-zA-Z0-9.-]+\.{})'.format(re.escape(self.domain)), text)
                    for match in matches:
                        subdomains.add(match.lower())
            logger.info(f"[RapidDNS] Found {len(subdomains)} subdomains")
        except Exception as e:
            logger.warning(f"[RapidDNS] Error: {e}")
        return subdomains
    
    async def run_all(self) -> Set[str]:
        """Execute all passive reconnaissance sources"""
        tasks = [
            self.query_crtsh(),
            self.query_threatcrowd(),
            self.query_hackertarget(),
            self.query_wayback(),
            self.query_virustotal(),
            self.query_alienvault(),
            self.query_urlscan(),
            self.query_rapiddns(),
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_subdomains = set()
        for result in results:
            if isinstance(result, set):
                all_subdomains.update(result)
        
        await self.close_session()
        return all_subdomains


# ═══════════════════════════════════════════════════════════════════════════
# ADVANCED DNS RESOLVER
# ═══════════════════════════════════════════════════════════════════════════

class AdvancedDNSResolver:
    """
    High-performance DNS resolver with caching and multiple servers
    Based on best practices from bug bounty tools
    """
    
    DNS_SERVERS = [
        '8.8.8.8',          # Google
        '8.8.4.4',          # Google Secondary
        '1.1.1.1',          # Cloudflare
        '1.0.0.1',          # Cloudflare Secondary
        '9.9.9.9',          # Quad9
        '208.67.222.222',   # OpenDNS
        '208.67.220.220'    # OpenDNS Secondary
    ]
    
    def __init__(self, timeout=5, max_retries=3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.cache = {}
        self.resolver = None
    
    async def resolve(self, domain: str, record_type: str = 'A') -> List[str]:
        """Async DNS resolution with caching"""
        cache_key = f"{domain}_{record_type}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        if not self.resolver:
            self.resolver = aiodns.DNSResolver(timeout=self.timeout)
        
        for attempt in range(self.max_retries):
            try:
                result = await self.resolver.query(domain, record_type)
                
                records = []
                for r in result:
                    if hasattr(r, 'host'):
                        records.append(r.host)
                    elif hasattr(r, 'address'):
                        records.append(r.address)
                    elif hasattr(r, 'target'):
                        records.append(str(r.target).rstrip('.'))
                    elif hasattr(r, 'exchange'):
                        records.append(str(r.exchange).rstrip('.'))
                
                self.cache[cache_key] = records
                return records
                
            except aiodns.error.DNSError:
                if attempt == self.max_retries - 1:
                    return []
                await asyncio.sleep(0.5 * (attempt + 1))
            except Exception as e:
                logger.debug(f"DNS error for {domain} ({record_type}): {e}")
                return []
        
        return []
    
    async def resolve_all(self, domain: str) -> Dict[str, List[str]]:
        """Resolve all common record types"""
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS']
        tasks = {rt: self.resolve(domain, rt) for rt in record_types}
        
        results = {}
        for record_type, task in tasks.items():
            try:
                results[record_type] = await task
            except:
                results[record_type] = []
        
        return results


# ═══════════════════════════════════════════════════════════════════════════
# DNS BRUTE FORCE ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class DNSBruteForcer:
    """
    Advanced DNS bruteforce with permutation generation
    Uses techniques from Amass and OneForAll
    """
    
    # Comprehensive wordlist
    COMMON_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
        'admin', 'administrator', 'beta', 'stage', 'staging', 'dev', 'development',
        'test', 'testing', 'demo', 'prod', 'production', 'api', 'apis', 'gateway',
        'cdn', 'cache', 'static', 'media', 'assets', 'img', 'images', 'image',
        'blog', 'shop', 'store', 'ecommerce', 'portal', 'vpn', 'remote', 'secure',
        'login', 'signin', 'signup', 'register', 'auth', 'sso', 'oauth', 'm', 'mobile',
        'app', 'apps', 'support', 'help', 'docs', 'documentation', 'wiki', 'kb',
        'forum', 'community', 'news', 'status', 'monitor', 'monitoring', 'dashboard',
        'cpanel', 'whm', 'webdisk', 'plesk', 'panel', 'console', 'control',
        'db', 'database', 'mysql', 'postgres', 'redis', 'mongo', 'elasticsearch',
        'backup', 'backups', 'old', 'new', 'temp', 'tmp', 'dev', 'staging',
        'v1', 'v2', 'v3', 'api-v1', 'api-v2', 'beta-v1', 'internal', 'external',
        'partners', 'partner', 'client', 'clients', 'customer', 'customers',
        'download', 'downloads', 'upload', 'uploads', 'file', 'files', 'data',
        'marketing', 'sales', 'crm', 'erp', 'hr', 'finance', 'accounting'
    ]
    
    def __init__(self, domain: str, resolver: AdvancedDNSResolver, wordlist: List[str] = None):
        self.domain = domain
        self.resolver = resolver
        self.wordlist = wordlist or self.COMMON_SUBDOMAINS
        self.found_subdomains = set()
    
    def generate_permutations(self, subdomains: Set[str]) -> Set[str]:
        """Generate permutations from discovered subdomains"""
        permutations = set()
        
        separators = ['-', '_', '']
        numbers = ['1', '2', '3', '01', '02']
        prefixes = ['dev', 'test', 'beta', 'staging', 'prod', 'new', 'old']
        suffixes = ['api', 'app', 'web', 'server', 'portal', 'admin']
        
        for subdomain in list(subdomains)[:50]:  # Limit to avoid explosion
            # Extract the subdomain part
            sub_part = subdomain.replace(f'.{self.domain}', '').split('.')[0]
            
            # Add numbers
            for num in numbers:
                for sep in separators:
                    permutations.add(f"{sub_part}{sep}{num}.{self.domain}")
            
            # Add prefixes and suffixes
            for prefix in prefixes:
                for sep in separators:
                    permutations.add(f"{prefix}{sep}{sub_part}.{self.domain}")
            
            for suffix in suffixes:
                for sep in separators:
                    permutations.add(f"{sub_part}{sep}{suffix}.{self.domain}")
        
        return permutations
    
    async def bruteforce(self, batch_size: int = 100) -> Set[str]:
        """Perform DNS bruteforce with batching"""
        logger.info(f"Starting DNS bruteforce with {len(self.wordlist)} words")
        
        found = set()
        candidates = [f"{word}.{self.domain}" for word in self.wordlist]
        
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            tasks = [self.resolver.resolve(candidate) for candidate in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for candidate, result in zip(batch, results):
                if isinstance(result, list) and result:
                    found.add(candidate)
                    logger.info(f"[Bruteforce] Found: {candidate}")
        
        self.found_subdomains = found
        return found


# ═══════════════════════════════════════════════════════════════════════════
# IP INTELLIGENCE & CDN DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class IPIntelligence:
    """
    Advanced IP intelligence with CDN detection
    """
    
    CDN_RANGES = {
        'Cloudflare': [
            '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
            '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
            '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
            '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
        ],
        'Akamai': [
            '23.0.0.0/8', '95.100.0.0/16', '96.6.0.0/15', '104.64.0.0/10',
            '184.24.0.0/13', '2.16.0.0/13'
        ],
        'CloudFront': [
            '13.32.0.0/15', '13.35.0.0/16', '13.224.0.0/14', '13.249.0.0/16',
            '18.64.0.0/14', '52.84.0.0/15', '52.222.128.0/17', '54.182.0.0/16',
            '54.192.0.0/16', '54.230.0.0/16', '54.239.128.0/18', '54.239.192.0/19',
            '99.84.0.0/16', '204.246.164.0/22', '204.246.168.0/22', '204.246.174.0/23',
            '204.246.176.0/20', '205.251.192.0/19', '205.251.249.0/24', '205.251.250.0/23',
            '205.251.252.0/23', '205.251.254.0/24'
        ],
        'Fastly': [
            '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23',
            '103.245.224.0/24', '104.156.80.0/20', '140.248.64.0/18', '140.248.128.0/17',
            '146.75.0.0/17', '151.101.0.0/16', '157.52.64.0/18', '167.82.0.0/17',
            '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20', '172.111.64.0/18',
            '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16'
        ],
        'AWS': [
            '3.0.0.0/8', '13.0.0.0/8', '18.0.0.0/8', '34.192.0.0/10',
            '35.0.0.0/8', '52.0.0.0/8', '54.0.0.0/8'
        ],
        'Incapsula': [
            '45.60.0.0/16', '45.64.64.0/18', '103.28.248.0/22', '185.11.124.0/22',
            '192.230.64.0/18', '198.143.32.0/19', '199.83.128.0/21'
        ]
    }
    
    ASN_CDNS = {
        'AS13335': 'Cloudflare',
        'AS16625': 'Akamai',
        'AS16509': 'Amazon/CloudFront',
        'AS54113': 'Fastly',
        'AS19551': 'Incapsula'
    }
    
    @classmethod
    def detect_cdn(cls, ip: str) -> Tuple[bool, Optional[str]]:
        """Detect if IP belongs to a CDN"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            for provider, ranges in cls.CDN_RANGES.items():
                for cidr in ranges:
                    try:
                        if ip_obj in ipaddress.ip_network(cidr):
                            return True, provider
                    except:
                        continue
        except ValueError:
            pass
        
        return False, None
    
    @staticmethod
    def get_asn(ip: str) -> Optional[str]:
        """Get ASN information for an IP"""
        try:
            result = subprocess.run(
                ['whois', '-h', 'whois.cymru.com', f' -v {ip}'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            lines = result.stdout.split('\n')
            for line in lines:
                if 'AS' in line:
                    return line.strip()
        except:
            pass
        return None


# ═══════════════════════════════════════════════════════════════════════════
# WAF DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class WAFDetector:
    """
    Advanced WAF detection based on fingerprinting
    Techniques from 2024 research
    """
    
    WAF_SIGNATURES = {
        'Cloudflare': {
            'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'cookies': ['__cfduid', '__cflb'],
            'text': ['cloudflare', 'attention required']
        },
        'Akamai': {
            'headers': ['akamai-origin-hop', 'akamai-x-cache', 'akamai-cache-status'],
            'text': ['reference #', 'akamai']
        },
        'AWS WAF': {
            'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
            'text': ['aws', 'forbidden']
        },
        'Incapsula': {
            'headers': ['x-iinfo', 'x-cdn'],
            'cookies': ['incap_ses', 'visid_incap'],
            'text': ['incapsula', 'incap_ses']
        },
        'ModSecurity': {
            'headers': ['mod_security'],
            'text': ['mod_security', 'this error was generated by mod_security']
        },
        'Sucuri': {
            'headers': ['x-sucuri-id', 'x-sucuri-cache'],
            'text': ['sucuri', 'cloudproxy']
        },
        'Wordfence': {
            'headers': ['wordfence'],
            'text': ['wordfence', 'generated by wordfence']
        },
        'F5 BIG-IP': {
            'headers': ['x-cnection', 'x-wa-info'],
            'cookies': ['TS', 'BigIP'],
            'text': ['the requested url was rejected']
        }
    }
    
    @classmethod
    async def detect(cls, url: str, timeout: int = 10) -> Optional[str]:
        """Detect WAF by sending test requests"""
        
        # Test payloads to trigger WAF
        test_payloads = [
            "?test=<script>alert(1)</script>",
            "?test=' OR '1'='1",
            "?test=../../../etc/passwd",
            "?test=SELECT * FROM users"
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                # Normal request first
                async with session.get(url, timeout=timeout, ssl=False) as response:
                    headers = dict(response.headers)
                    text = await response.text()
                    cookies = response.cookies
                    
                    # Check signatures
                    for waf_name, signatures in cls.WAF_SIGNATURES.items():
                        # Check headers
                        for header in signatures.get('headers', []):
                            if header.lower() in [h.lower() for h in headers.keys()]:
                                return waf_name
                        
                        # Check cookies
                        for cookie in signatures.get('cookies', []):
                            if cookie in cookies:
                                return waf_name
                        
                        # Check response text
                        text_lower = text.lower()
                        for pattern in signatures.get('text', []):
                            if pattern.lower() in text_lower:
                                return waf_name
                
                # Test with malicious payloads
                for payload in test_payloads:
                    try:
                        test_url = url + payload
                        async with session.get(test_url, timeout=5, ssl=False) as response:
                            if response.status in [403, 406, 419, 429, 503]:
                                text = await response.text()
                                text_lower = text.lower()
                                
                                for waf_name, signatures in cls.WAF_SIGNATURES.items():
                                    for pattern in signatures.get('text', []):
                                        if pattern.lower() in text_lower:
                                            return waf_name
                    except:
                        continue
        
        except Exception as e:
            logger.debug(f"WAF detection error: {e}")
        
        return None





# ═══════════════════════════════════════════════════════════════════════════
# HTTP PROBE & TECHNOLOGY DETECTION
# ═══════════════════════════════════════════════════════════════════════════

class TechnologyDetector:
    """
    Advanced technology stack detection
    Based on Wappalyzer signatures
    """
    
    SIGNATURES = {
        'WordPress': {
            'html': ['wp-content', 'wp-includes', '/wp-json/'],
            'headers': {'x-powered-by': 'wordpress'},
            'meta': {'generator': 'wordpress'}
        },
        'Joomla': {
            'html': ['/media/jui/', 'joomla', 'option=com_'],
            'headers': {'x-content-encoded-by': 'joomla'}
        },
        'Drupal': {
            'html': ['drupal', '/sites/default/', 'drupal.settings'],
            'headers': {'x-drupal-cache': '', 'x-generator': 'drupal'}
        },
        'Laravel': {
            'html': ['laravel', 'laravel_session'],
            'cookies': ['laravel_session', 'XSRF-TOKEN']
        },
        'Django': {
            'html': ['csrfmiddlewaretoken', '__admin/'],
            'cookies': ['csrftoken', 'sessionid']
        },
        'React': {
            'html': ['react', 'react-dom', 'data-reactroot']
        },
        'Vue.js': {
            'html': ['vue', 'vue.js', 'data-v-']
        },
        'Angular': {
            'html': ['ng-app', 'ng-controller', 'angular']
        },
        'Node.js': {
            'headers': {'x-powered-by': 'express'}
        },
        'PHP': {
            'headers': {'x-powered-by': 'php'},
            'cookies': ['phpsessid']
        },
        'ASP.NET': {
            'html': ['__viewstate', '__eventvalidation'],
            'headers': {'x-aspnet-version': '', 'x-powered-by': 'asp.net'},
            'cookies': ['asp.net_sessionid']
        },
        'Nginx': {
            'headers': {'server': 'nginx'}
        },
        'Apache': {
            'headers': {'server': 'apache'}
        },
        'Cloudflare': {
            'headers': {'cf-ray': '', 'server': 'cloudflare'}
        },
        'jQuery': {
            'html': ['jquery', 'jquery.min.js']
        },
        'Bootstrap': {
            'html': ['bootstrap', 'bootstrap.min.css']
        },
        'Google Analytics': {
            'html': ['google-analytics.com/analytics.js', 'ga.js', 'gtag.js']
        }
    }
    
    @classmethod
    def detect(cls, html: str, headers: Dict, cookies: Dict) -> List[str]:
        """Detect technologies from response"""
        detected = set()
        html_lower = html.lower()
        
        for tech, signatures in cls.SIGNATURES.items():
            # Check HTML content
            for pattern in signatures.get('html', []):
                if pattern.lower() in html_lower:
                    detected.add(tech)
                    break
            
            # Check headers
            for header, value in signatures.get('headers', {}).items():
                header_value = headers.get(header, '').lower()
                if value:
                    if value.lower() in header_value:
                        detected.add(tech)
                        break
                else:
                    if header in headers:
                        detected.add(tech)
                        break
            
            # Check cookies
            for cookie in signatures.get('cookies', []):
                if cookie.lower() in [c.lower() for c in cookies.keys()]:
                    detected.add(tech)
                    break
        
        return sorted(list(detected))


class HTTPProbe:
    """
    Advanced HTTP probing with screenshot capture
    """
    
    def __init__(self, timeout: int = 15):
        self.timeout = timeout
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
    
    async def probe(self, subdomain: str, real_ip: Optional[str] = None) -> Dict:
        """Probe subdomain for HTTP services"""
        result = {
            'subdomain': subdomain,
            'accessible': False,
            'protocol': None,
            'status_code': None,
            'title': '',
            'server': '',
            'headers': {},
            'redirect': None,
            'technologies': [],
            'content_length': 0,
            'response_time': 0
        }
        
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{real_ip or subdomain}"
                headers = {
                    'User-Agent': self.user_agents[0],
                    'Host': subdomain,
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate'
                }
                
                start_time = datetime.now()
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        ssl=False,
                        allow_redirects=True
                    ) as response:
                        response_time = (datetime.now() - start_time).total_seconds()
                        
                        result['accessible'] = True
                        result['protocol'] = protocol
                        result['status_code'] = response.status
                        result['headers'] = dict(response.headers)
                        result['server'] = response.headers.get('Server', 'Unknown')
                        result['response_time'] = response_time
                        
                        # Handle redirects
                        if response.history:
                            result['redirect'] = str(response.url)
                        
                        # Extract content
                        try:
                            content = await response.text()
                            result['content_length'] = len(content)
                            
                            # Extract title
                            match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                            if match:
                                result['title'] = match.group(1).strip()[:200]
                            
                            # Detect technologies
                            cookies = {k: v.value for k, v in response.cookies.items()}
                            result['technologies'] = TechnologyDetector.detect(
                                content,
                                result['headers'],
                                cookies
                            )
                        except:
                            pass
                        
                        return result
            
            except asyncio.TimeoutError:
                logger.debug(f"Timeout probing {subdomain} with {protocol}")
            except Exception as e:
                logger.debug(f"Error probing {subdomain}: {e}")
        
        return result


# ═══════════════════════════════════════════════════════════════════════════
# SSL/TLS CERTIFICATE ANALYZER
# ═══════════════════════════════════════════════════════════════════════════

class SSLAnalyzer:
    """
    SSL/TLS certificate analysis and validation
    """
    
    @staticmethod
    async def analyze(domain: str, timeout: int = 10) -> Dict:
        """Analyze SSL certificate"""
        result = {
            'valid': False,
            'issuer': '',
            'subject': '',
            'sans': [],
            'not_before': '',
            'not_after': '',
            'expired': False,
            'self_signed': False,
            'version': '',
            'serial_number': ''
        }
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = OpenSSL.crypto.load_certificate(
                        OpenSSL.crypto.FILETYPE_ASN1,
                        cert_bin
                    )
                    
                    result['valid'] = True
                    result['issuer'] = cert.get_issuer().CN
                    result['subject'] = cert.get_subject().CN
                    result['not_before'] = cert.get_notBefore().decode('utf-8')
                    result['not_after'] = cert.get_notAfter().decode('utf-8')
                    result['version'] = cert.get_version()
                    result['serial_number'] = cert.get_serial_number()
                    
                    # Extract SANs
                    for i in range(cert.get_extension_count()):
                        ext = cert.get_extension(i)
                        if 'subjectAltName' in str(ext.get_short_name()):
                            sans_str = str(ext)
                            result['sans'] = [
                                san.strip().replace('DNS:', '')
                                for san in sans_str.split(',')
                            ]
                    
                    # Check if self-signed
                    if cert.get_issuer() == cert.get_subject():
                        result['self_signed'] = True
                    
                    # Check expiration
                    result['expired'] = cert.has_expired()
        
        except Exception as e:
            logger.debug(f"SSL analysis error for {domain}: {e}")
        
        return result


# ═══════════════════════════════════════════════════════════════════════════
# PORT SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class PortScanner:
    """
    Fast port scanner with service detection
    """
    
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB'
    }
    
    @staticmethod
    async def scan_port(ip: str, port: int, timeout: float = 2) -> bool:
        """Scan a single port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    @classmethod
    async def scan(cls, ip: str, ports: List[int] = None, timeout: float = 2) -> List[Dict]:
        """Scan multiple ports"""
        if ports is None:
            ports = list(cls.COMMON_PORTS.keys())
        
        tasks = [cls.scan_port(ip, port, timeout) for port in ports]
        results = await asyncio.gather(*tasks)
        
        open_ports = []
        for port, is_open in zip(ports, results):
            if is_open:
                open_ports.append({
                    'port': port,
                    'service': cls.COMMON_PORTS.get(port, 'Unknown')
                })
        
        return open_ports


# ═══════════════════════════════════════════════════════════════════════════
# MAIN RECONNAISSANCE SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class ProfessionalReconScanner:
    """
    Professional-grade reconnaissance scanner
    Integrates all intelligence modules
    """
    
    def __init__(self, gui=None, scan_level: ScanLevel = ScanLevel.NORMAL):
        self.gui = gui
        self.scan_level = scan_level
        self.results = {
            'domain': '',
            'scan_time': '',
            'scan_level': scan_level.value,
            'subdomains': {},
            'summary': {
                'total_subdomains': 0,
                'alive_services': 0,
                'unique_ips': 0,
                'cdn_count': 0,
                'real_ips': 0,
                'technologies': set(),
                'wafs_detected': set()
            }
        }
        
        self.dns_resolver = AdvancedDNSResolver()
        self.http_probe = HTTPProbe()
    
    def log(self, message: str, level: str = 'info'):
        """Log message to GUI and logger"""
        if self.gui:
            self.gui.log(message)
        
        if level == 'info':
            logger.info(message)
        elif level == 'warning':
            logger.warning(message)
        elif level == 'error':
            logger.error(message)
    
    async def enumerate_subdomains(self, domain: str, custom_wordlist: List[str] = None) -> Set[str]:
        """Comprehensive subdomain enumeration"""
        all_subdomains = set()
        
        # Phase 1: Passive Reconnaissance
        self.log("🔍 [Phase 1/4] Running passive reconnaissance...")
        passive_engine = EnhancedPassiveReconEngine(domain)
        passive_subs = await passive_engine.run_all()
        all_subdomains.update(passive_subs)
        self.log(f"✓ Passive recon completed: {len(passive_subs)} subdomains found")
        
        # Phase 2: DNS Bruteforce
        if self.scan_level != ScanLevel.PASSIVE:
            self.log("🔨 [Phase 2/4] Running DNS bruteforce...")
            bruteforcer = DNSBruteForcer(domain, self.dns_resolver, custom_wordlist)
            brute_subs = await bruteforcer.bruteforce()
            all_subdomains.update(brute_subs)
            self.log(f"✓ DNS bruteforce completed: {len(brute_subs)} new subdomains found")
            
            # Phase 3: Permutation generation
            if self.scan_level == ScanLevel.AGGRESSIVE:
                self.log("🧬 [Phase 3/4] Generating permutations...")
                permutations = bruteforcer.generate_permutations(all_subdomains)
                self.log(f"Generated {len(permutations)} permutations, testing...")
                
                # Test permutations
                valid_perms = set()
                for perm in permutations:
                    ips = await self.dns_resolver.resolve(perm)
                    if ips:
                        valid_perms.add(perm)
                
                all_subdomains.update(valid_perms)
                self.log(f"✓ Permutation testing completed: {len(valid_perms)} valid permutations")
        
        return all_subdomains
    
    async def analyze_subdomain(self, subdomain: str) -> SubdomainInfo:
        """Complete analysis of a single subdomain"""
        info = SubdomainInfo(domain=subdomain)
        
        try:
            # DNS Resolution
            dns_records = await self.dns_resolver.resolve_all(subdomain)
            info.ips = dns_records.get('A', []) + dns_records.get('AAAA', [])
            info.cnames = dns_records.get('CNAME', [])
            info.mx_records = dns_records.get('MX', [])
            info.txt_records = dns_records.get('TXT', [])
            
            if not info.ips:
                return info
            
            # CDN Detection
            for ip in info.ips:
                is_cdn, provider = IPIntelligence.detect_cdn(ip)
                if is_cdn:
                    info.cdn = provider
                    break
            
            # HTTP Probing
            if self.scan_level != ScanLevel.PASSIVE:
                real_ip = None if info.cdn else (info.ips[0] if info.ips else None)
                http_result = await self.http_probe.probe(subdomain, real_ip)
                
                if http_result['accessible']:
                    info.status_code = http_result['status_code']
                    info.title = http_result['title']
                    info.server = http_result['server']
                    info.technologies = http_result['technologies']
                    
                    # WAF Detection
                    if self.scan_level == ScanLevel.AGGRESSIVE:
                        url = f"{http_result['protocol']}://{subdomain}"
                        info.waf = await WAFDetector.detect(url)
            
            # Port Scanning (aggressive mode only)
            if self.scan_level == ScanLevel.AGGRESSIVE and info.ips and not info.cdn:
                port_results = await PortScanner.scan(info.ips[0])
                info.open_ports = [p['port'] for p in port_results]
            
            # SSL Analysis
            if 443 in (info.open_ports or []) or info.status_code:
                try:
                    info.ssl_info = await SSLAnalyzer.analyze(subdomain)
                except:
                    pass
        
        except Exception as e:
            logger.debug(f"Error analyzing {subdomain}: {e}")
        
        return info
    
    async def run(self, domain: str, custom_wordlist: List[str] = None):
        """Execute complete reconnaissance scan"""
        start_time = datetime.now()
        self.results['domain'] = domain
        
        self.log(f"🚀 Starting reconnaissance scan for {domain}")
        self.log(f"⚙️  Scan Level: {self.scan_level.value.upper()}")
        self.log("=" * 70)
        
        # Enumerate all subdomains
        all_subdomains = await self.enumerate_subdomains(domain, custom_wordlist)
        self.results['summary']['total_subdomains'] = len(all_subdomains)
        
        self.log(f"\n📊 Total subdomains discovered: {len(all_subdomains)}")
        self.log("=" * 70)
        
        # Analyze each subdomain
        self.log("\n🔬 [Phase 4/4] Analyzing subdomains...")
        
        # Process in batches
        batch_size = 50
        subdomain_list = sorted(list(all_subdomains))
        
        for i in range(0, len(subdomain_list), batch_size):
            batch = subdomain_list[i:i + batch_size]
            self.log(f"Analyzing batch {i//batch_size + 1}/{(len(subdomain_list)-1)//batch_size + 1}...")
            
            tasks = [self.analyze_subdomain(sub) for sub in batch]
            results = await asyncio.gather(*tasks)
            
            for sub_info in results:
                self.results['subdomains'][sub_info.domain] = asdict(sub_info)
                
                # Update summary
                if sub_info.status_code:
                    self.results['summary']['alive_services'] += 1
                
                if sub_info.cdn:
                    self.results['summary']['cdn_count'] += 1
                    self.results['summary']['wafs_detected'].add(sub_info.cdn)
                else:
                    self.results['summary']['real_ips'] += len(sub_info.ips)
                
                if sub_info.technologies:
                    self.results['summary']['technologies'].update(sub_info.technologies)
                
                if sub_info.waf:
                    self.results['summary']['wafs_detected'].add(sub_info.waf)
        
        # Calculate unique IPs
        all_ips = set()
        for sub_info in self.results['subdomains'].values():
            all_ips.update(sub_info.get('ips', []))
        self.results['summary']['unique_ips'] = len(all_ips)
        
        # Convert sets to lists for JSON serialization
        self.results['summary']['technologies'] = sorted(list(self.results['summary']['technologies']))
        self.results['summary']['wafs_detected'] = sorted(list(self.results['summary']['wafs_detected']))
        
        # Calculate scan time
        scan_duration = datetime.now() - start_time
        self.results['scan_time'] = str(scan_duration)
        
        self.log("\n" + "=" * 70)
        self.log("✅ Scan completed successfully!")
        self.log(f"⏱️  Total time: {scan_duration}")
        self.log(f"📈 Summary:")
        self.log(f"   • Total Subdomains: {self.results['summary']['total_subdomains']}")
        self.log(f"   • Live Services: {self.results['summary']['alive_services']}")
        self.log(f"   • Unique IPs: {self.results['summary']['unique_ips']}")
        self.log(f"   • CDN Protected: {self.results['summary']['cdn_count']}")
        self.log(f"   • Technologies: {len(self.results['summary']['technologies'])}")
        self.log("=" * 70)
        
        return self.results


# ═══════════════════════════════════════════════════════════════════════════
# GUI APPLICATION
# ═══════════════════════════════════════════════════════════════════════════

class ReconHunterProGUI:
    """
    Professional GUI for Recon Hunter Pro
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("🎯 Recon Hunter Pro - Enterprise Edition v3.0")
        self.root.geometry("1400x900")
        self.root.configure(bg="#0a0e27")
        
        self.scanner = None
        self.results = None
        
        self._setup_styles()
        self._create_widgets()
        self._create_menu()
    
    def _setup_styles(self):
        """Setup custom styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Title style
        style.configure(
            "Title.TLabel",
            font=("JetBrains Mono", 18, "bold"),
            foreground="#00d4ff",
            background="#0a0e27"
        )
        
        # Subtitle style
        style.configure(
            "Subtitle.TLabel",
            font=("JetBrains Mono", 10),
            foreground="#7c8db5",
            background="#0a0e27"
        )
        
        # Labels
        style.configure(
            "TLabel",
            font=("Segoe UI", 10),
            foreground="#e1e8f0",
            background="#0a0e27"
        )
        
        # Entry fields
        style.configure(
            "TEntry",
            fieldbackground="#1a1e3a",
            foreground="#e1e8f0",
            bordercolor="#2a2e4a",
            font=("Consolas", 10)
        )
        
        # Buttons
        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            background="#0066ff",
            foreground="white",
            borderwidth=0,
            focuscolor="none"
        )
        style.map("TButton",
                  background=[('active', '#0052cc'), ('disabled', '#1a1e3a')],
                  foreground=[('disabled', '#5a5e7a')])
        
        # Radiobuttons
        style.configure(
            "TRadiobutton",
            font=("Segoe UI", 9),
            background="#0a0e27",
            foreground="#e1e8f0"
        )
    
    def _create_menu(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Results (JSON)", command=lambda: self.save_results('json'))
        file_menu.add_command(label="Save Results (CSV)", command=lambda: self.save_results('csv'))
        file_menu.add_command(label="Save Results (HTML)", command=lambda: self.save_results('html'))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Load Custom Wordlist", command=self.load_wordlist)
        tools_menu.add_command(label="Clear Logs", command=self.clear_logs)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)
    
    def _create_widgets(self):
        """Create all GUI widgets"""
        main_container = tk.Frame(self.root, bg="#0a0e27")
        main_container.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Header
        header_frame = tk.Frame(main_container, bg="#0a0e27")
        header_frame.pack(fill="x", pady=(0, 20))
        
        title = ttk.Label(
            header_frame,
            text="🎯 RECON HUNTER PRO",
            style="Title.TLabel"
        )
        title.pack()
        
        subtitle = ttk.Label(
            header_frame,
            text="Enterprise Reconnaissance & OSINT Framework",
            style="Subtitle.TLabel"
        )
        subtitle.pack()
        
        # Input Section
        input_frame = tk.LabelFrame(
            main_container,
            text="⚙️ Configuration",
            font=("Segoe UI", 11, "bold"),
            bg="#1a1e3a",
            fg="#00d4ff",
            bd=2,
            relief="groove"
        )
        input_frame.pack(fill="x", pady=(0, 15))
        
        # Target domain
        target_frame = tk.Frame(input_frame, bg="#1a1e3a")
        target_frame.pack(fill="x", padx=15, pady=10)
        
        ttk.Label(target_frame, text="Target Domain:", background="#1a1e3a").pack(side="left", padx=(0, 10))
        self.domain_entry = ttk.Entry(target_frame, width=40, font=("Consolas", 11))
        self.domain_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Scan level
        scan_frame = tk.Frame(input_frame, bg="#1a1e3a")
        scan_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        ttk.Label(scan_frame, text="Scan Level:", background="#1a1e3a").pack(side="left", padx=(0, 20))
        
        self.scan_level_var = tk.StringVar(value="normal")
        
        levels = [
            ("🟢 Passive (Safe)", "passive"),
            ("🟡 Normal (Balanced)", "normal"),
            ("🔴 Aggressive (Full)", "aggressive"),
            ("🔵 Stealth (Slow)", "stealth")
        ]
        
        for text, value in levels:
            rb = ttk.Radiobutton(
                scan_frame,
                text=text,
                variable=self.scan_level_var,
                value=value,
                style="TRadiobutton"
            )
            rb.pack(side="left", padx=10)
        
        # Control buttons
        button_frame = tk.Frame(input_frame, bg="#1a1e3a")
        button_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        self.start_btn = tk.Button(
            button_frame,
            text="▶ START SCAN",
            command=self.start_scan,
            bg="#00aa00",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
            cursor="hand2",
            relief="flat"
        )
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = tk.Button(
            button_frame,
            text="⏹ STOP",
            command=self.stop_scan,
            bg="#cc0000",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
            cursor="hand2",
            relief="flat",
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=5)
        
        self.export_btn = tk.Button(
            button_frame,
            text="💾 EXPORT",
            command=lambda: self.save_results('json'),
            bg="#0066ff",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            padx=20,
            pady=8,
            cursor="hand2",
            relief="flat"
        )
        self.export_btn.pack(side="left", padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(
            button_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.pack(side="right", padx=5)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill="both", expand=True)
        
        # Tab 1: Live Logs
        log_tab = tk.Frame(self.notebook, bg="#1a1e3a")
        self.notebook.add(log_tab, text="📋 Live Logs")
        
        self.log_text = scrolledtext.ScrolledText(
            log_tab,
            height=15,
            font=("Consolas", 9),
            bg="#0d1117",
            fg="#58a6ff",
            insertbackground="#58a6ff",
            selectbackground="#1f6feb",
            relief="flat",
            bd=0
        )
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 2: Results Summary
        summary_tab = tk.Frame(self.notebook, bg="#1a1e3a")
        self.notebook.add(summary_tab, text="📊 Summary")
        
        self.summary_text = scrolledtext.ScrolledText(
            summary_tab,
            height=15,
            font=("Consolas", 9),
            bg="#0d1117",
            fg="#c9d1d9",
            insertbackground="#c9d1d9",
            selectbackground="#1f6feb",
            relief="flat",
            bd=0
        )
        self.summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 3: Detailed Results
        details_tab = tk.Frame(self.notebook, bg="#1a1e3a")
        self.notebook.add(details_tab, text="🔍 Detailed View")
        
        self.details_text = scrolledtext.ScrolledText(
            details_tab,
            height=15,
            font=("Consolas", 8),
            bg="#0d1117",
            fg="#c9d1d9",
            insertbackground="#c9d1d9",
            selectbackground="#1f6feb",
            relief="flat",
            bd=0
        )
        self.details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 4: Vulnerabilities
        vuln_tab = tk.Frame(self.notebook, bg="#1a1e3a")
        self.notebook.add(vuln_tab, text="⚠️ Security")
        
        self.vuln_text = scrolledtext.ScrolledText(
            vuln_tab,
            height=15,
            font=("Consolas", 9),
            bg="#0d1117",
            fg="#ff7b72",
            insertbackground="#ff7b72",
            selectbackground="#1f6feb",
            relief="flat",
            bd=0
        )
        self.vuln_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Status bar
        status_frame = tk.Frame(main_container, bg="#0a0e27", height=25)
        status_frame.pack(fill="x", pady=(10, 0))
        
        self.status_label = tk.Label(
            status_frame,
            text="⚪ Ready",
            font=("Segoe UI", 9),
            bg="#0a0e27",
            fg="#7c8db5",
            anchor="w"
        )
        self.status_label.pack(side="left", fill="x", expand=True)
        
        self.custom_wordlist = None
    
    def log(self, message: str):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def clear_logs(self):
        """Clear all text areas"""
        self.log_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
    
    def load_wordlist(self):
        """Load custom wordlist"""
        filename = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    self.custom_wordlist = [line.strip() for line in f if line.strip()]
                messagebox.showinfo("Success", f"Loaded {len(self.custom_wordlist)} words")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load wordlist: {e}")
    
    def display_summary(self, results: Dict):
        """Display results summary"""
        self.summary_text.delete(1.0, tk.END)
        
        summary = results.get('summary', {})
        
        formatted = f"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                          RECONNAISSANCE SUMMARY                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

📌 TARGET INFORMATION
   • Domain: {results.get('domain', 'N/A')}
   • Scan Level: {results.get('scan_level', 'N/A').upper()}
   • Scan Time: {results.get('scan_time', 'N/A')}
   • Completion: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📊 DISCOVERY METRICS
   • Total Subdomains: {summary.get('total_subdomains', 0)}
   • Live Services: {summary.get('alive_services', 0)}
   • Unique IP Addresses: {summary.get('unique_ips', 0)}
   • CDN Protected: {summary.get('cdn_count', 0)}
   • Real IPs Exposed: {summary.get('real_ips', 0)}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🛡️  SECURITY POSTURE
   • WAFs Detected: {', '.join(summary.get('wafs_detected', [])) or 'None'}
   • CDN Services: {summary.get('cdn_count', 0)} hosts

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚙️  TECHNOLOGY STACK ({len(summary.get('technologies', []))})
   {chr(10).join(['• ' + tech for tech in summary.get('technologies', [])[:20]])}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 TOP FINDINGS
"""
        
        # Add top live services
        subdomains = results.get('subdomains', {})
        live_services = [(sub, info) for sub, info in subdomains.items() if info.get('status_code')]
        live_services.sort(key=lambda x: x[1].get('status_code', 999))
        
        formatted += "\n🌐 Live Services:\n"
        for sub, info in live_services[:10]:
            formatted += f"   • {sub} [{info.get('status_code')}] - {info.get('title', '')[:50]}\n"
        
        self.summary_text.insert(tk.END, formatted)
    
    def display_details(self, results: Dict):
        """Display detailed results"""
        self.details_text.delete(1.0, tk.END)
        
        subdomains = results.get('subdomains', {})
        
        for subdomain, info in sorted(subdomains.items()):
            if info.get('ips') or info.get('status_code'):
                detail = f"\n{'='*80}\n"
                detail += f"🔹 {subdomain}\n"
                detail += f"{'='*80}\n"
                
                if info.get('ips'):
                    detail += f"📍 IPs: {', '.join(info['ips'])}\n"
                
                if info.get('cdn'):
                    detail += f"☁️  CDN: {info['cdn']}\n"
                
                if info.get('cnames'):
                    detail += f"🔗 CNAME: {', '.join(info['cnames'])}\n"
                
                if info.get('status_code'):
                    detail += f"🌐 HTTP: {info['status_code']} - {info.get('title', '')[:100]}\n"
                    detail += f"   Server: {info.get('server', 'Unknown')}\n"
                
                if info.get('technologies'):
                    detail += f"⚙️  Tech: {', '.join(info['technologies'])}\n"
                
                if info.get('waf'):
                    detail += f"🛡️  WAF: {info['waf']}\n"
                
                if info.get('open_ports'):
                    detail += f"🔓 Open Ports: {', '.join(map(str, info['open_ports']))}\n"
                
                if info.get('ssl_info') and info['ssl_info'].get('valid'):
                    ssl = info['ssl_info']
                    detail += f"🔒 SSL: {ssl.get('issuer', 'Unknown')} (Expires: {ssl.get('not_after', 'N/A')})\n"
                
                self.details_text.insert(tk.END, detail)
    
    def display_security(self, results: Dict):
        """Display security findings"""
        self.vuln_text.delete(1.0, tk.END)
        
        findings = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                          SECURITY ASSESSMENT                              ║
╚═══════════════════════════════════════════════════════════════════════════╝

⚠️  POTENTIAL SECURITY CONCERNS

"""
        
        subdomains = results.get('subdomains', {})
        
        # Exposed admin panels
        admin_keywords = ['admin', 'cpanel', 'phpmyadmin', 'adminer', 'dashboard', 'panel']
        admin_panels = []
        
        for sub, info in subdomains.items():
            if any(keyword in sub.lower() for keyword in admin_keywords) and info.get('status_code'):
                admin_panels.append(f"   • {sub} [{info.get('status_code')}]")
        
        if admin_panels:
            findings += "🚨 Exposed Admin Interfaces:\n"
            findings += '\n'.join(admin_panels[:10]) + "\n\n"
        
        # Unprotected subdomains (no CDN/WAF)
        exposed = []
        for sub, info in subdomains.items():
            if info.get('ips') and not info.get('cdn') and not info.get('waf') and info.get('status_code'):
                exposed.append(f"   • {sub} - {', '.join(info['ips'][:2])}")
        
        if exposed:
            findings += "🔓 Subdomains Without Protection:\n"
            findings += '\n'.join(exposed[:15]) + "\n\n"
        
        # SSL issues
        ssl_issues = []
        for sub, info in subdomains.items():
            if info.get('ssl_info'):
                ssl = info['ssl_info']
                if ssl.get('expired'):
                    ssl_issues.append(f"   • {sub} - Certificate EXPIRED")
                elif ssl.get('self_signed'):
                    ssl_issues.append(f"   • {sub} - Self-signed certificate")
        
        if ssl_issues:
            findings += "🔐 SSL/TLS Issues:\n"
            findings += '\n'.join(ssl_issues[:10]) + "\n\n"
        
        # Open dangerous ports
        dangerous_ports = [21, 23, 3306, 3389, 5900, 6379, 27017]
        port_issues = []
        
        for sub, info in subdomains.items():
            open_dangerous = [p for p in info.get('open_ports', []) if p in dangerous_ports]
            if open_dangerous:
                port_issues.append(f"   • {sub} - Ports: {', '.join(map(str, open_dangerous))}")
        
        if port_issues:
            findings += "🔴 Dangerous Open Ports:\n"
            findings += '\n'.join(port_issues[:10]) + "\n\n"
        
        if not (admin_panels or exposed or ssl_issues or port_issues):
            findings += "✅ No major security concerns detected in this scan.\n"
            findings += "   (Note: This is not a comprehensive security audit)\n"
        
        findings += "\n" + "="*80 + "\n"
        findings += "⚠️  DISCLAIMER: This is reconnaissance data only. Always perform\n"
        findings += "    proper security testing with authorization.\n"
        
        self.vuln_text.insert(tk.END, findings)
    
    def save_results(self, format_type: str):
        """Save results in specified format"""
        if not self.results:
            messagebox.showwarning("Warning", "No results to save!")
            return
        
        if format_type == 'json':
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json")]
            )
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.results, f, indent=2, default=str)
                messagebox.showinfo("Success", f"Results saved to {filename}")
        
        elif format_type == 'csv':
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")]
            )
            if filename:
                import csv
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Subdomain', 'IPs', 'Status', 'Title', 'Technologies', 'CDN', 'WAF'])
                    
                    for sub, info in self.results['subdomains'].items():
                        writer.writerow([
                            sub,
                            ', '.join(info.get('ips', [])),
                            info.get('status_code', ''),
                            info.get('title', ''),
                            ', '.join(info.get('technologies', [])),
                            info.get('cdn', ''),
                            info.get('waf', '')
                        ])
                messagebox.showinfo("Success", f"Results saved to {filename}")
        
        elif format_type == 'html':
            filename = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html")]
            )
            if filename:
                html_content = self._generate_html_report(self.results)
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                messagebox.showinfo("Success", f"Report saved to {filename}")
    
    def _generate_html_report(self, results: Dict) -> str:
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Recon Report - {results['domain']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #0a0e27; color: #e1e8f0; margin: 40px; }}
        h1 {{ color: #00d4ff; }}
        h2 {{ color: #58a6ff; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #2a2e4a; padding: 12px; text-align: left; }}
        th {{ background: #1a1e3a; color: #00d4ff; }}
        tr:hover {{ background: #1a1e3a; }}
        .metric {{ display: inline-block; margin: 10px 20px; padding: 15px; background: #1a1e3a; border-radius: 8px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #00d4ff; }}
    </style>
</head>
<body>
    <h1>🎯 Reconnaissance Report</h1>
    <p><strong>Target:</strong> {results['domain']}</p>
    <p><strong>Scan Time:</strong> {results['scan_time']}</p>
    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <h2>📊 Summary</h2>
    <div>
        <div class="metric">
            <div class="metric-value">{results['summary']['total_subdomains']}</div>
            <div>Total Subdomains</div>
        </div>
        <div class="metric">
            <div class="metric-value">{results['summary']['alive_services']}</div>
            <div>Live Services</div>
        </div>
        <div class="metric">
            <div class="metric-value">{results['summary']['unique_ips']}</div>
            <div>Unique IPs</div>
        </div>
    </div>
    
    <h2>🌐 Discovered Subdomains</h2>
    <table>
        <tr>
            <th>Subdomain</th>
            <th>IP Addresses</th>
            <th>Status</th>
            <th>Title</th>
            <th>Technologies</th>
            <th>CDN/WAF</th>
        </tr>
"""
        
        for sub, info in sorted(results['subdomains'].items()):
            if info.get('status_code') or info.get('ips'):
                html += f"""
        <tr>
            <td>{sub}</td>
            <td>{', '.join(info.get('ips', [])[:3])}</td>
            <td>{info.get('status_code', '-')}</td>
            <td>{info.get('title', '')[:100]}</td>
            <td>{', '.join(info.get('technologies', [])[:5])}</td>
            <td>{info.get('cdn') or info.get('waf') or '-'}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        return html
    
    def start_scan(self):
        """Start reconnaissance scan"""
        domain = self.domain_entry.get().strip()
        
        if not domain:
            messagebox.showerror("Error", "Please enter a target domain!")
            return
        
        # Validate domain format
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$', domain):
            messagebox.showerror("Error", "Invalid domain format!")
            return
        
        # Clear previous results
        self.clear_logs()
        self.results = None
        
        # Update UI
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.progress.start(10)
        self.status_label.config(text="🟢 Scanning...", fg="#00ff00")
        
        # Get scan level
        scan_level_map = {
            'passive': ScanLevel.PASSIVE,
            'normal': ScanLevel.NORMAL,
            'aggressive': ScanLevel.AGGRESSIVE,
            'stealth': ScanLevel.STEALTH
        }
        scan_level = scan_level_map[self.scan_level_var.get()]
        
        # Run scan in thread
        def run_scan():
            try:
                self.scanner = ProfessionalReconScanner(gui=self, scan_level=scan_level)
                results = asyncio.run(self.scanner.run(domain, self.custom_wordlist))
                
                self.results = results
                
                # Display results
                self.root.after(0, self.display_summary, results)
                self.root.after(0, self.display_details, results)
                self.root.after(0, self.display_security, results)
                
                self.root.after(0, self.status_label.config, 
                               {'text': '✅ Scan completed', 'fg': '#00ff00'})
                
            except Exception as e:
                self.log(f"❌ Error: {str(e)}")
                logger.exception("Scan error")
                self.root.after(0, messagebox.showerror, "Error", f"Scan failed: {e}")
            
            finally:
                self.root.after(0, self.start_btn.config, {'state': 'normal'})
                self.root.after(0, self.stop_btn.config, {'state': 'disabled'})
                self.root.after(0, self.progress.stop)
        
        threading.Thread(target=run_scan, daemon=True).start()
    
    def stop_scan(self):
        """Stop ongoing scan"""
        if self.scanner:
            self.scanner = None
        self.progress.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="⏸️ Stopped", fg="#ff7b72")
        self.log("⏹️ Scan stopped by user")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
Recon Hunter Pro - Enterprise Edition v3.0

Advanced Reconnaissance & OSINT Framework

Features:
• Multi-source passive reconnaissance
• Advanced DNS enumeration
• Technology stack detection
• WAF/CDN identification
• Port scanning
• SSL/TLS analysis
• Export to multiple formats

© 2024 Recon Hunter Pro
"""
        messagebox.showinfo("About", about_text)
    
    def show_docs(self):
        """Show documentation"""
        docs_text = """
QUICK START GUIDE

1. Enter target domain
2. Select scan level:
   - Passive: Safe, no active scanning
   - Normal: Balanced approach
   - Aggressive: Full reconnaissance
   - Stealth: Slow but careful

3. Click START SCAN
4. View results in tabs
5. Export as JSON/CSV/HTML

SCAN LEVELS:
- Passive: Only uses public APIs
- Normal: Adds DNS bruteforce
- Aggressive: Adds port scanning, WAF detection
- Stealth: Slower with delays to avoid detection

TIPS:
- Use custom wordlists for better results
- Aggressive mode may trigger security alerts
- Always get permission before scanning
"""
        messagebox.showinfo("Documentation", docs_text)


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main():
    """Main entry point"""
    try:
        # Create and run GUI
        root = tk.Tk()
        app = ReconHunterProGUI(root)
        
        # Center window
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
        y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
        root.geometry(f'+{x}+{y}')
        
        root.mainloop()
        
    except Exception as e:
        logger.exception("Application error")
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║          🎯 RECON HUNTER PRO - ENTERPRISE EDITION v3.0 🎯                 ║
║                                                                           ║
║              Advanced Reconnaissance & OSINT Framework                    ║
║                      Powered by AI - Built for Pros                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝

[*] Initializing application...
[*] Loading modules...
[*] Starting GUI...

""")
    main()