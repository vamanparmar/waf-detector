"""
Advanced WAF / IDS / IPS Detector  –  Backend v5.0
====================================================
Architecture
  • 8 parallel HTTP probes with distinct fingerprinting goals
  • 25-entry WAF signature database (headers / cookies / body / error-body / IP-ranges / ASN-org)
  • Weighted scoring with per-evidence-type caps to prevent single-signal dominance
  • Confidence formula: Bayesian-style normalised against max achievable score per signature
  • Technology stack fingerprinting (server software, frameworks, cloud providers)
  • Rate-limit detection (429 + Retry-After analysis)
  • Security-header posture grading (A+ through F)
  • Scan history (last 20 scans, in-memory)
  • Structured request logging
  • Input validation & safe URL normalisation
"""

from __future__ import annotations

import ipaddress
import logging
import random
import re
import socket
import ssl
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urlencode

import urllib3
from flask import Flask, request, jsonify, g
from flask_cors import CORS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("wafscanner")

# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION             = "5.0.0"
MIN_DETECTION_SCORE = 5          # minimum weighted score to report a detection
MAX_BODY_BYTES      = 50_000     # bytes of response body to scan per probe
PROBE_MAX_WORKERS   = 8
SCAN_HISTORY_MAX    = 20
BLOCK_CODES         = frozenset({403, 406, 412, 418, 429, 444, 451, 503})

# Per-evidence-type score caps (prevents one type from dominating)
WEIGHT_CAP = {
    "HEADER":     20,
    "COOKIE":     20,
    "BODY":       18,
    "BLOCK_BODY": 15,
    "IP_RANGE":    8,
    "ASN_ORG":     8,
}

# Security-header grading thresholds
SEC_GRADES = [(90,"A+"),(75,"A"),(60,"B"),(45,"C"),(30,"D"),(0,"F")]

# In-memory scan history
_scan_history: list[dict] = []

# ---------------------------------------------------------------------------
# HTTP probe headers
# ---------------------------------------------------------------------------
HEADERS_BROWSER: dict[str, str] = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-CH-UA":                 '"Chromium";v="124", "Google Chrome";v="124"',
    "Sec-CH-UA-Mobile":          "?0",
    "Sec-CH-UA-Platform":        '"Windows"',
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Cache-Control":             "max-age=0",
    "DNT":                       "1",
}
HEADERS_CURL:   dict[str, str] = {"User-Agent": "curl/8.7.1", "Accept": "*/*"}
HEADERS_WGET:   dict[str, str] = {"User-Agent": "Wget/1.21.4", "Accept": "*/*", "Connection": "Keep-Alive"}
HEADERS_NIKTO:  dict[str, str] = {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)", "Accept": "*/*"}
HEADERS_PYTHON: dict[str, str] = {"User-Agent": "python-requests/2.31.0", "Accept": "*/*", "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"}

# ---------------------------------------------------------------------------
# WAF / IDS / IPS Signature Database  (25 entries)
# ---------------------------------------------------------------------------
# Schema per entry:
#   color         : UI hex colour
#   icon          : emoji glyph
#   category      : short display category
#   description   : long description shown on expansion
#   headers       : { header_name_lower: (regex, weight) }
#   cookies       : { cookie_name_substr_lower: weight }
#   body_patterns : [ (regex, weight) … ]    — scanned across ALL probe bodies
#   error_body    : [ (regex, weight) … ]    — scanned ONLY on 4xx/5xx bodies (+1 bonus)
#   ip_ranges     : [ CIDR … ]
#   asn_orgs      : [ lowercase keyword … ]  matched in server/via + PTR
# ---------------------------------------------------------------------------

WAF_DB: dict[str, dict] = {

    "Cloudflare": {
        "color": "#F6821F", "icon": "☁️", "category": "CDN + WAF",
        "description": (
            "World's largest CDN and WAF (~30 % of all websites). Provides Layers 3/4/7 DDoS "
            "mitigation, bot management, OWASP rule-based filtering, Turnstile CAPTCHA, and "
            "Zero Trust access. cf-ray and __cf_bm / cf_clearance are authoritative identifiers."
        ),
        "headers": {
            "cf-ray":           (r"[0-9a-f]+-[A-Z]{3}",                          6),
            "cf-cache-status":  (r"(HIT|MISS|DYNAMIC|BYPASS|EXPIRED|REVALIDATED)",4),
            "cf-mitigated":     (r"challenge",                                    6),
            "cf-connecting-ip": (r"\d{1,3}(\.\d{1,3}){3}",                       4),
            "cf-ipcountry":     (r"[A-Z]{2}",                                    4),
            "cf-visitor":       (r"\{.*scheme",                                  4),
            "cf-request-id":    (r"[0-9a-f]+",                                   4),
            "server":           (r"^cloudflare$",                                 5),
            "nel":              (r"cloudflare",                                   3),
            "report-to":        (r"cloudflare",                                   3),
        },
        "cookies": {
            "__cf_bm": 6, "cf_clearance": 6, "_cfuvid": 5, "__cfduid": 4, "__cflb": 4,
        },
        "body_patterns": [
            (r"cloudflare ray id",               6),
            (r"ray id\s*:\s*[0-9a-f]{16}",      5),
            (r"attention required.*cloudflare",  6),
            (r"challenge-platform",              5),
            (r"jschl[_-]vc",                     4),
            (r"cf-spinner",                      3),
            (r"checking your browser",           3),
            (r"turnstile\.cloudflare\.com",      4),
        ],
        "error_body": [
            (r"error\s+1020", 5), (r"error\s+1015", 5),
            (r"error\s+1006", 5), (r"error\s+1012", 4),
        ],
        "ip_ranges": [
            "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
            "104.16.0.0/13",  "104.24.0.0/14",  "108.162.192.0/18",
            "131.0.72.0/22",  "141.101.64.0/18","162.158.0.0/15",
            "172.64.0.0/13",  "173.245.48.0/20","188.114.96.0/20",
            "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
        ],
        "asn_orgs": ["cloudflare"],
    },

    "AWS CloudFront + WAF": {
        "color": "#FF9900", "icon": "🟠", "category": "CDN + WAF",
        "description": (
            "Amazon CloudFront CDN with AWS WAF attached for OWASP rule sets, rate limiting, "
            "IP reputation lists, and managed rule groups. AWS Shield Standard/Advanced adds "
            "volumetric DDoS protection. x-amz-cf-id and x-cache: ... from cloudfront are "
            "definitive identifiers. AWSALB and aws-waf-token cookies are strong signals."
        ),
        "headers": {
            "x-amz-cf-id":      (r"[A-Za-z0-9_\-=]{50,}",           6),
            "x-amz-cf-pop":     (r"[A-Z]{3}[0-9]+-[A-Z]\d+",        5),
            "x-amzn-requestid": (r"[0-9a-f\-]{30,}",                 4),
            "x-amzn-trace-id":  (r"Root=.+",                         4),
            "via":              (r"\d\.\d cloudfront\.",              6),
            "x-cache":          (r"(Hit|Miss|Error) from cloudfront", 6),
            "server":           (r"AmazonS3|awselb|AWSELBAutoSca",   4),
        },
        "cookies": {
            "AWSALB": 6, "AWSALBCORS": 5, "AWSELB": 4, "aws-waf-token": 6,
        },
        "body_patterns": [
            (r"Generated by cloudfront",            4),
            (r"The request could not be satisfied", 3),
            (r"Request blocked\.",                  4),
        ],
        "error_body": [
            (r"403 ERROR.*The request could not be satisfied", 5),
            (r"Generated by cloudfront \(CloudFront\)",        4),
        ],
        "ip_ranges": [],
        "asn_orgs": ["amazon", "cloudfront"],
    },

    "Imperva / Incapsula": {
        "color": "#005DAA", "icon": "🔵", "category": "Enterprise WAF",
        "description": (
            "Imperva Cloud WAF (ex-Incapsula) is enterprise-grade, used in financial services, "
            "healthcare, and government. Features advanced bot mitigation, DDoS protection "
            "(3–8 Tbps), API security, and CDN. incap_ses and visid_incap cookies are "
            "strong unique identifiers; x-iinfo header has a distinct structured format."
        ),
        "headers": {
            "x-iinfo":           (r"\d+-\d+-\d+ \d+ [A-Z]",  6),
            "x-cdn":             (r"incapsula",                6),
            "x-siid":            (r".+",                      4),
            "x-check-cacheable": (r"(YES|NO)",                 3),
        },
        "cookies": {
            "incap_ses": 6, "visid_incap": 6, "nlbi_": 6, "reese84": 4, "___utmvc": 3,
        },
        "body_patterns": [
            (r"incapsula incident id",           6),
            (r"_Incapsula_Resource",             6),
            (r"/_incapsula_resource",            6),
            (r"request unsuccessful.*incapsula", 5),
            (r"powered by incapsula",            5),
            (r"imperva\.com",                   3),
        ],
        "error_body": [(r"Access Denied.*Incapsula", 5)],
        "ip_ranges": [],
        "asn_orgs": ["incapsula", "imperva"],
    },

    "Akamai Kona / Bot Manager": {
        "color": "#009BDE", "icon": "🌐", "category": "Enterprise CDN + WAF",
        "description": (
            "Akamai Kona Site Defender + Bot Manager runs on the world's largest CDN. Provides "
            "OWASP Top-10 protection, credential-stuffing defence, DDoS scrubbing, and API security. "
            "AkamaiGHost server header, akamai-grn request-ID, and ak_bmsc / _abck cookies are "
            "definitive identifiers. Used by banks, media, and government."
        ),
        "headers": {
            "server":                  (r"AkamaiGHost|akamainetstorage", 6),
            "akamai-grn":              (r"0x[0-9a-f]+",                  6),
            "x-akamai-transformed":    (r".+",                           5),
            "x-akamai-request-id":     (r"[0-9a-f]+",                    5),
            "x-akamai-ssl-client-sid": (r".+",                           4),
            "x-akamai-edgescape":      (r".+",                           4),
            "x-check-cacheable":       (r"(YES|NO)",                     2),
        },
        "cookies": {
            "ak_bmsc": 6, "bm_sz": 5, "bm_sv": 4, "_abck": 6, "b_user_id": 3,
        },
        "body_patterns": [
            (r"access denied.*akamai",              6),
            (r"reference #\d+\.\w+\.\d+",           5),
            (r"akamai technologies",                 4),
            (r"you don't have permission.*akamai",   5),
        ],
        "error_body": [(r"reference #", 3)],
        "ip_ranges": [],
        "asn_orgs": ["akamai"],
    },

    "Sucuri CloudProxy": {
        "color": "#3F6AB1", "icon": "🛡", "category": "Website WAF",
        "description": (
            "Sucuri CloudProxy is a reverse-proxy WAF+CDN protecting SMBs and WordPress sites "
            "from SQLi, XSS, RCE, and DDoS. server: sucuri/cloudproxy and x-sucuri-id are "
            "definitive identifiers. Sucuri was acquired by GoDaddy in 2017."
        ),
        "headers": {
            "server":         (r"sucuri/cloudproxy", 6),
            "x-sucuri-id":    (r"\d+",               6),
            "x-sucuri-cache": (r"(HIT|MISS)",        4),
            "x-sucuri-block": (r".+",                6),
        },
        "cookies": {"sucuri_cloudproxy_uuid": 6},
        "body_patterns": [
            (r"sucuri website firewall",   6),
            (r"access denied.*sucuri",     6),
            (r"website firewall.*sucuri",  6),
            (r"sucuri\.net",               4),
        ],
        "error_body": [],
        "ip_ranges": [
            "192.88.134.0/23","185.93.228.0/22","66.248.200.0/22","208.109.0.0/22",
        ],
        "asn_orgs": ["sucuri"],
    },

    "Fastly Next-Gen WAF": {
        "color": "#FF282D", "icon": "⚡", "category": "CDN + Next-Gen WAF",
        "description": (
            "Fastly's edge cloud uses Varnish-based caching with an integrated Next-Gen WAF "
            "(ex-Signal Sciences). Detection relies on via: varnish, x-served-by cache-PoP, "
            "x-timer, and x-fastly-request-id. The NGWAF uses ML-based anomaly detection in "
            "addition to rule matching."
        ),
        "headers": {
            "via":                  (r"\d\.\d varnish",             6),
            "x-served-by":          (r"cache-[a-z]{3}\d+-[A-Z]+",  6),
            "x-cache":              (r"(HIT|MISS)",                 3),
            "x-cache-hits":         (r"\d+",                        4),
            "fastly-restarts":      (r"\d+",                        5),
            "x-timer":              (r"S\d+\.\d+,VS\d+,VE\d+",     5),
            "x-fastly-request-id":  (r"[0-9a-f]{32}",              6),
            "surrogate-key":        (r".+",                         3),
        },
        "cookies": {"fastly-ff": 4},
        "body_patterns": [
            (r"fastly error",    4), (r"fastly\.com",   3),
            (r"signal sciences", 5), (r"varnish cache", 3),
        ],
        "error_body": [
            (r"request forbidden by administrative rules", 5),
            (r"Varnish cache server",                      3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["fastly"],
    },

    "F5 BIG-IP ASM / AWAF": {
        "color": "#C8102E", "icon": "🔴", "category": "Enterprise WAF / ADC",
        "description": (
            "F5 BIG-IP ASM and Advanced WAF are hardware/software ADC+WAF appliances used "
            "heavily in banking, healthcare, and government. BIGipServer cookie and x-wa-info "
            "header are highly specific. The TS* cookie family is a lower-confidence signal."
        ),
        "headers": {
            "server":          (r"big-?ip",  6),
            "x-wa-info":       (r".+",       6),
            "x-f5-server":     (r".+",       5),
            "x-f5-request-id": (r".+",       4),
            "x-cnection":      (r".+",       3),
        },
        "cookies": {
            "BIGipServer": 6, "F5_ST": 5, "F5_HT_shp": 4, "TS": 3, "TSd": 3,
        },
        "body_patterns": [
            (r"the requested url was rejected", 6),
            (r"your support id is",             6),
            (r"f5 networks",                    4),
            (r"application security manager",   4),
        ],
        "error_body": [(r"request rejected by the policy", 5)],
        "ip_ranges": [],
        "asn_orgs": ["f5 networks", "f5, inc"],
    },

    "ModSecurity + OWASP CRS": {
        "color": "#E94F37", "icon": "🔒", "category": "Open-Source WAF",
        "description": (
            "ModSecurity is the most deployed open-source WAF module, integrated into "
            "Apache/Nginx/IIS. Combined with the OWASP Core Rule Set (CRS v3/v4) it detects "
            "SQLi, XSS, RCE, and other OWASP Top-10 attacks. CRS rarely exposes its identity "
            "in production but leaks 406 Not Acceptable on some rule matches."
        ),
        "headers": {"server": (r"mod_?security", 6)},
        "cookies": {},
        "body_patterns": [
            (r"mod_?security",                           6),
            (r"this error was generated by mod_security", 6),
            (r"modsecurity",                             6),
            (r"not acceptable!",                         3),
        ],
        "error_body": [(r"406 not acceptable", 4), (r"not acceptable", 3)],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Barracuda WAF": {
        "color": "#CC0000", "icon": "🐟", "category": "Hardware / Cloud WAF",
        "description": (
            "Barracuda WAF is available as hardware, virtual, and cloud (Azure). Protects "
            "against OWASP Top-10, DDoS, bots, and data loss. x-barracuda-connect and "
            "BNI__BARRACUDA_LB_COOKIE are authoritative identifiers."
        ),
        "headers": {
            "server":                 (r"barracudahttp",  6),
            "x-barracuda-connect":    (r".+",             6),
            "x-barracuda-start-time": (r"\d+",            4),
            "x-barracuda-url":        (r"https?://",      5),
            "x-barracuda-ag":         (r".+",             4),
        },
        "cookies": {"barra_counter_session": 5, "BNI__BARRACUDA_LB_COOKIE": 6},
        "body_patterns": [(r"barracuda networks", 4), (r"bwaf/", 4)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["barracuda"],
    },

    "Nginx Rate-Limit / OpenResty WAF": {
        "color": "#009900", "icon": "⚙️", "category": "Reverse Proxy / IPS",
        "description": (
            "Nginx with limit_req/limit_conn, or OpenResty with lua-resty-waf / NAXSI. "
            "x-ratelimit-* headers and x-naxsi-sig are reliable indicators. Note: Nginx alone "
            "without WAF modules is low-confidence."
        ),
        "headers": {
            "x-ratelimit-limit":     (r"\d+",        5),
            "x-ratelimit-remaining": (r"\d+",        5),
            "x-ratelimit-reset":     (r"\d+",        4),
            "retry-after":           (r"\d+",        3),
            "x-naxsi-sig":           (r".+",         6),
            "server":                (r"openresty",  4),
        },
        "cookies": {},
        "body_patterns": [
            (r"openresty", 4), (r"lua-resty", 4),
            (r"rate limit exceeded", 4), (r"naxsi", 5),
        ],
        "error_body": [(r"rate limit exceeded", 4), (r"too many requests", 3)],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Azure Front Door + WAF": {
        "color": "#0078D4", "icon": "🔷", "category": "Cloud WAF / CDN",
        "description": (
            "Microsoft Azure Front Door with Azure WAF provides global load balancing, TLS offload, "
            "DDoS, and OWASP rule sets (Bot Manager, managed rules). Widely used in Microsoft-hosted "
            "SaaS workloads. x-azure-ref is the definitive unique request-ID header."
        ),
        "headers": {
            "x-azure-ref":       (r"[0-9A-Za-z+/]{60,}", 6),
            "x-azure-requestid": (r"[0-9a-f\-]{36}",      5),
            "x-ms-request-id":   (r"[0-9a-f\-]{36}",      4),
            "x-ms-ests-server":  (r".+",                   4),
            "x-fd-healthprobe":  (r"1",                    4),
            "server":            (r"AzureDirect|ECAcc|Microsoft-IIS", 4),
        },
        "cookies": {"ai_user": 3, "ai_session": 3},
        "body_patterns": [
            (r"azure front door", 5), (r"x-azure-ref", 4), (r"microsoft azure", 3),
        ],
        "error_body": [(r"This request is blocked", 4)],
        "ip_ranges": [],
        "asn_orgs": ["microsoft", "azure"],
    },

    "Alibaba Cloud WAF": {
        "color": "#FF6A00", "icon": "🧧", "category": "Cloud WAF",
        "description": (
            "Alibaba Cloud WAF (SCDN + WAF service) protects apps on Alibaba Cloud from web "
            "attacks, DDoS, and scrapers. Tengine (Alibaba's Nginx fork) is a reliable "
            "server-header indicator. eagleid is Alibaba CDN's unique request-ID header."
        ),
        "headers": {
            "server":                    (r"Tengine",              5),
            "via":                       (r"(alicdn|aliyun)",      5),
            "eagleid":                   (r"[0-9a-f]{20,}",        6),
            "x-swift-savetime":          (r"\d+",                  3),
            "x-swift-cachetime":         (r"\d+",                  3),
            "ali-swift-global-savetime": (r"\d+",                  3),
        },
        "cookies": {"aliyungf_tc": 5, "cna": 3},
        "body_patterns": [(r"alibaba cloud", 4), (r"aliyun", 3), (r"waf\.aliyun", 5)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["alibaba", "aliyun", "alicloud"],
    },

    "Fortinet FortiWeb": {
        "color": "#EE3124", "icon": "🏰", "category": "Enterprise WAF",
        "description": (
            "FortiWeb is a hardware/VM WAF from Fortinet offering ML-based threat detection, "
            "bot mitigation, API security, and Fortinet Security Fabric integration. Common "
            "in enterprise data-centres. FORTIWAFSID cookie is authoritative."
        ),
        "headers": {
            "server":        (r"fortiweb|fortigate",       6),
            "x-fn-clientip": (r"\d{1,3}(\.\d{1,3}){3}",  4),
            "x-fw-debug":    (r"\d",                       4),
        },
        "cookies": {"FORTIWAFSID": 6, "cookiesession1": 3},
        "body_patterns": [
            (r"fortiweb", 6), (r"fortigate", 4),
            (r"fortinet", 3), (r"blocked by fortiweb", 6),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["fortinet"],
    },

    "Wordfence (WordPress WAF)": {
        "color": "#2196F3", "icon": "🔐", "category": "CMS WAF",
        "description": (
            "Wordfence is the most popular WordPress WAF plugin (4 M+ installations). It "
            "operates at PHP application level, blocking malicious requests before WordPress "
            "processes them. 'Generated by Wordfence' block-page signature is unambiguous."
        ),
        "headers": {},
        "cookies": {"wfvt_": 5},
        "body_patterns": [
            (r"generated by wordfence",                           6),
            (r"your access to this site has been limited.*wordfence", 6),
            (r"wordfence\.com",                                   4),
        ],
        "error_body": [(r"generated by wordfence", 6)],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "DDoS-Guard": {
        "color": "#FF5500", "icon": "🛡️", "category": "DDoS Protection + WAF",
        "description": (
            "DDoS-Guard provides cloud DDoS mitigation and WAF. Identifiable by "
            "server: ddos-guard and __ddg* cookie family."
        ),
        "headers": {"server": (r"ddos-guard", 6)},
        "cookies": {"__ddg1": 6, "__ddg2": 6, "__ddgid": 5, "__ddgmark": 5},
        "body_patterns": [
            (r"ddos-guard", 6), (r"ddosguard", 6), (r"checking your browser.*ddos", 5),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["ddos-guard"],
    },

    "Reblaze": {
        "color": "#1A73E8", "icon": "🛡", "category": "Cloud WAF / WAAP",
        "description": (
            "Reblaze is a cloud-native WAAP with real-time bot mitigation, DDoS protection, "
            "API security, and deep traffic analytics. rbzid and rbzsessionid cookies are "
            "authoritative identifiers."
        ),
        "headers": {"x-reblaze-protecting": (r".+", 6)},
        "cookies": {"rbzid": 6, "rbzsessionid": 6},
        "body_patterns": [(r"reblaze", 6), (r"blocked by reblaze", 6)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["reblaze"],
    },

    "Radware AppWall": {
        "color": "#007DC5", "icon": "🌊", "category": "Enterprise WAF",
        "description": (
            "Radware AppWall is a PCI DSS 6.6-compliant WAF with positive-security-model "
            "protection against OWASP Top-10, zero-day, and API abuse. x-rdwr-pop header "
            "is authoritative."
        ),
        "headers": {
            "x-rdwr-pop":     (r".+", 6),
            "x-rdwr-request": (r".+", 5),
            "server":         (r"radware|alteon", 5),
        },
        "cookies": {"rdwr": 5},
        "body_patterns": [(r"radware", 4), (r"appwall", 5)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["radware"],
    },

    "Palo Alto Prisma / PAN-OS": {
        "color": "#FA582D", "icon": "🔥", "category": "NGFW / WAAP",
        "description": (
            "Palo Alto Prisma Cloud WAAS and PAN-OS NGFW with App-ID provide WAF-equivalent "
            "capabilities for containers, serverless, and on-prem. Detectable via x-pan-* "
            "headers and block-page body signatures."
        ),
        "headers": {
            "x-pan-requestid": (r".+", 6),
            "x-pan-userid":    (r".+", 5),
        },
        "cookies": {},
        "body_patterns": [(r"palo alto networks", 4), (r"pan-os", 3), (r"threat id", 3)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["palo alto networks"],
    },

    "Edgio (Limelight) WAF": {
        "color": "#6B3FBF", "icon": "🟣", "category": "CDN + WAF",
        "description": (
            "Edgio (ex-Limelight/Verizon Media EdgeCast) provides CDN + WAF. "
            "server: ECAcc/ECS and x-ec-custom-error are strong identifiers."
        ),
        "headers": {
            "x-ec-custom-error": (r".+",         6),
            "x-hw":              (r".+",         4),
            "server":            (r"ECAcc|^ECS$",5),
        },
        "cookies": {"EC_SESSIONID": 4},
        "body_patterns": [(r"edgecast", 4), (r"limelight", 4), (r"edgio", 4)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["edgio", "limelight", "edgecast"],
    },

    "StackPath / MaxCDN WAF": {
        "color": "#00B3A4", "icon": "📦", "category": "CDN + WAF",
        "description": (
            "StackPath (merged MaxCDN/NetDNA) provides CDN, WAF, and edge computing. "
            "Detectable via x-sp-* headers and block-page body."
        ),
        "headers": {
            "x-sp-gateway": (r".+", 5), "x-sp-url": (r".+", 5),
            "x-sp-status":  (r".+", 4), "server":   (r"StackPath|NetDNA", 5),
        },
        "cookies": {},
        "body_patterns": [(r"stackpath", 5), (r"maxcdn", 4), (r"netdna", 4)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["stackpath", "maxcdn"],
    },

    "BunnyCDN": {
        "color": "#F5A623", "icon": "🐰", "category": "CDN + Basic WAF",
        "description": (
            "BunnyCDN is a low-cost CDN with a basic WAF add-on. Identifiable via "
            "server: BunnyCDN and cdn-* headers."
        ),
        "headers": {
            "server":                 (r"BunnyCDN",   6),
            "cdn-pullzone":           (r"\d+",        5),
            "cdn-uid":                (r".+",         4),
            "cdn-requestid":          (r".+",         4),
            "cdn-requestcountrycode": (r"[A-Z]{2}",  4),
        },
        "cookies": {},
        "body_patterns": [(r"bunnycdn", 5), (r"bunny\.net", 5)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["bunnycdn", "bunny.net"],
    },

    "Google Cloud Armor": {
        "color": "#4285F4", "icon": "🔵", "category": "Cloud WAF / DDoS",
        "description": (
            "Google Cloud Armor is a WAF and DDoS protection service for workloads behind "
            "Google Cloud Load Balancing. Identifiable by via: 1.1 google and distinctive "
            "Google error pages. Supports OWASP rules, geo-blocking, and adaptive protection."
        ),
        "headers": {
            "via":    (r"1\.1 google",        6),
            "server": (r"^gws$|^GSE$|Google", 4),
            "x-goog-generated-at": (r".+",    4),
        },
        "cookies": {"SIDCC": 2, "NID": 2},
        "body_patterns": [
            (r"google cloud armor",   6),
            (r"your client does not have permission to get URL", 4),
            (r"that's an error",      3),
        ],
        "error_body": [(r"Error 403 \(Forbidden\)", 4)],
        "ip_ranges": [],
        "asn_orgs": ["google"],
    },

    "Wallarm WAF": {
        "color": "#7B2FBE", "icon": "🌐", "category": "Next-Gen WAF / WAAP",
        "description": (
            "Wallarm is a next-gen WAF/WAAP with ML-based detection for API and web attacks. "
            "Provides real-time threat intelligence, custom rules, and deep API discovery. "
            "x-wallarm-* headers are authoritative."
        ),
        "headers": {
            "x-wallarm-node-uuid":      (r"[0-9a-f\-]{36}", 6),
            "x-wallarm-attack-detected":(r".+",              6),
            "x-wallarm-blocking-time":  (r".+",              5),
        },
        "cookies": {},
        "body_patterns": [(r"wallarm", 6), (r"blocked by wallarm", 6)],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["wallarm"],
    },

    "HAProxy / Varnish Enterprise": {
        "color": "#3D9970", "icon": "⚖️", "category": "Load Balancer / IPS",
        "description": (
            "HAProxy with Modsecurity or Varnish Enterprise with VCL-based WAF rules. "
            "Detectable via x-varnish, x-haproxy-*, and via headers."
        ),
        "headers": {
            "x-varnish":        (r"\d+",           5),
            "x-varnish-hits":   (r"\d+",           4),
            "via":              (r"1\.1 varnish",   5),
            "x-haproxy-id":     (r".+",             5),
        },
        "cookies": {},
        "body_patterns": [(r"varnish", 3), (r"haproxy", 4)],
        "error_body": [(r"Varnish cache server", 4)],
        "ip_ranges": [],
        "asn_orgs": ["varnish software"],
    },
}

# ---------------------------------------------------------------------------
# URL / Host helpers
# ---------------------------------------------------------------------------

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    return raw

def get_hostname(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]

def random_segment(n: int = 18) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))

# ---------------------------------------------------------------------------
# HTTP probe helpers
# ---------------------------------------------------------------------------
import requests as _req

def _fetch(url: str, headers: dict, timeout: int,
           allow_redirects: bool = True, method: str = "GET") -> dict:
    t0 = time.monotonic()
    try:
        fn = getattr(_req, method.lower())
        r  = fn(url, headers=headers, timeout=timeout,
                allow_redirects=allow_redirects, verify=False)
        return {"ok": True, "r": r, "elapsed": round(time.monotonic() - t0, 4)}
    except _req.exceptions.Timeout:
        return {"ok": False, "r": None, "error": "Timeout",
                "elapsed": float(timeout)}
    except _req.exceptions.ConnectionError as e:
        return {"ok": False, "r": None, "error": f"ConnectionError: {str(e)[:80]}",
                "elapsed": round(time.monotonic() - t0, 4)}
    except Exception as e:
        return {"ok": False, "r": None, "error": str(e)[:120],
                "elapsed": round(time.monotonic() - t0, 4)}

# ── 8 probe functions ───────────────────────────────────────────────────────

def probe_browser(url: str) -> dict:
    """Chrome-like browser GET — primary intelligence probe."""
    return _fetch(url, HEADERS_BROWSER, 14)

def probe_attack(url: str) -> dict:
    """
    Multi-vector attack probe:
      – SQLi UNION + boolean-blind
      – Reflected XSS
      – Path traversal
      – Command injection
      – XML entity injection hint
      – Scanner User-Agent (triggers IDS signature matching)
    A WAF that blocks returns 403/406/429/503/412/418/444.
    """
    qs = urlencode({
        "id":    "1' UNION SELECT NULL,NULL,NULL-- -",
        "q":     "<script>alert(document.domain)</script>",
        "file":  "../../../../etc/passwd",
        "cmd":   ";id;cat+/etc/passwd;uname+-a",
        "input": '<?xml version="1.0"?><!DOCTYPE x[<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>',
        "debug": "true",
        "test":  "../../windows/win.ini",
    })
    attack_url = url.rstrip("/") + "/search?" + qs
    h = {**HEADERS_BROWSER,
         "User-Agent":      "sqlmap/1.8.2#stable (https://sqlmap.org)",
         "X-Forwarded-For": "127.0.0.1' OR 1=1--",
         "X-Real-IP":       "127.0.0.1",
         "Referer":         "https://evil.example.com/attack"}
    return _fetch(attack_url, h, 10, allow_redirects=False)

def probe_random_404(url: str) -> dict:
    """
    Randomised nonexistent path.
    WAFs inject detection cookies / headers even on 404s.
    Path is unique each scan to defeat whitelist caching.
    """
    rand = url.rstrip("/") + f"/{random_segment()}/{random_segment(8)}.php"
    return _fetch(rand, HEADERS_BROWSER, 8)

def probe_curl(url: str) -> dict:
    """curl UA — reveals WAFs that challenge non-browser user-agents."""
    return _fetch(url, HEADERS_CURL, 8)

def probe_nikto(url: str) -> dict:
    """Nikto scanner UA — triggers signature-based IDS/IPS rules."""
    return _fetch(url, HEADERS_NIKTO, 8, allow_redirects=False)

def probe_python(url: str) -> dict:
    """python-requests UA — detects WAFs blocking generic library UAs."""
    return _fetch(url, HEADERS_PYTHON, 8)

def probe_options(url: str) -> dict:
    """HTTP OPTIONS — reveals allowed methods and WAF-injected CORS/security headers."""
    return _fetch(url, HEADERS_BROWSER, 8, allow_redirects=False, method="OPTIONS")

def probe_head(url: str) -> dict:
    """
    HTTP HEAD — faster header fingerprint without full body download.
    Some WAFs respond differently to HEAD vs GET.
    """
    return _fetch(url, HEADERS_BROWSER, 8, allow_redirects=True, method="HEAD")

# ---------------------------------------------------------------------------
# Network intelligence
# ---------------------------------------------------------------------------

def resolve_dns(hostname: str) -> dict:
    info: dict = {"ipv4": None, "ipv6": None, "all_ips": [], "ptr": None, "error": None}
    try:
        for r in socket.getaddrinfo(hostname, None):
            ip = r[4][0]
            if ":" in ip:
                info["ipv6"] = info["ipv6"] or ip
            else:
                info["ipv4"] = info["ipv4"] or ip
            if ip not in info["all_ips"]:
                info["all_ips"].append(ip)
        if info["ipv4"]:
            try:
                info["ptr"] = socket.gethostbyaddr(info["ipv4"])[0]
            except Exception:
                pass
    except Exception as e:
        info["error"] = str(e)[:120]
    return info

def get_ssl_info(hostname: str, port: int = 443) -> dict:
    info: dict = {
        "valid": False, "tls_version": None, "cipher": None,
        "issuer": None, "issuer_cn": None, "subject": None,
        "expires": None, "not_before": None, "san": [], "serial": None, "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname,
        ) as s:
            cert = s.getpeercert()
            info.update({
                "valid":       True,
                "tls_version": s.version(),
                "cipher":      s.cipher()[0] if s.cipher() else None,
                "issuer":      dict(x[0] for x in cert.get("issuer", [])).get("organizationName","Unknown"),
                "issuer_cn":   dict(x[0] for x in cert.get("issuer", [])).get("commonName","Unknown"),
                "subject":     dict(x[0] for x in cert.get("subject",[])).get("commonName", hostname),
                "expires":     cert.get("notAfter","Unknown"),
                "not_before":  cert.get("notBefore","Unknown"),
                "serial":      str(cert.get("serialNumber","")),
                "san":         [s[1] for s in cert.get("subjectAltName",[]) if s[0]=="DNS"][:10],
            })
    except ssl.SSLCertVerificationError as e:
        info["error"] = f"Verification failed: {str(e)[:100]}"
    except Exception as e:
        info["error"] = str(e)[:100]
    return info

def ip_in_ranges(ip_str: str, ranges: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in ipaddress.ip_network(c, strict=False) for c in ranges)
    except Exception:
        return False

def ptr_cdn_hint(ptr: str | None) -> str | None:
    if not ptr:
        return None
    pl = ptr.lower()
    for key, name in {
        "cloudflare":"Cloudflare","cloudfront":"AWS CloudFront","akamai":"Akamai",
        "edgekey":"Akamai Edge","fastly":"Fastly","sucuri":"Sucuri",
        "incapsula":"Imperva","azure":"Microsoft Azure","msedge":"Azure",
        "edgecast":"Edgio","llnwd":"Edgio (Limelight)","stackpath":"StackPath",
        "bunnycdn":"BunnyCDN","ddos-guard":"DDoS-Guard","google":"Google Cloud",
    }.items():
        if key in pl:
            return name
    return None

# ---------------------------------------------------------------------------
# Technology stack fingerprinting
# ---------------------------------------------------------------------------
def fingerprint_technology(headers: dict[str,str], body_snippet: str) -> list[str]:
    techs: list[str] = []
    srv   = headers.get("server","").lower()
    pwr   = headers.get("x-powered-by","").lower()
    via   = headers.get("via","").lower()
    b     = body_snippet.lower()

    if re.search(r"nginx",      srv): techs.append("Nginx")
    if re.search(r"apache",     srv): techs.append("Apache")
    if re.search(r"microsoft-iis",srv): techs.append("Microsoft IIS")
    if re.search(r"litespeed",  srv): techs.append("LiteSpeed")
    if re.search(r"openresty",  srv): techs.append("OpenResty")
    if re.search(r"gunicorn",   srv): techs.append("Gunicorn (Python)")
    if re.search(r"uwsgi",      srv): techs.append("uWSGI (Python)")
    if re.search(r"caddy",      srv): techs.append("Caddy")
    if re.search(r"tengine",    srv): techs.append("Tengine (Alibaba Nginx)")
    if m := re.search(r"php/([\d.]+)", pwr): techs.append(f"PHP/{m.group(1)}")
    if re.search(r"asp\.net",   pwr): techs.append("ASP.NET")
    if re.search(r"express",    pwr): techs.append("Express.js")
    if re.search(r"next\.js",   pwr): techs.append("Next.js")
    if "1.1 google" in via:          techs.append("Google Cloud CDN")
    if "wp-content" in b or "wp-includes" in b: techs.append("WordPress")
    if "joomla"     in b:            techs.append("Joomla")
    if "drupal"     in b:            techs.append("Drupal")
    if "shopify"    in b:            techs.append("Shopify")
    if "squarespace" in b:           techs.append("Squarespace")
    if "wix.com"    in b:            techs.append("Wix")
    return list(dict.fromkeys(techs))

# ---------------------------------------------------------------------------
# Security header posture grading
# ---------------------------------------------------------------------------
_SEC_HEADERS = {
    "strict-transport-security":    "HSTS",
    "content-security-policy":      "CSP",
    "x-frame-options":              "X-Frame-Options",
    "x-content-type-options":       "X-Content-Type-Options",
    "x-xss-protection":             "X-XSS-Protection",
    "referrer-policy":              "Referrer-Policy",
    "permissions-policy":           "Permissions-Policy",
    "cross-origin-opener-policy":   "COOP",
    "cross-origin-resource-policy": "CORP",
    "cross-origin-embedder-policy": "COEP",
}

def grade_security_headers(headers: dict[str,str]) -> dict:
    present = {k for k in _SEC_HEADERS if k in headers}
    pct     = round(len(present) / len(_SEC_HEADERS) * 100)
    grade   = next(g for thr, g in SEC_GRADES if pct >= thr)
    return {
        "score":   pct,
        "grade":   grade,
        "present": [_SEC_HEADERS[k] for k in present],
        "missing": [_SEC_HEADERS[k] for k in _SEC_HEADERS if k not in headers],
    }

# ---------------------------------------------------------------------------
# Scoring engine
# ---------------------------------------------------------------------------
def _capped_total(evidence: list[dict]) -> int:
    by_type: dict[str,int] = {}
    for e in evidence:
        by_type[e["type"]] = by_type.get(e["type"], 0) + e["weight"]
    return sum(min(v, WEIGHT_CAP.get(k, v)) for k, v in by_type.items())

def score_waf(probes: dict[str,dict], sig: dict,
              all_bodies: list[str]) -> tuple[int, list[dict]]:
    evidence: list[dict] = []
    seen: set[tuple]     = set()

    def add(ev: dict) -> None:
        key = (ev["type"], ev["key"])
        if key not in seen:
            seen.add(key)
            evidence.append(ev)

    # 1. Headers + cookies — across all successful probes
    for probe in probes.values():
        if not probe.get("ok") or probe.get("r") is None:
            continue
        r    = probe["r"]
        hdrs = {k.lower(): v for k, v in r.headers.items()}

        for hdr, (pattern, weight) in sig["headers"].items():
            val = hdrs.get(hdr.lower(), "")
            if val and re.search(pattern, val, re.IGNORECASE):
                add({"type": "HEADER", "key": hdr, "value": val[:200], "weight": weight})

        for cname, weight in sig.get("cookies", {}).items():
            for c in r.cookies:
                if cname.lower() in c.name.lower():
                    add({"type": "COOKIE", "key": c.name, "value": "(present)", "weight": weight})
                    break

    # 2. Body patterns — scan across all bodies (deduplicated per pattern)
    matched_pats: set[str] = set()
    for body in all_bodies:
        for pattern, weight in sig.get("body_patterns", []):
            if pattern in matched_pats:
                continue
            if re.search(pattern, body, re.IGNORECASE):
                add({"type": "BODY", "key": pattern,
                     "value": "Pattern matched in response body", "weight": weight})
                matched_pats.add(pattern)

    # 3. Error-body patterns — only on 4xx/5xx responses (+1 bonus weight)
    for probe in probes.values():
        if not probe.get("ok") or probe.get("r") is None:
            continue
        if probe["r"].status_code < 400:
            continue
        body = (probe["r"].text or "")[:MAX_BODY_BYTES]
        for pattern, weight in sig.get("error_body", []):
            if ("BLOCK_BODY", pattern) in seen:
                continue
            if re.search(pattern, body, re.IGNORECASE):
                add({"type": "BLOCK_BODY", "key": pattern,
                     "value": "Block/error page body matched", "weight": weight + 1})

    return _capped_total(evidence), evidence

# ---------------------------------------------------------------------------
# Main detection engine
# ---------------------------------------------------------------------------
def detect_waf(url: str) -> dict:
    url      = normalize_url(url)
    hostname = get_hostname(url)
    t0       = time.monotonic()

    # ── Phase 1: 8 probes in parallel ─────────────────────────────────────────
    probe_map = {
        "browser": probe_browser,
        "attack":  probe_attack,
        "404":     probe_random_404,
        "curl":    probe_curl,
        "nikto":   probe_nikto,
        "python":  probe_python,
        "options": probe_options,
        "head":    probe_head,
    }
    probes: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=PROBE_MAX_WORKERS) as ex:
        fmap = {ex.submit(fn, url): name for name, fn in probe_map.items()}
        for fut in as_completed(fmap):
            probes[fmap[fut]] = fut.result()

    # ── Phase 2: DNS + SSL in parallel ────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=2) as ex:
        dns_fut = ex.submit(resolve_dns,  hostname)
        ssl_fut = ex.submit(get_ssl_info, hostname)
        dns_info = dns_fut.result()
        ssl_info = ssl_fut.result()

    # ── Ensure primary probe succeeded ────────────────────────────────────────
    primary = probes["browser"]
    if not primary.get("ok"):
        fallback = probe_browser(url.replace("https://", "http://", 1))
        if not fallback.get("ok"):
            return {"success": False, "url": url,
                    "error": f"Target unreachable: {primary.get('error','Unknown')}"}
        primary = fallback
        probes["browser"] = fallback

    pr      = primary["r"]
    ph      = {k.lower(): v for k, v in pr.headers.items()}

    # Collect all response bodies
    all_bodies: list[str] = [
        (p["r"].text or "")[:MAX_BODY_BYTES]
        for p in probes.values()
        if p.get("ok") and p.get("r") is not None
    ]

    # ── Phase 3: WAF scoring ──────────────────────────────────────────────────
    detections: list[dict] = []
    for waf_name, sig in WAF_DB.items():
        raw, evidence = score_waf(probes, sig, all_bodies)

        # IP-range check
        for ip in dns_info["all_ips"]:
            if ip_in_ranges(ip, sig.get("ip_ranges", [])):
                wt = WEIGHT_CAP["IP_RANGE"]
                evidence.append({"type": "IP_RANGE", "key": ip,
                                  "value": f"IP in {waf_name} network range", "weight": wt})
                raw += wt
                break

        # ASN / org keyword match (server, via, PTR)
        srv_v = ph.get("server","").lower()
        via_v = ph.get("via","").lower()
        ptr_v = (dns_info.get("ptr") or "").lower()
        for org in sig.get("asn_orgs", []):
            if org in srv_v or org in via_v or org in ptr_v:
                src = "PTR" if org in ptr_v else "via" if org in via_v else "server"
                evidence.append({"type": "ASN_ORG", "key": org,
                                  "value": f"'{org}' in {src}", "weight": WEIGHT_CAP["ASN_ORG"]})
                raw += WEIGHT_CAP["ASN_ORG"]
                break

        if raw < MIN_DETECTION_SCORE or not evidence:
            continue

        max_achievable = sum(WEIGHT_CAP.get(e["type"], e["weight"]) for e in evidence)
        confidence     = min(98, max(30, round(raw / max(max_achievable, 1) * 100)))

        detections.append({
            "name":        waf_name,
            "score":       raw,
            "confidence":  confidence,
            "evidence":    sorted(evidence, key=lambda e: -e["weight"]),
            "color":       sig["color"],
            "icon":        sig["icon"],
            "category":    sig["category"],
            "description": sig["description"],
        })

    detections.sort(key=lambda d: (-d["confidence"], -d["score"]))

    # ── Phase 4: Probe-level analysis ─────────────────────────────────────────
    def pstatus(name: str) -> int | None:
        p = probes.get(name, {})
        return p["r"].status_code if p.get("ok") and p.get("r") else None

    attack_s  = pstatus("attack")
    nikto_s   = pstatus("nikto")
    curl_s    = pstatus("curl")
    browser_s = pstatus("browser")

    attack_blocked     = bool(attack_s  in BLOCK_CODES)
    nikto_blocked      = bool(nikto_s   in BLOCK_CODES)
    ua_discrimination  = bool(curl_s in BLOCK_CODES and browser_s not in BLOCK_CODES)
    rate_limited       = bool(
        attack_s == 429 or
        "x-ratelimit-limit" in ph or
        "retry-after" in ph
    )

    # ── Phase 5: Notable headers ──────────────────────────────────────────────
    _NP = ("cf-","x-amz","x-cdn","x-akamai","x-sucuri","x-barracuda","x-f5",
           "x-iinfo","x-azure","x-reblaze","x-rdwr","x-pan-","x-sp-","cdn-",
           "eagleid","x-varnish","x-naxsi","x-wallarm","x-goog")
    _NE = frozenset({
        "server","via","x-powered-by","x-cache","x-frame-options","nel","report-to",
        "content-security-policy","strict-transport-security","x-xss-protection",
        "x-content-type-options","x-ratelimit-limit","x-ratelimit-remaining",
        "x-ratelimit-reset","retry-after","referrer-policy","permissions-policy",
        "x-served-by","x-timer","x-cache-hits","surrogate-key","x-request-id",
        "x-correlation-id","cross-origin-opener-policy","cross-origin-resource-policy",
        "cross-origin-embedder-policy",
    })
    notable = {k: v for k, v in ph.items() if k in _NE or k.startswith(_NP)}

    # ── Phase 6: Supplementary intelligence ──────────────────────────────────
    security    = grade_security_headers(ph)
    technologies= fingerprint_technology(ph, (pr.text or "")[:5000])
    cdn_hint    = ptr_cdn_hint(dns_info.get("ptr"))
    elapsed_ms  = round((time.monotonic() - t0) * 1000)

    result = {
        "success":           True,
        "version":           VERSION,
        "timestamp":         datetime.now(timezone.utc).isoformat(),
        "url":               url,
        "final_url":         str(pr.url),
        "hostname":          hostname,
        "elapsed_ms":        elapsed_ms,
        "status_code":       pr.status_code,
        "redirect_count":    len(pr.history),
        "server":            ph.get("server") or "—",
        "tls":               url.startswith("https"),
        "dns":               dns_info,
        "ssl":               ssl_info,
        "cdn_hint":          cdn_hint,
        "technologies":      technologies,
        "waf_detected":      bool(detections),
        "detections":        detections,
        "attack_blocked":    attack_blocked,
        "nikto_blocked":     nikto_blocked,
        "ua_discrimination": ua_discrimination,
        "rate_limited":      rate_limited,
        "retry_after":       ph.get("retry-after"),
        "probe_statuses":    {name: pstatus(name) for name in probe_map},
        "probes_ok":         {name: p.get("ok", False) for name, p in probes.items()},
        "notable_headers":   notable,
        "all_headers_count": len(ph),
        "security":          security,
    }

    _scan_history.append({
        "timestamp":    result["timestamp"],
        "url":          url,
        "hostname":     hostname,
        "waf_detected": result["waf_detected"],
        "detections":   [d["name"] for d in detections],
        "elapsed_ms":   elapsed_ms,
    })
    if len(_scan_history) > SCAN_HISTORY_MAX:
        _scan_history.pop(0)

    return result

# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------
@app.before_request
def _start_timer():
    g.t0 = time.monotonic()

@app.after_request
def _log_req(resp):
    if request.path.startswith("/api/"):
        ms = round((time.monotonic() - g.t0) * 1000)
        log.info("%s %s → %d  (%d ms)", request.method, request.path, resp.status_code, ms)
    return resp

@app.route("/api/detect", methods=["POST"])
def api_detect():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"success": False, "error": 'Body must contain {"url":"..."}'}), 400
    raw = str(data["url"]).strip()
    if not raw:
        return jsonify({"success": False, "error": "URL is empty."}), 400
    parsed = urlparse(normalize_url(raw))
    if not parsed.netloc or "." not in parsed.netloc:
        return jsonify({"success": False, "error": "Invalid URL — must be a valid domain."}), 400
    try:
        return jsonify(detect_waf(raw))
    except Exception as e:
        log.exception("Unhandled error in detect_waf")
        return jsonify({"success": False, "error": f"Internal error: {str(e)}"}), 500

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "ok", "version": VERSION,
        "db_entries": len(WAF_DB), "history": len(_scan_history),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

@app.route("/api/signatures", methods=["GET"])
def api_signatures():
    return jsonify({
        "count": len(WAF_DB),
        "signatures": [
            {"name": n, "category": s["category"], "icon": s["icon"], "color": s["color"]}
            for n, s in WAF_DB.items()
        ],
    })

@app.route("/api/history", methods=["GET"])
def api_history():
    return jsonify({"count": len(_scan_history), "history": list(reversed(_scan_history))})

@app.route("/api/history", methods=["DELETE"])
def api_history_clear():
    _scan_history.clear()
    return jsonify({"status": "cleared"})

@app.route("/", methods=["GET"])
def api_root():
    return jsonify({
        "name": "Advanced WAF / IDS / IPS Detector", "version": VERSION,
        "db": f"{len(WAF_DB)} signatures",
        "probes": list({
            "browser":"Chrome-like GET","attack":"SQLi/XSS/traversal payload",
            "404":"Random 404 path","curl":"curl UA","nikto":"Nikto scanner UA",
            "python":"python-requests UA","options":"HTTP OPTIONS","head":"HTTP HEAD",
        }.keys()),
        "endpoints": {
            "POST /api/detect":    "Scan a URL",
            "GET  /api/health":    "Health check",
            "GET  /api/signatures":"WAF signature list",
            "GET  /api/history":   "Scan history",
            "DELETE /api/history": "Clear history",
        },
    })

# ---------------------------------------------------------------------------
if __name__ == "__main__":
    bar = "=" * 64
    print(bar)
    print(f"  Advanced WAF / IDS / IPS Detector   v{VERSION}")
    print(f"  Signatures  : {len(WAF_DB)}")
    print(f"  Probes      : 8  (browser, attack, 404, curl, nikto, python, OPTIONS, HEAD)")
    print(f"  URL         : http://localhost:5000")
    print(bar)
    app.run(debug=True, port=5000, threaded=True, use_reloader=False)
