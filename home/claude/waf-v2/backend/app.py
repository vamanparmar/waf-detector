"""
Advanced WAF / IDS / IPS Detector — Backend
Author: Enhanced Professional Build
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import socket
import ssl
import re
import time
import json
import hashlib
import ipaddress
import random
import string
from urllib.parse import urlparse, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ─── Constants ────────────────────────────────────────────────────────────────

PROBE_TIMEOUT_NORMAL  = 14
PROBE_TIMEOUT_ATTACK  = 10
PROBE_TIMEOUT_FAST    = 8
MIN_DETECTION_SCORE   = 4
MAX_BODY_SCAN_BYTES   = 40000
VERSION               = "4.0.0"

# HTTP status codes that strongly indicate active WAF blocking
BLOCK_STATUS_CODES    = {403, 406, 429, 503, 412, 418, 444, 451}

# ─── Browser-like request headers ─────────────────────────────────────────────

HEADERS_BROWSER = {
    "User-Agent":                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language":           "en-US,en;q=0.9",
    "Accept-Encoding":           "gzip, deflate, br",
    "Connection":                "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest":            "document",
    "Sec-Fetch-Mode":            "navigate",
    "Sec-Fetch-Site":            "none",
    "Cache-Control":             "max-age=0",
    "DNT":                       "1",
}

HEADERS_CURL = {
    "User-Agent":    "curl/8.4.0",
    "Accept":        "*/*",
    "Connection":    "keep-alive",
}

HEADERS_SCANNER = {
    "User-Agent":    "Nikto/2.1.6",
    "Accept":        "*/*",
    "X-Scanner":     "true",
}

# ─── WAF Signature Database ────────────────────────────────────────────────────
# Schema per entry:
#   headers       : {header_name: (regex_pattern, weight)}
#   cookies       : {cookie_name_substr: weight}
#   body_patterns : [(regex_pattern, weight)]
#   error_body    : [(regex_pattern, weight)]   — scanned on non-2xx responses only
#   ip_ranges     : [CIDR strings]
#   asn_orgs      : [lowercase strings matched in server/via headers]

WAF_DB = {

    # ── Cloud / CDN WAFs ──────────────────────────────────────────────────────

    "Cloudflare": {
        "color":       "#F6821F",
        "icon":        "☁️",
        "category":    "CDN + WAF",
        "description": (
            "Cloudflare is the world's largest CDN and WAF, protecting over 30% of all websites. "
            "It provides DDoS mitigation, bot management, OWASP rule-based filtering, and Turnstile "
            "CAPTCHA challenges. Detection is high-confidence due to its distinctive headers and cookies."
        ),
        "headers": {
            "cf-ray":              (r".+",              5),
            "cf-cache-status":     (r".+",              3),
            "cf-request-id":       (r".+",              4),
            "cf-mitigated":        (r"challenge",       5),
            "cf-connecting-ip":    (r".+",              3),
            "cf-ipcountry":        (r".+",              3),
            "cf-visitor":          (r".+",              3),
            "server":              (r"^cloudflare$",    4),
            "x-frame-options":     (r".+",              1),
            "nel":                 (r"cloudflare",      3),
            "report-to":           (r"cloudflare",      2),
        },
        "cookies": {
            "__cfduid":    3,
            "cf_clearance":5,
            "__cf_bm":     5,
            "_cfuvid":     4,
            "__cflb":      4,
        },
        "body_patterns": [
            (r"cloudflare ray id",                 5),
            (r"cf-ray",                            3),
            (r"attention required.*cloudflare",    5),
            (r"checking your browser",             3),
            (r"please (stand by|wait)",            2),
            (r"enable javascript.*cookies",        2),
            (r"ray id\s*:\s*[0-9a-f]+",           4),
            (r"jschl[_-]vc",                       4),
            (r"cf-spinner",                        3),
            (r"challenge-platform",                4),
            (r"turnstile",                         3),
        ],
        "error_body": [
            (r"error\s+1020",  4),
            (r"error\s+1006",  4),
            (r"error\s+1015",  4),
            (r"error\s+1012",  3),
        ],
        "ip_ranges": [
            "103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
            "104.16.0.0/13","104.24.0.0/14","108.162.192.0/18",
            "131.0.72.0/22","141.101.64.0/18","162.158.0.0/15",
            "172.64.0.0/13","173.245.48.0/20","188.114.96.0/20",
            "190.93.240.0/20","197.234.240.0/22","198.41.128.0/17",
        ],
        "asn_orgs": ["cloudflare"],
    },

    "AWS CloudFront + Shield": {
        "color":       "#FF9900",
        "icon":        "🟠",
        "category":    "CDN + DDoS Protection",
        "description": (
            "Amazon CloudFront with AWS Shield Standard/Advanced provides DDoS mitigation and "
            "edge caching. AWS WAF can be attached for OWASP rule-based filtering, rate limiting, "
            "and managed rule groups."
        ),
        "headers": {
            "x-amz-cf-id":          (r".+",                              5),
            "x-amz-cf-pop":         (r".+",                              4),
            "x-amzn-requestid":     (r".+",                              4),
            "x-amzn-trace-id":      (r".+",                              3),
            "x-amz-rid":            (r".+",                              3),
            "via":                  (r"cloudfront",                      5),
            "x-cache":              (r"(hit|miss|error)\s+from\s+cloudfront", 5),
            "server":               (r"amazons3|awselb|awsalb|CloudFront",3),
            "x-amz-apigw-id":       (r".+",                              3),
        },
        "cookies": {
            "AWSALB":        5,
            "AWSALBCORS":    4,
            "AWSELB":        4,
            "AWSALBTG":      3,
            "aws-waf-token": 5,
        },
        "body_patterns": [
            (r"cloudfront\.net",        3),
            (r"aws\.amazon\.com",       2),
            (r"x-amz-cf-id",            3),
            (r"request blocked.*aws",   4),
            (r"generated by cloudfront",3),
        ],
        "error_body": [
            (r"403 error.*cloudfront",  4),
            (r"the request could not be satisfied", 3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["amazon", "aws", "cloudfront"],
    },

    "Imperva / Incapsula": {
        "color":       "#005DAA",
        "icon":        "🔵",
        "category":    "Enterprise WAF",
        "description": (
            "Imperva Cloud WAF (formerly Incapsula) is an enterprise-grade security platform with "
            "advanced bot mitigation, DDoS protection, API security, and CDN capabilities used "
            "by large financial and government organisations."
        ),
        "headers": {
            "x-iinfo":            (r".+",          5),
            "x-cdn":              (r"incapsula",   5),
            "x-check-cacheable":  (r".+",          3),
            "x-siid":             (r".+",          4),
            "x-request-id":       (r".+",          2),
        },
        "cookies": {
            "incap_ses":    5,
            "visid_incap":  5,
            "nlbi_":        5,
            "reese84":      4,
            "___utmvc":     3,
        },
        "body_patterns": [
            (r"incapsula incident id",               5),
            (r"_Incapsula_Resource",                 5),
            (r"/_incapsula_resource",                5),
            (r"incapsula\.com",                      4),
            (r"request unsuccessful.*incapsula",     5),
            (r"imperva\.com",                        3),
            (r"powered by incapsula",                4),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["incapsula", "imperva"],
    },

    "Akamai Kona / Bot Manager": {
        "color":       "#009BDE",
        "icon":        "🌐",
        "category":    "Enterprise CDN + WAF",
        "description": (
            "Akamai Kona Site Defender is an enterprise WAF integrated into the Akamai Intelligent "
            "Edge Platform. Combined with Bot Manager Premier, it defends against sophisticated bots, "
            "credential stuffing, and OWASP Top 10 attacks at massive scale."
        ),
        "headers": {
            "server":                   (r"akamaighost|akamainetstorage|AkamaiGHost", 5),
            "x-akamai-transformed":     (r".+",             5),
            "x-akamai-request-id":      (r".+",             4),
            "x-akamai-ssl-client-sid":  (r".+",             4),
            "akamai-grn":               (r".+",             5),
            "x-akamai-staging":         (r".+",             3),
            "x-akamai-edgescape":       (r".+",             3),
            "x-check-cacheable":        (r".+",             2),
            "x-serial":                 (r"\d+",            2),
        },
        "cookies": {
            "ak_bmsc":   5,
            "bm_sz":     5,
            "bm_sv":     4,
            "_abck":     5,
            "b_user_id": 3,
        },
        "body_patterns": [
            (r"reference #[\d.]+\w+",           4),
            (r"akamai",                         3),
            (r"access denied.*akamai",          5),
            (r"akamai technologies",            4),
            (r"you don't have permission.*akamai", 4),
        ],
        "error_body": [
            (r"you don't have permission to access", 3),
            (r"reference #",                         3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["akamai"],
    },

    "Sucuri CloudProxy": {
        "color":       "#3F6AB1",
        "icon":        "🛡",
        "category":    "Website WAF",
        "description": (
            "Sucuri CloudProxy is a website firewall and CDN that transparently proxies traffic "
            "to protect against SQLi, XSS, DDoS, brute-force, and malware injection. Widely used "
            "by SMBs and WordPress-based sites."
        ),
        "headers": {
            "server":         (r"sucuri/cloudproxy",    5),
            "x-sucuri-id":    (r".+",                   5),
            "x-sucuri-cache": (r".+",                   4),
            "x-sucuri-block": (r".+",                   5),
        },
        "cookies": {
            "sucuri_cloudproxy_uuid": 5,
        },
        "body_patterns": [
            (r"sucuri website firewall",              5),
            (r"access denied.*sucuri website firewall",5),
            (r"sucuri\.net",                          4),
            (r"website firewall.*sucuri",             5),
            (r"your ip\s+\d+\.\d+\.\d+\.\d+.*blocked",3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["sucuri"],
    },

    "Fastly Next-Gen WAF": {
        "color":       "#FF282D",
        "icon":        "⚡",
        "category":    "CDN + Next-Gen WAF",
        "description": (
            "Fastly provides an edge cloud platform with an integrated Next-Gen WAF (formerly Signal Sciences). "
            "It uses behavioral analysis and OWASP rules to detect and block malicious requests with "
            "low false-positive rates."
        ),
        "headers": {
            "via":              (r"varnish",      5),
            "x-served-by":      (r"cache-\w+",    5),
            "x-cache":          (r"HIT|MISS",     3),
            "x-cache-hits":     (r"\d+",          4),
            "fastly-restarts":  (r".+",           5),
            "x-timer":          (r"S\d+\.",        4),
            "x-fastly-request-id": (r".+",        5),
            "surrogate-key":    (r".+",            3),
        },
        "cookies": {
            "fastly-ff": 4,
        },
        "body_patterns": [
            (r"fastly error",       4),
            (r"varnish cache",      3),
            (r"fastly\.com",        3),
            (r"signal sciences",    4),
        ],
        "error_body": [
            (r"request forbidden by administrative rules", 4),
        ],
        "ip_ranges": [],
        "asn_orgs": ["fastly"],
    },

    "F5 BIG-IP ASM / AWAF": {
        "color":       "#C8102E",
        "icon":        "🔴",
        "category":    "Enterprise WAF / ADC",
        "description": (
            "F5 BIG-IP Application Security Manager (ASM) and Advanced WAF (AWAF) are hardware/software "
            "WAF solutions providing L7 protection, SSL offload, and load balancing. Common in large "
            "enterprise and financial sector deployments."
        ),
        "headers": {
            "server":          (r"big-?ip",       5),
            "x-wa-info":       (r".+",            5),
            "x-cnection":      (r".+",            3),
            "x-f5-server":     (r".+",            5),
            "x-f5-request-id": (r".+",            4),
        },
        "cookies": {
            "BIGipServer":  5,
            "F5_ST":        5,
            "F5_HT_shp":   4,
            "TS":           3,
            "TSd":          3,
        },
        "body_patterns": [
            (r"the requested url was rejected",  5),
            (r"your support id is",              5),
            (r"f5 networks",                     4),
            (r"bigip",                           3),
            (r"application security manager",    4),
        ],
        "error_body": [
            (r"request rejected by the policy",  4),
        ],
        "ip_ranges": [],
        "asn_orgs": ["f5 networks", "f5, inc"],
    },

    "ModSecurity + OWASP CRS": {
        "color":       "#E94F37",
        "icon":        "🔒",
        "category":    "Open-Source WAF",
        "description": (
            "ModSecurity is the most widely deployed open-source WAF module, used with Apache, Nginx "
            "and IIS. When combined with the OWASP Core Rule Set (CRS), it detects SQLi, XSS, command "
            "injection, and other OWASP Top 10 attacks."
        ),
        "headers": {
            "server": (r"mod_?security", 5),
        },
        "cookies": {},
        "body_patterns": [
            (r"mod_?security",                          5),
            (r"not acceptable!",                        3),
            (r"406 not acceptable",                     3),
            (r"this error was generated by mod_security",5),
            (r"modsecurity",                            5),
        ],
        "error_body": [
            (r"406 not acceptable",  3),
            (r"not acceptable",      2),
        ],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Barracuda WAF": {
        "color":       "#CC0000",
        "icon":        "🐟",
        "category":    "Hardware / Cloud WAF",
        "description": (
            "Barracuda Web Application Firewall protects against OWASP Top 10, DDoS, bots, and "
            "data loss. Available as hardware appliance or cloud service with adaptive profiling."
        ),
        "headers": {
            "server":                  (r"barracudahttp",    5),
            "x-barracuda-connect":     (r".+",              5),
            "x-barracuda-start-time":  (r".+",              4),
            "x-barracuda-url":         (r".+",              5),
            "x-barracuda-ag":          (r".+",              4),
        },
        "cookies": {
            "barra_counter_session":    4,
            "BNI__BARRACUDA_LB_COOKIE": 5,
        },
        "body_patterns": [
            (r"barracuda.networks",   4),
            (r"bwaf/",               4),
            (r"barracuda networks",  3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["barracuda"],
    },

    "Nginx + Rate Limit / OpenResty": {
        "color":       "#009900",
        "icon":        "⚙️",
        "category":    "Reverse Proxy / IPS",
        "description": (
            "Nginx acting as a reverse proxy with built-in rate limiting, or OpenResty with WAF "
            "modules (lua-resty-waf, naxsi). Detectable via rate-limit headers and OpenResty "
            "server signature."
        ),
        "headers": {
            "server":                  (r"^nginx",          2),
            "x-ratelimit-limit":       (r".+",              4),
            "x-ratelimit-remaining":   (r".+",              4),
            "x-ratelimit-reset":       (r".+",              3),
            "retry-after":             (r".+",              3),
            "x-naxsi-sig":             (r".+",              5),
        },
        "cookies": {},
        "body_patterns": [
            (r"openresty",              4),
            (r"lua-resty",             3),
            (r"rate limit exceeded",   3),
            (r"naxsi",                 4),
        ],
        "error_body": [
            (r"rate limit exceeded",   3),
            (r"too many requests",     2),
        ],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Alibaba Cloud WAF": {
        "color":       "#FF6A00",
        "icon":        "🧧",
        "category":    "Cloud WAF",
        "description": (
            "Alibaba Cloud WAF (formerly SCDN) provides protection against common web attacks and "
            "DDoS. Widely used in APAC and China-based deployments, identifiable by Tengine/CDN "
            "headers and aliyun cookies."
        ),
        "headers": {
            "server":             (r"tenginx|tengine",   4),
            "via":                (r"alicdn|aliyun",     5),
            "x-swift-savetime":   (r".+",                3),
            "x-swift-cachetime":  (r".+",                3),
            "eagleid":            (r".+",                5),
            "x-cache":            (r"alibaba|aliyun",    4),
        },
        "cookies": {
            "aliyungf_tc": 5,
            "cna":         3,
        },
        "body_patterns": [
            (r"aliyun",          3),
            (r"alicdn",          4),
            (r"alibaba cloud",   4),
            (r"waf.aliyun",      5),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["alibaba", "aliyun", "alicloud"],
    },

    "Azure Front Door / WAF": {
        "color":       "#0078D4",
        "icon":        "🔷",
        "category":    "Cloud WAF / CDN",
        "description": (
            "Microsoft Azure Front Door with Azure WAF provides DDoS protection, SSL offload, "
            "URL-based routing, and OWASP rule sets. Used extensively in Microsoft Azure-hosted workloads."
        ),
        "headers": {
            "x-azure-ref":                   (r".+",             5),
            "x-azure-requestid":             (r".+",             4),
            "x-ms-request-id":               (r".+",             3),
            "x-ms-ests-server":              (r".+",             4),
            "x-fd-healthprobe":              (r".+",             3),
            "x-cache":                       (r"tcp.*microsoft", 4),
            "server":                        (r"AzureDirect|ECAcc", 4),
        },
        "cookies": {
            "ai_user":      3,
            "ai_session":   3,
        },
        "body_patterns": [
            (r"microsoft azure",             3),
            (r"azure front door",            5),
            (r"x-azure-ref",                 4),
            (r"error.*azure",                3),
        ],
        "error_body": [
            (r"this request is blocked",     4),
        ],
        "ip_ranges": [],
        "asn_orgs": ["microsoft", "azure"],
    },

    "Cloudfront / Edgio (Limelight)": {
        "color":       "#6B3FBF",
        "icon":        "🟣",
        "category":    "CDN + WAF",
        "description": (
            "Edgio (formerly Limelight Networks / Verizon Media) provides a CDN with an integrated "
            "WAF. Detectable via EC headers and specific cookie patterns."
        ),
        "headers": {
            "x-ec-custom-error":  (r".+",              5),
            "x-hw":               (r".+",              4),
            "x-check-cacheable":  (r".+",              3),
            "server":             (r"ECAcc|ECS",       4),
            "x-cache":            (r"HIT|MISS|TCP",    3),
        },
        "cookies": {
            "EC_SESSIONID": 4,
        },
        "body_patterns": [
            (r"edgecast",          4),
            (r"limelight",         4),
            (r"verizon media",     3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["edgio", "limelight", "edgecast"],
    },

    "Fortinet FortiWeb": {
        "color":       "#EE3124",
        "icon":        "🏰",
        "category":    "Enterprise WAF",
        "description": (
            "Fortinet FortiWeb is a hardware/VM WAF that provides ML-based threat detection, "
            "bot mitigation, and API security. Common in enterprise and government environments."
        ),
        "headers": {
            "server":                (r"fortiweb|fortigate", 5),
            "x-fn-clientip":         (r".+",                4),
            "x-fw-debug":            (r".+",                4),
            "x-forwarded-by":        (r"fortiweb",          5),
        },
        "cookies": {
            "FORTIWAFSID":  5,
            "cookiesession1": 3,
        },
        "body_patterns": [
            (r"fortiweb",            5),
            (r"fortigate",           3),
            (r"fortinet",            3),
            (r"blocked by fortiweb", 5),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["fortinet"],
    },

    "Wordfence (WordPress WAF)": {
        "color":       "#2196F3",
        "icon":        "🔐",
        "category":    "CMS WAF",
        "description": (
            "Wordfence Security is the most popular WordPress WAF plugin. It operates at the "
            "application layer and blocks malicious requests before WordPress processes them. "
            "Detectable by its specific HTML block page signature."
        ),
        "headers": {},
        "cookies": {
            "wfvt_": 4,
        },
        "body_patterns": [
            (r"generated by wordfence",              5),
            (r"wordfence",                           4),
            (r"your access to this site has been limited.*wordfence", 5),
            (r"blocked.*wordfence",                  5),
        ],
        "error_body": [
            (r"generated by wordfence",              5),
        ],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Palo Alto Prisma Cloud / PAN-OS": {
        "color":       "#FA582D",
        "icon":        "🔥",
        "category":    "NGFW / WAF",
        "description": (
            "Palo Alto Networks Next-Generation Firewall with app-ID and threat prevention "
            "provides WAF-like capabilities. Prisma Cloud WAAS is a cloud-native WAF for "
            "containers and serverless."
        ),
        "headers": {
            "x-pan-requestid":  (r".+",              5),
            "x-pan-userid":     (r".+",              4),
        },
        "cookies": {
            "SESSID": 1,
        },
        "body_patterns": [
            (r"palo alto networks",        4),
            (r"threat id",                 3),
            (r"application threat",        3),
            (r"pan-os",                    3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["palo alto networks"],
    },

    "Radware AppWall": {
        "color":       "#007DC5",
        "icon":        "🌊",
        "category":    "Enterprise WAF",
        "description": (
            "Radware AppWall is a PCI-compliant WAF providing patented, positive-security "
            "protection against OWASP Top 10 and zero-day application attacks in hardware "
            "and cloud deployments."
        ),
        "headers": {
            "x-rdwr-pop":      (r".+",   5),
            "x-rdwr-request":  (r".+",   5),
            "server":          (r"radware|alteon", 4),
        },
        "cookies": {
            "rdwr": 4,
        },
        "body_patterns": [
            (r"radware",         4),
            (r"appwall",         5),
            (r"web blocked",     3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["radware"],
    },

    "DDoS-Guard": {
        "color":       "#FF5500",
        "icon":        "🛡️",
        "category":    "DDoS Protection",
        "description": (
            "DDoS-Guard provides cloud-based DDoS protection and content delivery with "
            "WAF capabilities. Popular with hosting providers in Eastern Europe and Russia."
        ),
        "headers": {
            "server":      (r"ddos-guard", 5),
        },
        "cookies": {
            "__ddg1":  5,
            "__ddg2":  5,
            "__ddgid": 4,
            "__ddgmark": 4,
        },
        "body_patterns": [
            (r"ddos-guard",        5),
            (r"ddosguard",         5),
            (r"checking your browser.*ddos", 4),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["ddos-guard"],
    },

    "Reblaze": {
        "color":       "#1A73E8",
        "icon":        "🔵",
        "category":    "Cloud WAF",
        "description": (
            "Reblaze is a cloud-native WAF with real-time traffic analytics, bot mitigation, "
            "DDoS protection, and API security. Deployed as reverse proxy in front of web apps."
        ),
        "headers": {
            "x-reblaze-protecting": (r".+", 5),
        },
        "cookies": {
            "rbzid":  5,
            "rbzsessionid": 5,
        },
        "body_patterns": [
            (r"reblaze",        5),
            (r"blocked by reblaze", 5),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": ["reblaze"],
    },

    "AWS API Gateway WAF": {
        "color": "#B0620D",
        "icon": "🔑",
        "category": "API Gateway + WAF",
        "description": (
            "Amazon API Gateway with AWS WAF provides rate limiting, API key enforcement, "
            "and OWASP-based request filtering for REST/HTTP/WebSocket APIs hosted in AWS."
        ),
        "headers": {
            "x-amzn-requestid":   (r".+",             4),
            "x-amzn-errortype":   (r".+",             4),
            "x-amzn-trace-id":    (r".+",             4),
            "apigw-requestid":    (r".+",             5),
        },
        "cookies": {
            "aws-waf-token": 5,
        },
        "body_patterns": [
            (r"forbidden.*api gateway",        4),
            (r"\"message\"\s*:\s*\"forbidden\"",3),
        ],
        "error_body": [],
        "ip_ranges": [],
        "asn_orgs": [],
    },
}

# ─── URL / Host Helpers ────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def get_hostname(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]

def random_path_segment(length: int = 16) -> str:
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

# ─── Multi-Probe Fetchers ──────────────────────────────────────────────────────

def probe_normal(url: str, timeout: int = PROBE_TIMEOUT_NORMAL) -> dict:
    """Standard browser-like GET — primary intelligence probe."""
    try:
        t = time.time()
        r = requests.get(
            url, headers=HEADERS_BROWSER, timeout=timeout,
            allow_redirects=True, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "normal"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "normal"}


def probe_attack_like(url: str, timeout: int = PROBE_TIMEOUT_ATTACK) -> dict:
    """
    Multi-vector attack simulation:
      - SQLi (classic UNION, boolean-blind, error-based)
      - XSS (inline + encoded)
      - Path traversal
      - Command injection markers
      - Scanner user-agent
    WAFs with active blocking return 403/406/429/503.
    """
    # Composite payload in query string and body
    sqli   = "' OR '1'='1'-- -"
    xss    = "<script>alert(document.domain)</script>"
    trav   = "../../../../etc/passwd"
    cmdinj = ";id;whoami;uname+-a"

    attack_qs = urlencode({
        "id":    sqli,
        "q":     xss,
        "file":  trav,
        "cmd":   cmdinj,
        "debug": "1",
    })
    attack_url = url.rstrip("/") + f"/search?{attack_qs}"

    h = {**HEADERS_BROWSER}
    h["User-Agent"]        = "sqlmap/1.7.8 (https://sqlmap.org)"
    h["X-Forwarded-For"]   = "127.0.0.1"
    h["X-Real-IP"]         = "127.0.0.1"
    h["X-Originating-IP"]  = "127.0.0.1"
    h["Referer"]           = "https://scanner.internal/"

    try:
        t = time.time()
        r = requests.get(
            attack_url, headers=h, timeout=timeout,
            allow_redirects=False, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "attack"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "attack"}


def probe_random_path(url: str, timeout: int = PROBE_TIMEOUT_FAST) -> dict:
    """
    Request a guaranteed-nonexistent path.
    WAFs often inject block pages or fingerprint cookies even on 404s.
    """
    rand_url = url.rstrip("/") + f"/{random_path_segment()}/probe-{random_path_segment(8)}.php"
    try:
        t = time.time()
        r = requests.get(
            rand_url, headers=HEADERS_BROWSER, timeout=timeout,
            allow_redirects=True, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "404"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "404"}


def probe_curl_agent(url: str, timeout: int = PROBE_TIMEOUT_FAST) -> dict:
    """
    Curl / bot user-agent probe.
    Some WAFs challenge or block non-browser agents.
    """
    try:
        t = time.time()
        r = requests.get(
            url, headers=HEADERS_CURL, timeout=timeout,
            allow_redirects=True, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "curl"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "curl"}


def probe_scanner_agent(url: str, timeout: int = PROBE_TIMEOUT_FAST) -> dict:
    """
    Known scanner user-agent (Nikto).
    IDS/IPS systems that inspect User-Agent strings often block this.
    """
    try:
        t = time.time()
        r = requests.get(
            url, headers=HEADERS_SCANNER, timeout=timeout,
            allow_redirects=False, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "scanner"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "scanner"}


def probe_options_method(url: str, timeout: int = PROBE_TIMEOUT_FAST) -> dict:
    """
    HTTP OPTIONS method probe.
    Can reveal allowed methods and WAF-injected Access-Control headers.
    """
    try:
        t = time.time()
        r = requests.options(
            url, headers=HEADERS_BROWSER, timeout=timeout,
            allow_redirects=False, verify=False,
        )
        return {"ok": True, "r": r, "elapsed": round(time.time() - t, 4), "probe": "options"}
    except Exception as e:
        return {"ok": False, "error": str(e), "r": None, "probe": "options"}


# ─── Network Intelligence ──────────────────────────────────────────────────────

def resolve_dns(hostname: str) -> dict:
    info = {"ipv4": None, "ipv6": None, "all_ips": [], "error": None, "ptr": None}
    try:
        results = socket.getaddrinfo(hostname, None)
        for r in results:
            ip = r[4][0]
            if ":" in ip:
                if not info["ipv6"]:
                    info["ipv6"] = ip
            else:
                if not info["ipv4"]:
                    info["ipv4"] = ip
            if ip not in info["all_ips"]:
                info["all_ips"].append(ip)
        # Attempt reverse DNS on primary IPv4
        if info["ipv4"]:
            try:
                ptr = socket.gethostbyaddr(info["ipv4"])
                info["ptr"] = ptr[0]
            except Exception:
                pass
    except Exception as e:
        info["error"] = str(e)
    return info


def get_ssl_info(hostname: str, port: int = 443) -> dict:
    info = {
        "valid": False, "issuer": None, "issuer_cn": None,
        "subject": None, "expires": None, "not_before": None,
        "san": [], "serial": None, "version": None, "error": None,
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, port), timeout=8),
            server_hostname=hostname,
        ) as s:
            cert = s.getpeercert()
            info["valid"]      = True
            info["version"]    = s.version()
            issuer_dict        = dict(x[0] for x in cert.get("issuer", []))
            info["issuer"]     = issuer_dict.get("organizationName", "Unknown")
            info["issuer_cn"]  = issuer_dict.get("commonName", "Unknown")
            subject_dict       = dict(x[0] for x in cert.get("subject", []))
            info["subject"]    = subject_dict.get("commonName", hostname)
            info["expires"]    = cert.get("notAfter", "Unknown")
            info["not_before"] = cert.get("notBefore", "Unknown")
            sans               = cert.get("subjectAltName", [])
            info["san"]        = [s[1] for s in sans if s[0] == "DNS"][:10]
            info["serial"]     = str(cert.get("serialNumber", ""))
    except ssl.SSLCertVerificationError as e:
        info["error"] = f"Cert verification failed: {e}"
    except Exception as e:
        info["error"] = str(e)
    return info


def ip_in_cidr(ip_str: str, cidr_list: list) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidr_list:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except Exception:
        pass
    return False


def detect_cdn_ptr(ptr: str | None) -> str | None:
    """Map reverse-DNS hostname to a recognisable CDN/provider name."""
    if not ptr:
        return None
    ptr_lower = ptr.lower()
    mapping = {
        "cloudflare": "Cloudflare",
        "akamai":     "Akamai",
        "fastly":     "Fastly",
        "cloudfront": "AWS CloudFront",
        "amazon":     "Amazon",
        "azure":      "Microsoft Azure",
        "sucuri":     "Sucuri",
        "incapsula":  "Imperva Incapsula",
        "edgecast":   "Edgio",
        "llnwd":      "Edgio (Limelight)",
    }
    for key, name in mapping.items():
        if key in ptr_lower:
            return name
    return None


# ─── Scoring Engine ────────────────────────────────────────────────────────────

def score_response(response, waf_name: str, sig: dict, all_bodies: list) -> tuple[int, list]:
    """
    Score a single HTTP response against a WAF signature.
    Returns (total_score, evidence_list).
    """
    evidence = []
    score    = 0
    resp_headers = {k.lower(): v for k, v in response.headers.items()}
    is_error = response.status_code >= 400

    # 1. Header matching
    for hdr, (pattern, weight) in sig["headers"].items():
        val = resp_headers.get(hdr.lower(), "")
        if val and re.search(pattern, val, re.IGNORECASE):
            evidence.append({
                "type": "HEADER", "key": hdr,
                "value": val[:200], "weight": weight,
            })
            score += weight

    # 2. Cookie matching
    for cookie_name, weight in sig.get("cookies", {}).items():
        for c in response.cookies:
            if cookie_name.lower() in c.name.lower():
                evidence.append({
                    "type": "COOKIE", "key": c.name,
                    "value": "(present)", "weight": weight,
                })
                score += weight
                break

    # 3. Body pattern matching (across all probe bodies)
    already_matched_patterns = set()
    for body in all_bodies:
        for pattern, weight in sig.get("body_patterns", []):
            if pattern in already_matched_patterns:
                continue
            if re.search(pattern, body, re.IGNORECASE):
                evidence.append({
                    "type": "BODY", "key": pattern,
                    "value": "Pattern matched in response body", "weight": weight,
                })
                score += weight
                already_matched_patterns.add(pattern)

    # 4. Error-specific body patterns (only on non-2xx)
    if is_error:
        for pattern, weight in sig.get("error_body", []):
            if pattern in already_matched_patterns:
                continue
            for body in all_bodies:
                if re.search(pattern, body, re.IGNORECASE):
                    evidence.append({
                        "type": "BLOCK_BODY", "key": pattern,
                        "value": "Block/error body pattern matched", "weight": weight + 1,
                    })
                    score += weight + 1
                    already_matched_patterns.add(pattern)
                    break

    return score, evidence


# ─── Main Detection Engine ─────────────────────────────────────────────────────

def detect_waf(url: str) -> dict:
    url      = normalize_url(url)
    hostname = get_hostname(url)
    start_ts = time.time()

    # ── Phase 1: Parallel HTTP probes ─────────────────────────────────────────
    probe_tasks = {
        "normal":  (probe_normal,        url),
        "attack":  (probe_attack_like,   url),
        "404":     (probe_random_path,   url),
        "curl":    (probe_curl_agent,    url),
        "scanner": (probe_scanner_agent, url),
        "options": (probe_options_method,url),
    }
    probes: dict = {}
    with ThreadPoolExecutor(max_workers=6) as ex:
        futures = {ex.submit(fn, arg): key for key, (fn, arg) in probe_tasks.items()}
        for f in as_completed(futures):
            probes[futures[f]] = f.result()

    # ── Phase 2: DNS + SSL (parallel) ─────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=2) as ex:
        dns_f = ex.submit(resolve_dns,  hostname)
        ssl_f = ex.submit(get_ssl_info, hostname)
        dns_info = dns_f.result()
        ssl_info = ssl_f.result()

    # ── Primary probe must succeed; fall back to HTTP ──────────────────────────
    normal = probes.get("normal", {})
    if not normal.get("ok"):
        http_url = url.replace("https://", "http://")
        normal   = probe_normal(http_url)
        if not normal.get("ok"):
            return {
                "success": False, "url": url,
                "error": f"Cannot reach target: {normal.get('error', 'Unknown error')}",
            }

    primary_response = normal["r"]
    primary_headers  = {k.lower(): v for k, v in primary_response.headers.items()}

    # Collect bodies from all successful probes
    all_bodies: list[str] = []
    for p in probes.values():
        if p.get("ok") and p.get("r") is not None:
            text = p["r"].text or ""
            all_bodies.append(text[:MAX_BODY_SCAN_BYTES])

    # ── Phase 3: WAF Scoring ───────────────────────────────────────────────────
    detections = []
    for waf_name, sig in WAF_DB.items():
        total_score  = 0
        all_evidence = []

        for p in probes.values():
            if not p.get("ok") or p.get("r") is None:
                continue
            s, ev = score_response(p["r"], waf_name, sig, all_bodies)
            total_score += s
            for e in ev:
                if not any(x["key"] == e["key"] and x["type"] == e["type"] for x in all_evidence):
                    all_evidence.append(e)

        # IP range check against primary IPv4
        for ip in dns_info["all_ips"]:
            if ip_in_cidr(ip, sig.get("ip_ranges", [])):
                all_evidence.append({
                    "type":   "IP_RANGE",
                    "key":    ip,
                    "value":  f"IP belongs to {waf_name} network range",
                    "weight": 6,
                })
                total_score += 6
                break

        # ASN/org match via server + via headers
        server_val = primary_headers.get("server", "").lower()
        via_val    = primary_headers.get("via", "").lower()
        ptr_val    = (dns_info.get("ptr") or "").lower()
        for org_str in sig.get("asn_orgs", []):
            org_lower = org_str.lower()
            if org_lower in server_val or org_lower in via_val or org_lower in ptr_val:
                all_evidence.append({
                    "type":   "ASN_ORG",
                    "key":    "org_match",
                    "value":  f"'{org_str}' found in server/via/PTR",
                    "weight": 4,
                })
                total_score += 4

        if total_score >= MIN_DETECTION_SCORE and all_evidence:
            max_possible = sum(e["weight"] for e in all_evidence) + 4
            confidence   = min(98, max(30, int((total_score / max(max_possible, 1)) * 100)))
            detections.append({
                "name":        waf_name,
                "score":       total_score,
                "confidence":  confidence,
                "evidence":    sorted(all_evidence, key=lambda x: -x["weight"]),
                "color":       sig["color"],
                "icon":        sig["icon"],
                "category":    sig["category"],
                "description": sig["description"],
            })

    detections.sort(key=lambda x: -x["score"])

    # ── Phase 4: Attack probe analysis ────────────────────────────────────────
    attack_probe  = probes.get("attack", {})
    attack_status = None
    attack_blocked = False
    if attack_probe.get("ok") and attack_probe.get("r") is not None:
        attack_status  = attack_probe["r"].status_code
        attack_blocked = attack_status in BLOCK_STATUS_CODES

    # Scanner probe analysis (IDS/IPS indicator)
    scanner_probe   = probes.get("scanner", {})
    scanner_blocked = False
    scanner_status  = None
    if scanner_probe.get("ok") and scanner_probe.get("r") is not None:
        scanner_status  = scanner_probe["r"].status_code
        scanner_blocked = scanner_status in BLOCK_STATUS_CODES

    # Curl vs browser delta (behaviour difference signals WAF)
    curl_probe   = probes.get("curl", {})
    curl_status  = None
    curl_diff    = False
    if curl_probe.get("ok") and curl_probe.get("r") is not None:
        curl_status = curl_probe["r"].status_code
        curl_diff   = (curl_status != primary_response.status_code)

    # ── Phase 5: Notable headers ──────────────────────────────────────────────
    notable_prefixes = [
        "cf-", "x-amz", "x-cdn", "x-akamai", "x-sucuri",
        "x-barracuda", "x-f5", "x-iinfo", "x-azure",
        "x-reblaze", "x-rdwr", "x-pan-",
    ]
    notable_exact = {
        "server", "via", "x-powered-by", "x-cache", "x-frame-options",
        "content-security-policy", "strict-transport-security", "x-xss-protection",
        "x-content-type-options", "x-ratelimit-limit", "x-ratelimit-remaining",
        "x-ratelimit-reset", "retry-after", "x-request-id", "eagleid",
        "x-served-by", "x-timer", "x-cache-hits", "surrogate-key",
        "nel", "report-to",
    }
    notable_headers = {}
    for k, v in primary_headers.items():
        if k in notable_exact or any(k.startswith(p) for p in notable_prefixes):
            notable_headers[k] = v

    # Security posture score (0–100)
    security_headers = {
        "strict-transport-security", "content-security-policy", "x-frame-options",
        "x-content-type-options", "x-xss-protection", "referrer-policy",
        "permissions-policy",
    }
    present_sec = sum(1 for h in security_headers if h in primary_headers)
    security_score = round((present_sec / len(security_headers)) * 100)

    elapsed_ms = int((time.time() - start_ts) * 1000)

    # CDN hint from PTR record
    cdn_hint = detect_cdn_ptr(dns_info.get("ptr"))

    return {
        "success":             True,
        "version":             VERSION,
        "timestamp":           datetime.utcnow().isoformat() + "Z",
        "url":                 url,
        "final_url":           str(primary_response.url),
        "hostname":            hostname,
        "dns":                 dns_info,
        "ssl":                 ssl_info,
        "status_code":         primary_response.status_code,
        "elapsed_ms":          elapsed_ms,
        "redirect_count":      len(primary_response.history),
        "server":              primary_headers.get("server", "—"),
        "tls":                 url.startswith("https"),
        "waf_detected":        len(detections) > 0,
        "detections":          detections,
        "attack_probe_status": attack_status,
        "attack_blocked":      attack_blocked,
        "scanner_probe_status":scanner_status,
        "scanner_blocked":     scanner_blocked,
        "curl_status":         curl_status,
        "curl_diff":           curl_diff,
        "probes_ok":           {k: v.get("ok", False) for k, v in probes.items()},
        "probe_statuses":      {
            k: v["r"].status_code if v.get("ok") and v.get("r") is not None else None
            for k, v in probes.items()
        },
        "notable_headers":     notable_headers,
        "all_headers_count":   len(primary_headers),
        "security_score":      security_score,
        "cdn_hint":            cdn_hint,
    }


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({"success": False, "error": "Request body must contain a 'url' field."}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"success": False, "error": "URL cannot be empty."}), 400
    # Basic sanity check
    parsed = urlparse(normalize_url(url))
    if not parsed.netloc:
        return jsonify({"success": False, "error": "Invalid URL format."}), 400
    return jsonify(detect_waf(url))


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status":  "ok",
        "version": VERSION,
        "waf_db_size": len(WAF_DB),
        "timestamp": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/api/signatures", methods=["GET"])
def signatures():
    """Return list of all supported WAF signatures (no regex details)."""
    sigs = [
        {
            "name":     name,
            "category": sig["category"],
            "icon":     sig["icon"],
            "color":    sig["color"],
        }
        for name, sig in WAF_DB.items()
    ]
    return jsonify({"count": len(sigs), "signatures": sigs})


@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "name":    "Advanced WAF / IDS / IPS Detector API",
        "version": VERSION,
        "endpoints": {
            "POST /api/detect":     "Detect WAF/IDS/IPS for a URL",
            "GET  /api/health":     "Health check",
            "GET  /api/signatures": "List supported WAF signatures",
        },
    })


if __name__ == "__main__":
    print("=" * 60)
    print(f"  Advanced WAF / IDS / IPS Detector  v{VERSION}")
    print(f"  Signatures loaded : {len(WAF_DB)}")
    print(f"  Running on        : http://localhost:5000")
    print(f"  Open index.html in your browser")
    print("=" * 60)
    app.run(debug=True, port=5000, threaded=True)
