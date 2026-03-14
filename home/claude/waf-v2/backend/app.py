from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import socket
import ssl
import re
import time
import json
import ipaddress
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ─── WAF Signature Database ───────────────────────────────────────────────────
# Each entry: headers (dict of header→patterns), cookies (list), body_patterns,
# status_codes (trigger on specific error codes), ip_ranges (CIDR blocks),
# asn_orgs (strings to match in ASN org name), weight per evidence type

WAF_DB = {
    "Cloudflare": {
        "color": "#F6821F",
        "icon": "☁️",
        "category": "CDN + WAF",
        "description": "Cloudflare is the world's most widely used WAF and CDN. It operates at the DNS/HTTP layer and provides DDoS mitigation, bot management, and rule-based filtering.",
        "headers": {
            "cf-ray":              (r".+",          4),
            "cf-cache-status":     (r".+",          3),
            "cf-request-id":       (r".+",          3),
            "cf-mitigated":        (r".+",          4),
            "cf-connecting-ip":    (r".+",          2),
            "server":              (r"^cloudflare$",3),
            "x-frame-options":     (r".+",          1),
        },
        "cookies": {
            "__cfduid":   3,
            "cf_clearance": 4,
            "__cf_bm":    4,
            "_cfuvid":    3,
        },
        "body_patterns": [
            (r"cloudflare ray id",        4),
            (r"cf-ray",                   3),
            (r"attention required.*cloudflare", 4),
            (r"checking your browser",    3),
            (r"please (stand by|wait)",   2),
            (r"enable javascript.*cookies",2),
            (r"ray id:",                  3),
        ],
        "error_body": [
            (r"1020",  3),  # Access Denied
            (r"1006",  3),  # Access Denied
            (r"1015",  3),  # Rate limited
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

    "AWS Shield / CloudFront": {
        "color": "#FF9900",
        "icon": "🟠",
        "category": "CDN + DDoS Protection",
        "description": "Amazon CloudFront with AWS Shield provides DDoS protection and edge caching. AWS WAF can be attached for rule-based filtering.",
        "headers": {
            "x-amz-cf-id":        (r".+",          4),
            "x-amz-cf-pop":       (r".+",          4),
            "x-amzn-requestid":   (r".+",          3),
            "x-amz-rid":          (r".+",          3),
            "via":                (r"cloudfront",  4),
            "x-cache":            (r"(hit|miss) from cloudfront", 4),
            "server":             (r"amazons3|awselb|awsalb", 2),
        },
        "cookies": {
            "AWSALB":     4,
            "AWSALBCORS": 3,
            "AWSELB":     3,
        },
        "body_patterns": [
            (r"cloudfront\.net",  3),
            (r"aws\.amazon\.com", 2),
            (r"x-amz-cf-id",      3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["amazon", "aws"],
    },

    "Imperva Incapsula": {
        "color": "#005DAA",
        "icon": "🔵",
        "category": "Enterprise WAF",
        "description": "Imperva Incapsula is an enterprise-grade cloud WAF with bot mitigation, DDoS protection, and CDN capabilities.",
        "headers": {
            "x-iinfo":            (r".+",          4),
            "x-cdn":              (r"incapsula",   5),
            "x-check-cacheable":  (r".+",          2),
            "x-powered-by-plesk": (r".+",          1),
        },
        "cookies": {
            "incap_ses":    5,
            "visid_incap":  5,
            "nlbi_":        4,
            "reese84":      3,
        },
        "body_patterns": [
            (r"incapsula incident id",     5),
            (r"_Incapsula_Resource",       5),
            (r"/_incapsula_resource",      5),
            (r"incapsula\.com",            3),
            (r"request unsuccessful.*incapsula", 4),
        ],
        "ip_ranges": [],
        "asn_orgs": ["incapsula", "imperva"],
    },

    "Akamai": {
        "color": "#009BDE",
        "icon": "🌐",
        "category": "Enterprise CDN + WAF",
        "description": "Akamai Kona Site Defender is an enterprise WAF integrated into the Akamai Intelligent Edge Platform with advanced bot and DDoS protection.",
        "headers": {
            "server":                  (r"akamaighost|akamainetstorage", 5),
            "x-akamai-transformed":    (r".+",          4),
            "x-akamai-request-id":     (r".+",          4),
            "x-akamai-ssl-client-sid": (r".+",          3),
            "akamai-grn":              (r".+",          4),
            "x-check-cacheable":       (r".+",          2),
            "x-akamai-staging":        (r".+",          3),
        },
        "cookies": {
            "ak_bmsc":  5,
            "bm_sz":    4,
            "bm_sv":    4,
            "_abck":    4,
        },
        "body_patterns": [
            (r"reference #\d+\.\w+\.\w+",  4),
            (r"akamai",                    3),
            (r"access denied.*akamai",     5),
        ],
        "ip_ranges": [],
        "asn_orgs": ["akamai"],
    },

    "Sucuri": {
        "color": "#3F6AB1",
        "icon": "🛡",
        "category": "Website WAF",
        "description": "Sucuri CloudProxy is a website firewall and CDN that protects against SQLi, XSS, DDoS, and brute-force attacks.",
        "headers": {
            "server":         (r"sucuri/cloudproxy", 5),
            "x-sucuri-id":    (r".+",                5),
            "x-sucuri-cache": (r".+",                4),
        },
        "cookies": {},
        "body_patterns": [
            (r"sucuri website firewall",              5),
            (r"access denied.*sucuri website firewall", 5),
            (r"sucuri\.net",                          3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["sucuri"],
    },

    "Fastly": {
        "color": "#FF282D",
        "icon": "⚡",
        "category": "CDN + WAF",
        "description": "Fastly is an edge cloud platform with WAF capabilities powered by the OWASP ModSecurity ruleset.",
        "headers": {
            "via":              (r"varnish",      4),
            "x-served-by":      (r"cache-\w+",    4),
            "x-cache":          (r"HIT|MISS",     3),
            "x-cache-hits":     (r"\d+",          3),
            "fastly-restarts":  (r".+",           4),
            "x-timer":          (r"S\d+\.",       3),
        },
        "cookies": {},
        "body_patterns": [
            (r"fastly error",   4),
            (r"varnish cache",  3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["fastly"],
    },

    "F5 BIG-IP ASM": {
        "color": "#C8102E",
        "icon": "🔴",
        "category": "Enterprise WAF / ADC",
        "description": "F5 BIG-IP Application Security Manager is a hardware/software WAF providing L7 protection, SSL offload, and load balancing.",
        "headers": {
            "server":         (r"big-?ip",  5),
            "x-wa-info":      (r".+",       4),
            "x-cnection":     (r".+",       3),
            "x-f5-server":    (r".+",       4),
        },
        "cookies": {
            "BIGipServer": 5,
            "F5_ST":       4,
            "F5_HT_shp":   4,
            "TS":          2,
        },
        "body_patterns": [
            (r"the requested url was rejected", 4),
            (r"your support id is",             4),
            (r"f5 networks",                    3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["f5 networks"],
    },

    "ModSecurity": {
        "color": "#E94F37",
        "icon": "🔒",
        "category": "Open-source WAF",
        "description": "ModSecurity is the most widely deployed open-source WAF, commonly used with Apache/Nginx/IIS using OWASP Core Rule Set.",
        "headers": {
            "server": (r"mod_?security", 5),
        },
        "cookies": {},
        "body_patterns": [
            (r"mod_?security",          5),
            (r"not acceptable!",        3),
            (r"406 not acceptable",     3),
            (r"this error was generated by mod_security", 5),
        ],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Barracuda WAF": {
        "color": "#CC0000",
        "icon": "🐟",
        "category": "Hardware / Cloud WAF",
        "description": "Barracuda Web Application Firewall protects against OWASP Top 10, DDoS, bots, and data loss.",
        "headers": {
            "server":                  (r"barracudahttp", 5),
            "x-barracuda-connect":     (r".+",            4),
            "x-barracuda-start-time":  (r".+",            4),
            "x-barracuda-url":         (r".+",            4),
        },
        "cookies": {
            "barra_counter_session": 4,
            "BNI__BARRACUDA_LB_COOKIE": 4,
        },
        "body_patterns": [
            (r"barracuda.networks", 4),
            (r"bwaf/",             3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["barracuda"],
    },

    "Nginx + Rate Limit": {
        "color": "#009900",
        "icon": "⚙️",
        "category": "Reverse Proxy / IPS",
        "description": "Nginx acting as a reverse proxy with built-in rate limiting or OpenResty with WAF rules (e.g., lua-resty-waf).",
        "headers": {
            "server":           (r"^nginx",  2),
            "x-ratelimit-limit":(r".+",      4),
            "x-ratelimit-remaining":(r".+",  4),
            "retry-after":      (r".+",      3),
        },
        "cookies": {},
        "body_patterns": [
            (r"openresty",        3),
            (r"lua-resty",        3),
            (r"rate limit exceeded",3),
        ],
        "ip_ranges": [],
        "asn_orgs": [],
    },

    "Alibaba Cloud WAF": {
        "color": "#FF6A00",
        "icon": "🧧",
        "category": "Cloud WAF",
        "description": "Alibaba Cloud WAF provides protection for web applications against common web attacks and DDoS.",
        "headers": {
            "server":          (r"tenginx|tengine", 3),
            "via":             (r"alicdn|aliyun",   4),
            "x-swift-savetime":(r".+",              3),
            "x-swift-cachetime":(r".+",             3),
            "eagleid":         (r".+",              4),
        },
        "cookies": {
            "aliyungf_tc": 4,
            "XSRF-TOKEN":  1,
        },
        "body_patterns": [
            (r"aliyun",       3),
            (r"alicdn",       3),
            (r"alibaba cloud",3),
        ],
        "ip_ranges": [],
        "asn_orgs": ["alibaba", "aliyun"],
    },
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def get_hostname(url: str) -> str:
    return urlparse(url).netloc.split(":")[0]

HEADERS_PROBE = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Cache-Control": "max-age=0",
}

# ─── Multi-Probe Fetcher ──────────────────────────────────────────────────────

def probe_normal(url, timeout=12):
    """Standard browser-like GET"""
    try:
        t = time.time()
        r = requests.get(url, headers=HEADERS_PROBE, timeout=timeout,
                         allow_redirects=True, verify=False)
        return {"ok": True, "r": r, "elapsed": round(time.time()-t, 3), "probe": "normal"}
    except Exception as e:
        return {"ok": False, "error": str(e), "probe": "normal"}

def probe_attack_like(url, timeout=8):
    """Send a crafted request that WAFs commonly block — helps confirm presence"""
    attack_url = url.rstrip("/") + "/?id=1'+OR+'1'='1&cmd=<script>alert(1)</script>"
    h = dict(HEADERS_PROBE)
    h["X-Forwarded-For"] = "127.0.0.1"
    h["X-Real-IP"] = "127.0.0.1"
    try:
        t = time.time()
        r = requests.get(attack_url, headers=h, timeout=timeout,
                         allow_redirects=False, verify=False)
        return {"ok": True, "r": r, "elapsed": round(time.time()-t, 3), "probe": "attack"}
    except Exception as e:
        return {"ok": False, "error": str(e), "probe": "attack"}

def probe_random_path(url, timeout=8):
    """404 path — WAFs often inject themselves on 404 pages"""
    rand_url = url.rstrip("/") + "/waf-probe-nonexistent-path-12345"
    try:
        t = time.time()
        r = requests.get(rand_url, headers=HEADERS_PROBE, timeout=timeout,
                         allow_redirects=True, verify=False)
        return {"ok": True, "r": r, "elapsed": round(time.time()-t, 3), "probe": "404"}
    except Exception as e:
        return {"ok": False, "error": str(e), "probe": "404"}

# ─── Network Info ─────────────────────────────────────────────────────────────

def resolve_dns(hostname):
    info = {"ipv4": None, "ipv6": None, "all_ips": [], "error": None}
    try:
        results = socket.getaddrinfo(hostname, None)
        for r in results:
            ip = r[4][0]
            if ":" in ip:
                if not info["ipv6"]: info["ipv6"] = ip
            else:
                if not info["ipv4"]: info["ipv4"] = ip
            if ip not in info["all_ips"]:
                info["all_ips"].append(ip)
    except Exception as e:
        info["error"] = str(e)
    return info

def get_ssl_info(hostname, port=443):
    info = {"valid": False, "issuer": None, "subject": None,
            "expires": None, "san": [], "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, port), timeout=6),
                              server_hostname=hostname) as s:
            cert = s.getpeercert()
            info["valid"] = True
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            info["issuer"] = issuer_dict.get("organizationName", "Unknown")
            subject_dict = dict(x[0] for x in cert.get("subject", []))
            info["subject"] = subject_dict.get("commonName", hostname)
            info["expires"] = cert.get("notAfter", "Unknown")
            sans = cert.get("subjectAltName", [])
            info["san"] = [s[1] for s in sans if s[0] == "DNS"][:8]
    except Exception as e:
        info["error"] = str(e)
    return info

def ip_in_cidr(ip_str, cidr_list):
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in cidr_list:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
    except Exception:
        pass
    return False

# ─── Scoring Engine ───────────────────────────────────────────────────────────

def score_response(response, waf_name, sig, all_probes_bodies):
    evidence = []
    score = 0

    resp_headers = {k.lower(): v for k, v in response.headers.items()}

    # 1. Header matching
    for hdr, (pattern, weight) in sig["headers"].items():
        val = resp_headers.get(hdr.lower(), "")
        if val and re.search(pattern, val, re.IGNORECASE):
            evidence.append({
                "type": "HEADER", "key": hdr,
                "value": val[:150], "weight": weight
            })
            score += weight

    # 2. Cookie matching
    for cookie_name, weight in sig["cookies"].items():
        for c in response.cookies:
            if cookie_name.lower() in c.name.lower():
                evidence.append({
                    "type": "COOKIE", "key": c.name,
                    "value": "(present)", "weight": weight
                })
                score += weight
                break

    # 3. Body pattern matching (across all probes)
    for body in all_probes_bodies:
        for pattern, weight in sig["body_patterns"]:
            if re.search(pattern, body, re.IGNORECASE):
                evidence.append({
                    "type": "BODY", "key": pattern,
                    "value": "Pattern matched in response body", "weight": weight
                })
                score += weight
                break  # one match per pattern

    return score, evidence


def detect_waf(url: str):
    url = normalize_url(url)
    hostname = get_hostname(url)

    # ── Parallel probes ──────────────────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(probe_normal, url):       "normal",
            ex.submit(probe_attack_like, url):  "attack",
            ex.submit(probe_random_path, url):  "404",
        }
        probes = {}
        for f in as_completed(futures):
            key = futures[f]
            probes[key] = f.result()

    # ── DNS + SSL (parallel) ─────────────────────────────────────────────────
    with ThreadPoolExecutor(max_workers=2) as ex:
        dns_future = ex.submit(resolve_dns, hostname)
        ssl_future = ex.submit(get_ssl_info, hostname)
        dns_info = dns_future.result()
        ssl_info = ssl_future.result()

    # Primary probe must succeed
    normal = probes.get("normal", {})
    if not normal.get("ok"):
        # Try HTTP fallback
        http_url = url.replace("https://", "http://")
        normal = probe_normal(http_url)
        if not normal.get("ok"):
            return {"success": False, "url": url,
                    "error": f"Cannot reach target: {normal.get('error','Unknown error')}"}

    primary_response = normal["r"]
    primary_headers = {k.lower(): v for k, v in primary_response.headers.items()}

    # Collect bodies from all successful probes
    all_bodies = []
    for p in probes.values():
        if p.get("ok") and p["r"] is not None:
            all_bodies.append(p["r"].text[:30000])

    # ── WAF Scoring ──────────────────────────────────────────────────────────
    detections = []
    for waf_name, sig in WAF_DB.items():
        total_score = 0
        all_evidence = []

        for p in probes.values():
            if not p.get("ok") or p["r"] is None:
                continue
            s, ev = score_response(p["r"], waf_name, sig, all_bodies)
            total_score += s
            for e in ev:
                # deduplicate evidence by key+type
                if not any(x["key"] == e["key"] and x["type"] == e["type"] for x in all_evidence):
                    all_evidence.append(e)

        # IP range check
        for ip in dns_info["all_ips"]:
            if ip_in_cidr(ip, sig.get("ip_ranges", [])):
                all_evidence.append({
                    "type": "IP_RANGE", "key": ip,
                    "value": f"IP belongs to {waf_name} network range", "weight": 5
                })
                total_score += 5
                break

        # ASN org check via SSL issuer / server header heuristic
        server_val = primary_headers.get("server", "").lower()
        via_val = primary_headers.get("via", "").lower()
        for org_str in sig.get("asn_orgs", []):
            if org_str.lower() in server_val or org_str.lower() in via_val:
                all_evidence.append({
                    "type": "ASN_ORG", "key": "org_match",
                    "value": f"'{org_str}' found in server/via headers", "weight": 3
                })
                total_score += 3

        if total_score >= 3 and all_evidence:
            # Confidence: cap at 98, min at 30
            max_possible = sum(e["weight"] for e in all_evidence) + 2
            confidence = min(98, max(30, int((total_score / max(max_possible, 1)) * 100)))
            detections.append({
                "name": waf_name,
                "score": total_score,
                "confidence": confidence,
                "evidence": sorted(all_evidence, key=lambda x: -x["weight"]),
                "color": sig["color"],
                "icon": sig["icon"],
                "category": sig["category"],
                "description": sig["description"],
            })

    detections.sort(key=lambda x: -x["score"])

    # ── Attack probe analysis ─────────────────────────────────────────────────
    attack_probe = probes.get("attack", {})
    attack_status = None
    attack_blocked = False
    if attack_probe.get("ok") and attack_probe["r"] is not None:
        attack_status = attack_probe["r"].status_code
        # 403, 406, 429, 503 on attack probe = strong WAF indicator
        attack_blocked = attack_status in (403, 406, 429, 503)

    # ── Notable headers ───────────────────────────────────────────────────────
    notable_keys = [
        "server","via","x-powered-by","x-cache","x-cdn","x-frame-options",
        "content-security-policy","strict-transport-security","x-xss-protection",
        "x-content-type-options","x-ratelimit-limit","x-ratelimit-remaining",
        "cf-ray","cf-cache-status","x-amz-cf-id","x-amz-cf-pop","x-iinfo",
        "x-sucuri-id","x-akamai-transformed","akamai-grn","x-served-by",
        "x-timer","x-cache-hits","x-barracuda-connect","eagleid",
    ]
    notable_headers = {}
    for k, v in primary_headers.items():
        if k in notable_keys or any(k.startswith(p) for p in ["cf-","x-amz","x-cdn","x-akamai","x-sucuri","x-barracuda","x-f5"]):
            notable_headers[k] = v

    return {
        "success": True,
        "url": url,
        "final_url": primary_response.url,
        "hostname": hostname,
        "dns": dns_info,
        "ssl": ssl_info,
        "status_code": primary_response.status_code,
        "elapsed_ms": int(normal["elapsed"] * 1000),
        "redirect_count": len(primary_response.history),
        "server": primary_headers.get("server", "—"),
        "tls": url.startswith("https"),
        "attack_probe_status": attack_status,
        "attack_blocked": attack_blocked,
        "probes_ok": {k: v.get("ok", False) for k, v in probes.items()},
        "waf_detected": len(detections) > 0,
        "detections": detections,
        "notable_headers": notable_headers,
        "all_headers_count": len(primary_headers),
    }

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/api/detect", methods=["POST"])
def detect():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"success": False, "error": "URL is required"}), 400
    url = data["url"].strip()
    if not url:
        return jsonify({"success": False, "error": "URL cannot be empty"}), 400
    return jsonify(detect_waf(url))

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "WAF Detector API — POST /api/detect with {url}"})

if __name__ == "__main__":
    print("=" * 50)
    print("  WAF / IDS / IPS Detector Backend")
    print("  Running on http://localhost:5000")
    print("  Open frontend/index.html in browser")
    print("=" * 50)
    app.run(debug=True, port=5000, threaded=True)
