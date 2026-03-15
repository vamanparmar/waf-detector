# 🛡️ WAF / IDS / IPS Detector

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![Use Case](https://img.shields.io/badge/Use%20Case-Bug%20Bounty%20%7C%20Pentest%20%7C%20Recon-red)]()

> Detect Web Application Firewalls, Intrusion Detection & Prevention Systems via multi-probe HTTP fingerprinting — with a clean web UI and REST API backend.

---

## 📸 Overview

WAF Detector uses multiple crafted HTTP probes to accurately identify which security solution is protecting a target. Before launching any vulnerability scan or bug bounty test, knowing the WAF helps you choose the right bypass technique and save time.

---

## ✨ Features

- 🔍 Detects **10+ WAF / CDN / IDS / IPS** solutions
- 🌐 Clean **web-based UI** — no command line needed
- ⚡ **REST API backend** — integrate into your own tools
- 🧪 **Multi-probe detection** — headers, cookies, body, status codes
- 💡 **Bypass suggestions** for each detected product
- 🪟 Works on **Windows, Linux, and macOS**
- 📦 **Minimal dependencies** — just `requests` and `flask`

---

## 🔍 Detected Solutions

| Product | Vendor |
|---------|--------|
| Cloudflare | Cloudflare Inc. |
| AWS Shield / CloudFront | Amazon Web Services |
| Akamai | Akamai Technologies |
| Imperva Incapsula | Imperva |
| Sucuri | Sucuri Inc. |
| Fastly | Fastly Inc. |
| F5 BIG-IP ASM | F5 Networks |
| ModSecurity | SpiderLabs (Open Source) |
| Barracuda WAF | Barracuda Networks |
| Alibaba Cloud WAF | Alibaba Cloud |

---

## 📁 Project Structure

```
waf-detector/
├── home/claude/waf-v2/
│   ├── backend/
│   │   ├── app.py              ← Flask REST API
│   │   └── requirements.txt    ← Python dependencies
│   └── frontend/
│       └── index.html          ← Web UI
└── README.md
```

---

## 🚀 Installation & Setup

### Step 1 — Clone the repo
```bash
git clone https://github.com/vamanparmar/waf-detector.git
cd waf-detector
```

### Step 2 — Install dependencies
```bash
pip install -r home/claude/waf-v2/backend/requirements.txt
```

### Step 3 — Start the backend
```bash
cd home/claude/waf-v2/backend
python app.py
```

You should see:
```
 * Running on http://127.0.0.1:5000
```

### Step 4 — Open the frontend
Open this file in your browser:
```
home/claude/waf-v2/frontend/index.html
```

Or navigate to:
```
http://127.0.0.1:5000
```

---

## 🖥️ Using the Web UI

1. Enter the target URL (e.g. `https://example.com`)
2. Click **Detect WAF**
3. View results — detected product, confidence level, and bypass tips

---

## 🔌 API Usage

Call the backend directly:

### Detect WAF via API
```bash
curl -X POST http://127.0.0.1:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### Example Response
```json
{
  "target": "https://example.com",
  "waf_detected": true,
  "product": "Cloudflare",
  "confidence": "HIGH",
  "signatures_matched": [
    "cf-ray header present",
    "HTTP 403 on XSS payload",
    "Cloudflare block page in body"
  ],
  "bypass_suggestions": [
    "Use chunked transfer encoding",
    "Try Unicode/UTF-8 payload encoding",
    "Use HTTP/2 requests",
    "Discover origin IP to bypass CDN"
  ]
}
```

---

## 🧪 How Detection Works

| Probe | What It Does |
|-------|-------------|
| **Passive headers** | Checks Server, cookies, WAF-specific headers |
| **XSS probe** | Sends XSS payload — checks if blocked and how |
| **SQLi probe** | Sends SQL injection — looks for block page or 403 |
| **Traversal probe** | Sends `../etc/passwd` — checks WAF response |
| **Scanner UA probe** | Sends scanner User-Agent — detects UA-based blocking |
| **Error page probe** | Triggers 404/400 — fingerprints custom error pages |

---

## 💡 WAF Bypass Tips

### Cloudflare
- Use chunked transfer encoding
- Try Unicode payload encoding
- Use HTTP/2 requests
- Find origin IP to bypass CDN entirely

### ModSecurity
- Case variation: `SeLeCt` instead of `SELECT`
- Comment injection: `SE/**/LECT`
- Double URL encoding: `%2527`
- HTTP parameter pollution

### AWS WAF
- JSON unicode escapes in payloads
- Multipart form-data tricks
- Slow HTTP requests

---

## 🔗 Integration with WebSentinel

Pairs perfectly with **[WebSentinel](https://github.com/vamanparmar/websentinel)** — a full web vulnerability scanner:

```bash
# Step 1 — Detect WAF
python app.py

# Step 2 — Run full vulnerability scan
python vuln_scanner.py https://target.com
```

---

## ⚖️ Legal Disclaimer

- ✅ Your own systems
- ✅ Bug bounty programs (in-scope targets only)
- ✅ Authorized penetration testing
- ✅ CTF challenges
- ❌ Any system without explicit written permission

Unauthorized use is **illegal and unethical**. The author assumes no liability for misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE)

---

## 👤 Author

**vamanparmar** — [GitHub](https://github.com/vamanparmar)

⭐ If this tool helped you, please **star the repo!**
