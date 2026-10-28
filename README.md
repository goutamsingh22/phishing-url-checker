# Phishing URL Checker

A simple Flask web app that checks URLs for common phishing indicators and provides explanations of suspicious patterns.

## Features

- Flags suspicious URL patterns (IP addresses, unusual ports, punycode/homoglyphs, long subdomains, suspicious TLDs, etc.)
- Explains warning indicators clearly
- Provides an overall risk assessment (Safe/Low/Medium/High)
- Simple web interface

## Setup

```bash
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

Then open http://localhost:5000 in your browser.

## How It Works

The checker uses rule-based heuristics to detect suspicious patterns:
- Uses IP address instead of domain name
- Contains `@` symbol (URL confusion)
- Uses HTTP instead of HTTPS on suspicious-looking domains
- Very long URLs
- Suspicious or uncommon TLDs
- Excessive subdomains
- Contains suspicious keywords (login, verify, secure, update, etc.)
- Punycode (xn--) indicators

## Limitations

- **Heuristic-based only**: This tool uses pattern matching, not a real-time blacklist or machine learning model. It may produce false positives and false negatives.
- **No live threat intelligence**: It doesn't check against known phishing databases (like Google Safe Browsing, PhishTank, etc.).
- **URL shorteners**: Shortened URLs (bit.ly, tinyurl) aren't expanded to check the final destination.
- **Sophisticated attacks**: Advanced phishing techniques (homograph attacks with lookalike Unicode characters, compromised legitimate domains) may not be fully detected.
- **No SSL/TLS validation**: Doesn't verify certificate validity.
- **Client-side only checks**: All analysis is done locally based on URL structure.
- **Not a replacement for security tools**: This is an educational tool and should not be relied upon as the sole protection against phishing.

## Disclaimer

This tool is for educational purposes only. Always exercise caution with suspicious links and use additional security measures.