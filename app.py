from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re
import ipaddress

app = Flask(__name__)

SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.buzz', '.xyz', 
    '.club', '.work', '.click', '.link', '.download'
]

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'account', 'verify', 'update', 'secure', 
    'banking', 'paypal', 'amazon', 'microsoft', 'apple', 'password',
    'confirm', 'suspended', 'limited', 'urgent'
]

def check_url(url):
    """Check a URL for phishing indicators and return analysis."""
    warnings = []
    score = 0
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path.lower()
        full_url = url.lower()
    except Exception as e:
        return {
            'url': url,
            'risk_level': 'Unknown',
            'score': 0,
            'warnings': [{'indicator': 'Invalid URL', 'explanation': f'Could not parse URL: {str(e)}'}],
            'safe': False
        }
    
    # Check 1: IP address instead of domain
    try:
        # Remove port if present
        host = domain.split(':')[0]
        ipaddress.ip_address(host)
        warnings.append({
            'indicator': 'IP Address Used',
            'explanation': 'Using an IP address instead of a domain name is common in phishing attacks.'
        })
        score += 3
    except ValueError:
        pass
    
    # Check 2: @ symbol in URL
    if '@' in url:
        warnings.append({
            'indicator': '@ Symbol Present',
            'explanation': 'The @ symbol can be used to confuse users - everything before @ is ignored by browsers.'
        })
        score += 3
    
    # Check 3: HTTP instead of HTTPS
    if parsed.scheme == 'http' and not any(domain.startswith(x) for x in ['localhost', '127.0.0.1']):
        warnings.append({
            'indicator': 'No HTTPS',
            'explanation': 'Using HTTP (not HTTPS) means the connection is not encrypted, which is suspicious for login pages.'
        })
        score += 1
    
    # Check 4: Very long URL
    if len(url) > 75:
        warnings.append({
            'indicator': 'Unusually Long URL',
            'explanation': f'URL is {len(url)} characters long. Phishers often use long URLs to hide malicious domains.'
        })
        score += 2
    
    # Check 5: Excessive subdomains
    if domain.count('.') >= 4:
        warnings.append({
            'indicator': 'Excessive Subdomains',
            'explanation': f'Domain has {domain.count(".")} dots, indicating many subdomains which is often used to mimic legitimate sites.'
        })
        score += 2
    
    # Check 6: Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            warnings.append({
                'indicator': f'Suspicious TLD ({tld})',
                'explanation': f'Top-level domains like {tld} are commonly used for free hosting and are frequently abused for phishing.'
            })
            score += 2
            break
    
    # Check 7: Punycode
    if 'xn--' in domain:
        warnings.append({
            'indicator': 'Punycode Detected',
            'explanation': 'Punycode (xn--) can be used for homograph attacks where lookalike characters impersonate legitimate domains.'
        })
        score += 3
    
    # Check 8: Suspicious keywords
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in full_url:
            found_keywords.append(keyword)
    if found_keywords:
        warnings.append({
            'indicator': 'Suspicious Keywords',
            'explanation': f'URL contains suspicious keywords: {", ".join(found_keywords)}. These are commonly used in phishing lures.'
        })
        score += 1
    
    # Check 9: Hyphens in domain (excessive)
    domain_part = domain.split(':')[0]
    if domain_part.count('-') >= 3:
        warnings.append({
            'indicator': 'Excessive Hyphens',
            'explanation': 'Multiple hyphens in the domain name can be a sign of a typosquatting attempt.'
        })
        score += 1
    
    # Check 10: Port number specified
    if ':' in domain and not domain.startswith('['):  # Not IPv6
        port = domain.split(':')[-1]
        if port.isdigit() and port not in ['80', '443']:
            warnings.append({
                'indicator': 'Unusual Port',
                'explanation': f'Using port {port} is unusual for web browsing and can indicate suspicious activity.'
            })
            score += 1
    
    # Determine risk level
    if score == 0:
        risk_level = 'Safe'
    elif score <= 2:
        risk_level = 'Low'
    elif score <= 5:
        risk_level = 'Medium'
    else:
        risk_level = 'High'
    
    return {
        'url': url,
        'risk_level': risk_level,
        'score': score,
        'warnings': warnings,
        'safe': score < 3
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'Please provide a URL'}), 400
    result = check_url(url)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
