from flask import Flask, request, jsonify
import subprocess
import requests
from tld import get_tld
import socket
from urllib.parse import urlparse

app = Flask(__name__)

# Domain
def get_domain_name(url):
    try:
        domain_name = get_tld(url)
        return domain_name
    except Exception as e:
        return "Error"

# IP хаяг
def get_ip_address(url):
    try:
        parsed_url = urlparse(url)
        url_without_protocol = parsed_url.netloc or parsed_url.path
        ip_address = socket.gethostbyname(url_without_protocol)
        return ip_address
    except socket.gaierror as e:
        return f"Error: {e}"


# SQL Injection 
payloads = [
    "' OR 1=1 --",
    "' OR 'a' = 'a",
    "admin' --",
    "admin' #",
    "' OR 'x'='x",
    "1' OR 1=1 --"
]

def check_sqli(url):
    results = []
    for payload in payloads:
        try:
            test_url = f"{url}?q={payload}"
            response = requests.get(test_url)

            if response.status_code == 200:
                if "error" in response.text.lower() or "mysql" in response.text.lower():
                    results.append(f"Payload '{payload}' might have triggered an issue. Possible SQL Injection vulnerability.")
            else:
                results.append(f"Payload '{payload}' returned status code {response.status_code}, which suggests blocking or sanitization.")

        except requests.exceptions.RequestException as e:
            print(f"Request error with payload {payload}: {e}")
            results.append(f"Error testing payload '{payload}': {e}")

    if len(results) == 0:
        return "Pass" 
    else:
        return "\n".join(results)




# Reflected XSS Test
def test_reflected_xss(url):
    try:
        xss_payload = "<script>alert('XSS')</script>"
        response = requests.get(url, params={"q": xss_payload})
        if xss_payload in response.text:
            return "Fail"  
        return "Pass" 
    except Exception as e:
        return "Error"

# Stored XSS Test
def test_stored_xss(url):
    try:
        xss_payload = "<script>alert('Stored XSS')</script>"
        response = requests.post(url, data={"input": xss_payload})
        if xss_payload in response.text:
            return "Fail" 
        return "Pass" 
    except Exception as e:
        return "Error"

# Command Injection Test
def test_command_injection(url):
    try:
        command_payload = ["test; ls", "test && dir", "test | whoami"]
        for payload in command_payload:
            response = requests.get(f"{url}?input={payload}")
            if "bash" in response.text:
                return f"Fail: Command injection detected with payload '{payload}' (bash command)"
            if "ls" in response.text:
                return f"Fail: Command injection detected with payload '{payload}' (ls command)"
            if "whoami" in response.text:
                return f"Fail: Command injection detected with payload '{payload}' (whoami command)"
        return "Pass"  # No command injection detected
    except Exception as e:
        return f"Error: {str(e)}"

#HTTPS Security headers
def test_http_headers(url):
    response = requests.get(url)
    headers = response.headers
    missing_headers = []
    required_headers = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy', 'Permissions-Policy', 'Referrer Policy']

    for header in required_headers:
        if header not in headers:
            missing_headers.append(header)
    
    if missing_headers:
        return f"Fail: Missing headers: {', '.join(missing_headers)}"
    return "Pass" 

def test_clickjacking(url):
    response = requests.get(url)
    if "X-Frame-Options" in response.headers:
        return "Pass"  
    return "Fail"  

#CSRF Test
def test_csrf(url):
    try:
        response = requests.post(url, data={"action": "change_password", "password": "newpass"})
        if "csrf token" in response.text.lower():  
            return "Pass" 
        return "Fail"  
    except Exception as e:
        return "Error"

# Open Redirect Test
def test_open_redirect(url):
    try:
        redirect_url = url + "/?url=http://malicious.com"
        response = requests.get(redirect_url)
        if response.url == redirect_url:
            return "Fail"
        return "Pass"
    except Exception as e:
        return "Error"

# Directory Traversal Test
def test_directory_traversal(url):
    try:
        payloads = [
        "../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../windows/win.ini",
        "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "/etc/passwd",
        "/windows/win.ini",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5c..%5c..%5cetc%5cpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "..%00../etc/passwd",
        "../../../../../../boot.ini",
        "..%2f..%2f..%2fwindows%2fwin.ini",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        "/proc/self/environ"
        ]
        
        for payload in payloads:
            response = requests.get(url, params={"file": payload})
            
            # Check for sensitive content in the response
            if "root:" in response.text or "[extensions]" in response.text:
                return f"Fail: Vulnerable to directory traversal with payload '{payload}'"
        
        return "Pass: No directory traversal vulnerability detected"
    except Exception as e:
        return f"Error: {str(e)}"

# Sensitive Data Exposure Test
def test_sensitive_data_exposure(url):
    try:
        if url.startswith("https://"):
            return "Pass"  
        return "Fail"  
    except Exception as e:
        return "Error"


@app.route('/scan', methods=['POST'])
def scan_website():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    results = {}
    results["URL"] = url
    results["IP address"] = get_ip_address(url)
    results["Domain"] = get_domain_name(url)
    results["SQL Injection"] = check_sqli(url)
    results["Reflected XSS"] = test_reflected_xss(url)
    results["Stored XSS"] = test_stored_xss(url)
    results["Command Injection"] = test_command_injection(url)
    results["Open Redirect"] = test_open_redirect(url)
    results["Directory Traversal"] = test_directory_traversal(url)
    results["Sensitive Data Exposure"] = test_sensitive_data_exposure(url)
    results["HTTP Headers"] = test_http_headers(url)
    results["Clickjacking"] = test_clickjacking(url)
    results["CSRF"] = test_csrf(url)
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
