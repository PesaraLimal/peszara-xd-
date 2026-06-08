import requests
from .config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

# Test/Mock threat databases to make simulation works out of the box
MOCK_MALICIOUS_IPS = {
    "185.220.101.5": {"abuse_score": 100, "country": "DE", "domain": "tor-exit-node.net"}, # Tor node
    "91.241.12.33": {"abuse_score": 85, "country": "RU", "domain": "c2-server.ru"},      # Mock C2
    "45.142.195.4": {"abuse_score": 60, "country": "CN", "domain": "crawler-scanner.cn"}, # Scanner
    "8.8.8.8": {"abuse_score": 0, "country": "US", "domain": "dns.google"}                 # Known clean
}

MOCK_MALICIOUS_HASHES = {
    "2e008c237c8c83aa6396f8c859d0df54593818e38d49b2f6efd555c82245b6db": {"malicious": 68, "total": 73}, # Mimikatz
    "5d7e8b6bda4e67272886fdf4598d1a1005a76e7c3b9b47cfbc8d249f7d242661": {"malicious": 59, "total": 71}, # Wannacry hash
    "0000000000000000000000000000000000000000000000000000000000000000": {"malicious": 0, "total": 70}  # Safe placeholder
}

def check_ip_reputation(ip: str) -> dict:
    """
    Checks AbuseIPDB for IP reputation. Falls back to mock data if key is missing or request fails.
    """
    if not ABUSEIPDB_API_KEY:
        # Check mock database
        if ip in MOCK_MALICIOUS_IPS:
            return MOCK_MALICIOUS_IPS[ip]
        # Return generic clean
        return {"abuse_score": 0, "country": "Unknown", "domain": "clean.net"}

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        response = requests.get(url, headers=headers, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "Unknown"),
                "domain": data.get("domain", "")
            }
    except Exception as e:
        print(f"AbuseIPDB request error: {e}")

    # Fallback in case of API failure
    if ip in MOCK_MALICIOUS_IPS:
        return MOCK_MALICIOUS_IPS[ip]
    return {"abuse_score": 0, "country": "Unknown", "domain": "error-fallback"}

def check_hash_reputation(file_hash: str) -> dict:
    """
    Checks VirusTotal for SHA256/MD5 hash reputation. Falls back to mock data if key is missing.
    """
    if not VIRUSTOTAL_API_KEY:
        if file_hash in MOCK_MALICIOUS_HASHES:
            return MOCK_MALICIOUS_HASHES[file_hash]
        return {"malicious": 0, "total": 0}

    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json().get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values())
            }
    except Exception as e:
        print(f"VirusTotal request error: {e}")

    if file_hash in MOCK_MALICIOUS_HASHES:
        return MOCK_MALICIOUS_HASHES[file_hash]
    return {"malicious": 0, "total": 0}
