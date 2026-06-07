import logging
import requests
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from app.config import settings
from app.models import ThreatIntelCache

logger = logging.getLogger("PeszaraIntel")

# Safe public DNS or common private subnets we shouldn't query on AbuseIPDB
PRIVATE_IP_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "127.0.0.1", "0.0.0.0")

# Pre-populated mock malicious lists for demo/testing without keys
MOCK_MALICIOUS_HASHES = {
    "c8ee76a74152864f77c3e1762c4a9eb482998a442e947ff1c875d9e5bdfefaa5": "Trojan.Agent.PowerShell",  # Sample suspicious hash
    "44d88612fe8a7f3cd27b1402243e33f2d2946c1a84f7222384a441c7ffcc2222": "WannaCry Ransomware",
    "55d88612fe8a7f3cd27b1402243e33f2d2946c1a84f7222384a441c7ffcc3333": "Mimikatz Credential Stealer"
}

MOCK_MALICIOUS_IPS = {
    "185.112.145.2": "Known Command & Control Server (C2)",
    "45.227.254.10": "Active SSH Bruteforcer",
    "198.51.100.42": "Exfiltration endpoint"
}


def check_hash_reputation(db: Session, sha256: str) -> tuple[str, dict]:
    """
    Checks the reputation of a file hash. First looks at DB cache, then falls back to VirusTotal API,
    and defaults to a mock generator if no key is configured.
    Returns: (reputation: 'clean'|'suspicious'|'malicious', raw_response: dict)
    """
    if not sha256:
        return "clean", {}

    sha256 = sha256.lower().strip()

    # 1. Check Database Cache
    cached = db.query(ThreatIntelCache).filter(ThreatIntelCache.indicator == sha256).first()
    if cached:
        # Cache expires after 24 hours
        if datetime.utcnow() - cached.cached_at.replace(tzinfo=None) < timedelta(hours=24):
            return cached.reputation, cached.raw_response

    # 2. Query External API or Mock
    reputation = "clean"
    raw_response = {}

    if settings.VIRUSTOTAL_API_KEY:
        try:
            logger.info(f"Querying VirusTotal for hash: {sha256}")
            headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            response = requests.get(url, headers=headers, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                raw_response = data
                
                # Analyze VT stats
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)

                if malicious_count > 3:
                    reputation = "malicious"
                elif malicious_count > 0 or suspicious_count > 2:
                    reputation = "suspicious"
            elif response.status_code == 404:
                reputation = "clean"
                raw_response = {"detail": "Hash not found in VirusTotal"}
            else:
                logger.error(f"VirusTotal error {response.status_code}: {response.text}")
                # Fall back to mock on error to maintain app logic
                reputation, raw_response = _get_mock_hash_reputation(sha256)
        except Exception as e:
            logger.error(f"VT Query failed: {e}")
            reputation, raw_response = _get_mock_hash_reputation(sha256)
    else:
        # Mock mode
        reputation, raw_response = _get_mock_hash_reputation(sha256)

    # 3. Update Database Cache
    if cached:
        cached.reputation = reputation
        cached.raw_response = raw_response
        cached.cached_at = datetime.utcnow()
    else:
        new_cache = ThreatIntelCache(
            indicator=sha256,
            indicator_type="file_hash",
            reputation=reputation,
            raw_response=raw_response
        )
        db.add(new_cache)
    
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit threat intel cache write: {e}")

    return reputation, raw_response


def check_ip_reputation(db: Session, ip_address: str) -> tuple[str, dict]:
    """
    Checks the reputation of a remote IP. Checks DB cache, then AbuseIPDB API, and defaults to mock.
    """
    if not ip_address or any(ip_address.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
        return "clean", {"detail": "Private / local IP address"}

    # 1. Check Database Cache
    cached = db.query(ThreatIntelCache).filter(ThreatIntelCache.indicator == ip_address).first()
    if cached:
        if datetime.utcnow() - cached.cached_at.replace(tzinfo=None) < timedelta(hours=24):
            return cached.reputation, cached.raw_response

    # 2. Query External API or Mock
    reputation = "clean"
    raw_response = {}

    if settings.ABUSEIPDB_API_KEY:
        try:
            logger.info(f"Querying AbuseIPDB for IP: {ip_address}")
            headers = {
                "Accept": "application/json",
                "Key": settings.ABUSEIPDB_API_KEY
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": "90"
            }
            url = "https://api.abuseipdb.com/api/v2/check"
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                raw_response = data
                abuse_score = data.get("data", {}).get("abuseConfidenceScore", 0)
                
                if abuse_score >= 50:
                    reputation = "malicious"
                elif abuse_score >= 15:
                    reputation = "suspicious"
            else:
                logger.error(f"AbuseIPDB error {response.status_code}: {response.text}")
                reputation, raw_response = _get_mock_ip_reputation(ip_address)
        except Exception as e:
            logger.error(f"AbuseIPDB Query failed: {e}")
            reputation, raw_response = _get_mock_ip_reputation(ip_address)
    else:
        # Mock mode
        reputation, raw_response = _get_mock_ip_reputation(ip_address)

    # 3. Update Database Cache
    if cached:
        cached.reputation = reputation
        cached.raw_response = raw_response
        cached.cached_at = datetime.utcnow()
    else:
        new_cache = ThreatIntelCache(
            indicator=ip_address,
            indicator_type="ip_address",
            reputation=reputation,
            raw_response=raw_response
        )
        db.add(new_cache)
        
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to commit threat intel cache write: {e}")

    return reputation, raw_response


def _get_mock_hash_reputation(sha256: str) -> tuple[str, dict]:
    if sha256 in MOCK_MALICIOUS_HASHES:
        threat_name = MOCK_MALICIOUS_HASHES[sha256]
        return "malicious", {
            "mocked": True,
            "threat_name": threat_name,
            "positives": 42,
            "total": 72,
            "description": f"Mock database flagged this as {threat_name}."
        }
    return "clean", {"mocked": True, "positives": 0, "total": 72}


def _get_mock_ip_reputation(ip_address: str) -> tuple[str, dict]:
    if ip_address in MOCK_MALICIOUS_IPS:
        threat_name = MOCK_MALICIOUS_IPS[ip_address]
        return "malicious", {
            "mocked": True,
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "usageType": "Data Center/Web Hosting/Transit",
            "domain": "malicioushost.net",
            "description": f"Mock database flagged this IP: {threat_name}."
        }
    return "clean", {"mocked": True, "abuseConfidenceScore": 0, "countryCode": "US"}
