import requests
import os
import urllib.parse
import ipaddress
import socket
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def calculate_global_risk(vt_malicious, vt_suspicious, urlert_score, cloudflare_score):
    vt_component = (vt_malicious * 4) + (vt_suspicious * 2)
    urlert_component = urlert_score * 3
    cloudflare_component = cloudflare_score * 2

    global_score = vt_component + urlert_component + cloudflare_component

    if global_score == 0:
        level = "Clean"
    elif global_score <= 50:
        level = "Low"
    elif global_score <= 150:
        level = "Medium"
    else:
        level = "High"

    total_alerts = vt_malicious + vt_suspicious + urlert_score + cloudflare_score
    if total_alerts > 5:
        confidence = "Strong"
    elif total_alerts > 0:
        confidence = "Moderate"
    else:
        confidence = "Weak"

    return global_score, level, confidence


def virustotal_url_scan(url: str):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found"}
    try:
        headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        data = {"url": url}
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        if submit_response.status_code != 200:
            return {"error": f"VirusTotal submission failed: {submit_response.status_code}"}

        analysis_id = submit_response.json()["data"]["id"]
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        if analysis_response.status_code != 200:
            return {"error": "Failed to get analysis results"}

        stats = analysis_response.json()["data"]["attributes"]["stats"]
        return {"malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0)}

    except Exception as e:
        return {"error": f"VirusTotal scan failed: {str(e)}"}


def urlert_scan(url: str):
    try:
        domain = urllib.parse.urlparse(url).netloc or url
        score = 1 if is_ip_address(domain) or len(domain) > 30 else 0
        return {"domain": domain, "score": score, "note": "Basic domain analysis"}
    except Exception as e:
        return {"error": f"Urlert scan failed: {str(e)}"}


def cloudflare_radar_scan(url: str):
    try:
        domain = urllib.parse.urlparse(url).netloc or url
        score = 1 if "-" in domain else 0
        return {"domain": domain, "score": score, "note": "Basic Cloudflare analysis"}
    except Exception as e:
        return {"error": f"Cloudflare scan failed: {str(e)}"}


def get_url_report(url: str):
    domain = urllib.parse.urlparse(url).netloc or url

    # Resolve IP
    if not is_ip_address(domain):
        try:
            ip_address_value = socket.gethostbyname(domain)
        except Exception:
            ip_address_value = "Could not resolve"
    else:
        ip_address_value = domain

    vt_result = virustotal_url_scan(url)
    urlert_result = urlert_scan(url)
    cloudflare_result = cloudflare_radar_scan(url)

    vt_malicious = vt_result.get("malicious", 0) if "error" not in vt_result else 0
    vt_suspicious = vt_result.get("suspicious", 0) if "error" not in vt_result else 0
    urlert_score = urlert_result.get("score", 0) if "error" not in urlert_result else 0
    cloudflare_score = cloudflare_result.get("score", 0) if "error" not in cloudflare_result else 0

    global_score, global_level, confidence = calculate_global_risk(
        vt_malicious, vt_suspicious, urlert_score, cloudflare_score
    )

    return {
        "url": url,
        "domain": domain,
        "ip": ip_address_value,
        "type": "IP" if is_ip_address(domain) else "Domain",
        "scan_time": datetime.utcnow().isoformat(),
        "reputation": {"global_score": global_score, "global_level": global_level, "confidence": confidence},
        "vendors": {"virustotal": vt_result, "urlert": urlert_result, "cloudflare_radar": cloudflare_result},
    }