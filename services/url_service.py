import requests
import os
import urllib.parse
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def calculate_risk(malicious: int, suspicious: int, reputation: int) -> tuple:
    
    score = (malicious * 5) + (suspicious * 3) + abs(reputation)
    
    if score == 0:
        level = "Clean"
    elif score <= 20:
        level = "Low"
    elif score <= 50:
        level = "Medium"
    else:
        level = "High"
    
    return level, score

def calculate_global_risk(vt_malicious, vt_suspicious):

    
    vt_component = (vt_malicious * 4) + (vt_suspicious * 2)
    
    global_score = vt_component
    
    if global_score == 0:
        level = "Clean"
    elif global_score <= 50:
        level = "Low"
    elif global_score <= 150:
        level = "Medium"
    else:
        level = "High"
    
    # Niveau de confiance (basé uniquement sur VT)
    if vt_malicious > 3:
        confidence = "Strong"
    elif vt_malicious > 0:
        confidence = "Moderate"
    else:
        confidence = "Weak"
    
    return global_score, level, confidence

def virustotal_url_scan(url: str):
    
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not found"}
    
    try:
        # Soumettre l'URL
        headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
        data = {"url": url}
        
        submit_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
        
        if submit_response.status_code != 200:
            return {"error": f"VirusTotal submission failed: {submit_response.status_code}"}
        
        # Récupérer les résultats
        analysis_id = submit_response.json()["data"]["id"]
        analysis_response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
        
        if analysis_response.status_code != 200:
            return {"error": "Failed to get analysis results"}
        
        stats = analysis_response.json()["data"]["attributes"]["stats"]
        
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }
        
    except Exception as e:
        return {"error": f"VirusTotal scan failed: {str(e)}"}



def urlert_scan(url: str):
    
    try:
        domain = urllib.parse.urlparse(url).netloc or urllib.parse.urlparse(url).path
        return {
            "domain": domain,
            "note": "Basic domain info only"
        }
    except Exception as e:
        return {"error": f"Urlert scan failed: {str(e)}"}

def cloudflare_radar_scan(url: str):
    
    try:
        domain = urllib.parse.urlparse(url).netloc or urllib.parse.urlparse(url).path
        return {
            "domain": domain,
            "note": "Cloudflare Radar basic info"
        }
    except Exception as e:
        return {"error": f"Cloudflare scan failed: {str(e)}"}

def get_url_report(url: str):
    """Fonction principale qui orchestre l'analyse d'URL (sans urlscan)"""
    
    # Analyses 
    vt_result = virustotal_url_scan(url)
    urlert_result = urlert_scan(url)
    cloudflare_result = cloudflare_radar_scan(url)
    
    # Calcul du risque global 
    vt_malicious = vt_result.get("malicious", 0) if "error" not in vt_result else 0
    vt_suspicious = vt_result.get("suspicious", 0) if "error" not in vt_result else 0
    
    global_score, global_level, confidence = calculate_global_risk(
        vt_malicious, vt_suspicious
    )
    
    return {
        "url": url,
        "domain": urllib.parse.urlparse(url).netloc or urllib.parse.urlparse(url).path,
        "reputation": {
            "global_score": global_score,
            "global_level": global_level,
            "confidence": confidence
        },
        "vendors": {
            "virustotal": vt_result,
            "urlert": urlert_result,
            "cloudflare_radar": cloudflare_result
            
        }
    }