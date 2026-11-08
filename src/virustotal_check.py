"""
Sprint 4 - Step 4: VirusTotal second opinion (Figure 3.2, Stage 5).
Only the file's SHA-256 HASH is sent to VirusTotal - the APK itself is never uploaded.
Setup : put your key in a file called .env in the MalSense folder:   VT_API_KEY=your_key_here
Usage : python src/virustotal_check.py samples/<file>.apk      (hashes the file, then looks it up)
        python src/virustotal_check.py <64-character sha256>    (looks up a hash directly)
Free API limits: 4 lookups per minute, 500 per day.
Later, Flask will import vt_lookup() from this file.
"""
import os, sys, hashlib, logging
import requests
from dotenv import load_dotenv

load_dotenv()                                   # reads VT_API_KEY from the .env file
API_KEY = os.getenv("VT_API_KEY")
URL = "https://www.virustotal.com/api/v3/files/{}"
log = logging.getLogger(__name__)        # technical details go to the server console, not the web page


def sha256_of(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def vt_lookup(sha256):
    """Look up a hash on VirusTotal. Always returns a dict with a 'status' key."""
    if not API_KEY:
        return {"status": "error", "message": "VT_API_KEY missing - create the .env file"}
    try:
        r = requests.get(URL.format(sha256), headers={"x-apikey": API_KEY}, timeout=20)
    except requests.Timeout as e:
        log.warning(f"VirusTotal lookup timed out: {e}")
        return {"status": "error", "message": "VirusTotal took too long to answer (slow or filtered network)."}
    except requests.ConnectionError as e:
        log.warning(f"VirusTotal unreachable: {e}")
        return {"status": "error", "message": "Couldn't reach VirusTotal (no internet or the network blocked it)."}
    except requests.RequestException as e:
        log.warning(f"VirusTotal request failed: {e}")
        return {"status": "error", "message": "Couldn't reach VirusTotal (network problem)."}

    if r.status_code == 404:
        return {"status": "not_found", "message": "VirusTotal has never seen this file"}
    if r.status_code == 401:
        return {"status": "error", "message": "API key rejected - check VT_API_KEY in .env"}
    if r.status_code == 429:
        return {"status": "error", "message": "Rate limit reached (4/min, 500/day) - wait and retry"}
    if r.status_code != 200:
        log.warning(f"VirusTotal returned HTTP {r.status_code}: {r.text[:200]}")
        return {"status": "error", "message": f"VirusTotal is not available right now (HTTP {r.status_code})."}

    a = r.json()["data"]["attributes"]
    stats = a.get("last_analysis_stats", {})
    flagged = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    ptc = a.get("popular_threat_classification", {}) or {}
    label = ptc.get("suggested_threat_label", "")
    # most common family name / category that the engines agree on, e.g. "joker" / "trojan" (threat intelligence)
    top = lambda key: max(ptc.get(key) or [{}], key=lambda x: x.get("count", 0)).get("value", "")
    return {"status": "found",
            "malicious": stats.get("malicious", 0), "suspicious": stats.get("suspicious", 0),
            "engines_total": total, "flagged": flagged,
            "detection_ratio": f"{flagged}/{total}",
            "threat_label": label,
            "family": top("popular_threat_name"),
            "category": top("popular_threat_category"),
            "file_type": a.get("type_description", ""),
            "names": a.get("names", [])[:3],
            "link": f"https://www.virustotal.com/gui/file/{sha256}"}


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else "samples/a2dp.Vol_137.apk"
    h = arg.lower() if len(arg) == 64 and not os.path.exists(arg) else sha256_of(arg)
    print("=== VIRUSTOTAL LOOKUP ===")
    print(f"Input   : {arg}")
    print(f"SHA-256 : {h}  (only this hash is sent, not the file)")
    res = vt_lookup(h)
    if res["status"] == "found":
        print(f"Result  : {res['detection_ratio']} antivirus engines flagged this file "
              f"({res['malicious']} malicious, {res['suspicious']} suspicious)")
        print(f"Label   : {res['threat_label'] or '-'}")
        print(f"Type    : {res['file_type']} | known names: {', '.join(res['names']) or '-'}")
        print(f"Link    : {res['link']}")
    else:
        print(f"Result  : {res['status'].upper()} - {res['message']}")