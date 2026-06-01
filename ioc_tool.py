import requests
import csv
import time
import datetime
import os

# STEP 1 - Setup the API keys
#------------------------------------

print()
print("===========================================")
print("         IOC Enrichment Tool")
print("===========================================")
print()
print("First, Use your API keys.")
print("(they won't be saved anywhere, just used per session)")
print()

VT_KEY     = input("Paste your VirusTotal API key  : ").strip()
ABUSE_KEY  = input("Paste your AbuseIPDB API key   : ").strip()

# STEP 2 - get the IOC list from the user
#------------------------------------

print()
print("How do you want to provide the IOCs?")
print("  1 - Type them one by one")
print("  2 - Upload a .txt file path (one IOC per line)")
print()

choice = input("Enter 1 or 2: ").strip()
iocs = []

if choice == "1":
    print()
    print("Type each IOC and press Enter.")
    print("When you are done, just type 'done' and press Enter.")
    print()
    while True:
        entry = input("IOC > ").strip()
        if entry.lower() == "done":
            break
        if entry:
            iocs.append(entry)

elif choice == "2":
    print()
    path = input("File path (e.g. C:/Users/Desktop/iocs.txt): ").strip()
    try:
        with open(path, "r") as f:
            for line in f:
                ioc = line.strip()
                if ioc and not ioc.startswith("#"):
                    iocs.append(ioc)
        print(f"Loaded {len(iocs)} IOCs from file.")
    except FileNotFoundError:
        print(f"ERROR: couldn't find the file: {path}")
        exit()
else:
    print("Invalid choice.")
    exit()

if not iocs:
    print("No IOCs to check. Exiting.")
    exit()



# helper - figure out what type the IOC is
#------------------------------------

def detect_type(ioc):
    # hash? only hex chars + right length
    if all(c in "0123456789abcdefABCDEF" for c in ioc) and len(ioc) in [32, 40, 64]:
        return "hash"
    # IP? four parts all 0-255
    parts = ioc.split(".")
    if len(parts) == 4:
        try:
            if all(0 <= int(p) <= 255 for p in parts):
                return "ip"
        except:
            pass
    # URL?
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    # domain?
    if "." in ioc:
        return "domain"
    return "unknown"



# helper - check VirusTotal
#------------------------------------

def check_vt(ioc, ioc_type):
    if ioc_type == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    elif ioc_type == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
    elif ioc_type == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{ioc}"
    elif ioc_type == "url":
        import base64
        encoded = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        url = f"https://www.virustotal.com/api/v3/urls/{encoded}"
    else:
        return {"vt_verdict": "SKIPPED", "vt_malicious": "N/A", "vt_total": "N/A"}

    try:
        r = requests.get(url, headers={"x-apikey": VT_KEY})
        if r.status_code != 200:
            return {"vt_verdict": f"ERROR {r.status_code}", "vt_malicious": "N/A", "vt_total": "N/A"}
        stats      = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious",  0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())
        verdict    = "MALICIOUS" if malicious > 0 else ("SUSPICIOUS" if suspicious > 0 else "CLEAN")
        return {"vt_verdict": verdict, "vt_malicious": malicious, "vt_total": total}
    except Exception as e:
        return {"vt_verdict": "ERROR", "vt_malicious": "N/A", "vt_total": "N/A"}

# helper - check AbuseIPDB  (IPs only)
#------------------------------------

def check_abuse(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        if r.status_code != 200:
            return {"ab_verdict": f"ERROR {r.status_code}", "ab_score": "N/A", "ab_reports": "N/A", "ab_country": "N/A"}
        d       = r.json()["data"]
        score   = d.get("abuseConfidenceScore", 0)
        verdict = "MALICIOUS" if score >= 50 else "CLEAN"
        return {"ab_verdict": verdict, "ab_score": score, "ab_reports": d.get("totalReports", 0), "ab_country": d.get("countryCode", "N/A")}
    except Exception as e:
        return {"ab_verdict": "ERROR", "ab_score": "N/A", "ab_reports": "N/A", "ab_country": "N/A"}


# STEP 3 - run the checks
#------------------------------------

print()
print(f"Checking {len(iocs)} IOC(s)... hang on")
print()

results = []

for ioc in iocs:
    ioc_type = detect_type(ioc)
    print(f"  Checking {ioc}  ({ioc_type})")

    vt    = check_vt(ioc, ioc_type)
    abuse = check_abuse(ioc) if ioc_type == "ip" else {"ab_verdict": "N/A", "ab_score": "N/A", "ab_reports": "N/A", "ab_country": "N/A"}

    row = {"ioc": ioc, "type": ioc_type}
    row.update(vt)
    row.update(abuse)
    results.append(row)

    print(f"    VT: {vt['vt_verdict']}  ({vt['vt_malicious']} malicious / {vt['vt_total']} engines)")
    if ioc_type == "ip":
        print(f"    AbuseIPDB: {abuse['ab_verdict']}  (score {abuse['ab_score']}/100, {abuse['ab_reports']} reports)")

    time.sleep(1)


# STEP 4 - save to results.csv
#------------------------------------

timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
output_file = f"results_{timestamp}.csv"

columns = ["ioc", "type", "vt_verdict", "vt_malicious", "vt_total", "ab_verdict", "ab_score", "ab_reports", "ab_country"]

with open(output_file, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=columns)
    writer.writeheader()
    for row in results:
        writer.writerow({col: row.get(col, "N/A") for col in columns})

# Fil path
full_path = os.path.abspath(output_file)

print()
print("===========================================")
print(f" Done!")
print(f" File saved as : {output_file}")
print(f" Full path     : {full_path}")
print("===========================================")
