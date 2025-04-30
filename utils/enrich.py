import requests

def enrich_ip(ip, abuseipdb_key=None):
    enrichment = {}

    try:
        geo_resp = requests.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org")
        if geo_resp.status_code == 200:
            geo = geo_resp.json()
            enrichment["geo"] = {
                "country": geo.get("country"),
                "region": geo.get("regionName"),
                "city": geo.get("city"),
                "isp": geo.get("isp"),
                "org": geo.get("org")
            }
    except:
        enrichment["geo"] = {"error": "Geo lookup failed"}

    #AbuseIPDB (Optional)
    if abuseipdb_key:
        try:
            headers = {
                "Key": abuseipdb_key,
                "Accept": "application/json"
            }
            abuse_resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=headers)
            if abuse_resp.status_code == 200:
                data = abuse_resp.json()["data"]
                enrichment["abuse"] = {
                    "isWhitelisted": data.get("isWhitelisted"),
                    "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                    "totalReports": data.get("totalReports"),
                    "lastReportedAt": data.get("lastReportedAt")
                }
        except:
            enrichment["abuse"] = {"error": "AbuseIPDB lookup failed"}

    return enrichment
