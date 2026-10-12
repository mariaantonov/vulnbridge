import sys
import requests
import json

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def check_cisa_kev(cve_id: str) -> dict:
    """Check if the CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    try:
        response = requests.get(CISA_KEV_URL, timeout=10)
        response.raise_for_status()
        kev_catalog = response.json()
        
        for entry in kev_catalog.get("vulnerabilities", []):
            if entry.get("cveID", "").upper() == cve_id.strip().upper():
                return {
                    "is_known_exploited": True,
                    "date_added": entry.get("dateAdded", "N/A"),
                    "due_date": entry.get("dueDate", "N/A"),
                    "required_action": entry.get("requiredAction", "Apply mitigations per vendor guidance.")
                }
        return {"is_known_exploited": False}
    except requests.exceptions.RequestException as e:
        print(f"[!] Warning: Unable to check CISA KEV feed ({e})")
        return {"is_known_exploited": False}

def fetch_cve_details(cve_id: str) -> dict:
    """Fetch vulnerability metadata from the NIST NVD REST API."""
    url = f"{NVD_API_URL}{cve_id.strip()}"
    headers = {"User-Agent": "VulnBridge-Triage-Tool"}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        
        cve_item = vulnerabilities[0].get("cve", {})
        
        descriptions = cve_item.get("descriptions", [])
        desc_text = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
        
        metrics = cve_item.get("metrics", {})
        cvss_score = "N/A"
        severity = "UNKNOWN"
        vector = "N/A"
        
        if "cvssMetricV31" in metrics:
            metric_data = metrics["cvssMetricV31"][0]["cvssData"]
            cvss_score = metric_data.get("baseScore", "N/A")
            severity = metric_data.get("baseSeverity", "UNKNOWN")
            vector = metric_data.get("vectorString", "N/A")
        elif "cvssMetricV30" in metrics:
            metric_data = metrics["cvssMetricV30"][0]["cvssData"]
            cvss_score = metric_data.get("baseScore", "N/A")
            severity = metric_data.get("baseSeverity", "UNKNOWN")
            vector = metric_data.get("vectorString", "N/A")

        return {
            "id": cve_id,
            "score": cvss_score,
            "severity": severity,
            "vector": vector,
            "description": desc_text
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {cve_id}: {e}")
        return None

def generate_remediation_card(vuln: dict, kev_data: dict) -> str:
    """Format parsed vulnerability into a clean Markdown ticket with threat intel."""
    if not vuln:
        return "Could not generate ticket: CVE not found."
    
    kev_status = "⚠️ YES (Active In-The-Wild Exploitation)" if kev_data.get("is_known_exploited") else "No active KEV entry"
    kev_action = kev_data.get("required_action", "Apply vendor patch.") if kev_data.get("is_known_exploited") else "Standard patching schedule."
    kev_due = kev_data.get("due_date", "Standard SLA") if kev_data.get("is_known_exploited") else "Standard SLA"

    card = f"""### 🛡️ Vulnerability Remediation Ticket: {vuln['id']}

| Attribute | Details |
| :--- | :--- |
| **Vulnerability ID** | `{vuln['id']}` |
| **CVSS Base Score** | **{vuln['score']}** |
| **Severity Tier** | `{vuln['severity']}` |
| **CVSS Vector** | `{vuln['vector']}` |
| **CISA KEV Status** | **{kev_status}** |
| **Federal Due Date** | `{kev_due}` |

#### 📝 Technical Summary
{vuln['description']}

#### 🚨 Threat Intel & Action Required
- **Mandatory Action:** {kev_action}

#### ⚡ Recommended Remediation Steps
1. **Identify Affected Assets:** Cross-reference internal SBOM/dependency manifests.
2. **Review Vendor Advisory:** Check upstream vendor patch notes associated with `{vuln['id']}`.
3. **Emergency Patching:** If listed in CISA KEV, prioritize for out-of-band deployment ahead of routine patch cycles.
---
"""
    return card

def main():
    if len(sys.argv) < 2:
        print("Usage: python vulnbridge.py <CVE-ID> (e.g., python vulnbridge.py CVE-2021-44228)")
        return
    
    target_cve = sys.argv[1].strip()
    print(f"[*] Querying NIST NVD for {target_cve}...")
    details = fetch_cve_details(target_cve)
    
    print(f"[*] Cross-referencing CISA Known Exploited Vulnerabilities catalog...")
    kev_info = check_cisa_kev(target_cve)
    
    if details:
        ticket = generate_remediation_card(details, kev_info)
        print("\n" + ticket)
        
        output_filename = f"{target_cve}_ticket.md"
        with open(output_filename, "w") as f:
            f.write(ticket)
        print(f"[✓] Saved remediation card to {output_filename}")
    else:
        print(f"[!] No record found for {target_cve}.")

if __name__ == "__main__":
    main()
