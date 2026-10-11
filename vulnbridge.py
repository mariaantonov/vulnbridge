import sys
import requests
import json

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

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
        
        # Extract description
        descriptions = cve_item.get("descriptions", [])
        desc_text = descriptions[0].get("value", "No description available.") if descriptions else "No description available."
        
        # Extract CVSS Metrics
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

def generate_remediation_card(vuln: dict) -> str:
    """Format parsed vulnerability into a clean Markdown ticket."""
    if not vuln:
        return "Could not generate ticket: CVE not found."
    
    card = f"""### 🛡️ Vulnerability Remediation Ticket: {vuln['id']}

| Attribute | Details |
| :--- | :--- |
| **Vulnerability ID** | `{vuln['id']}` |
| **CVSS Base Score** | **{vuln['score']}** |
| **Severity Tier** | `{vuln['severity']}` |
| **CVSS Vector** | `{vuln['vector']}` |

#### 📝 Technical Summary
{vuln['description']}

#### ⚡ Recommended Remediation Steps
1. **Identify Affected Assets:** Cross-reference internal SBOM/dependency manifests for matches.
2. **Review Vendor Advisory:** Check upstream vendor patch notes associated with `{vuln['id']}`.
3. **Apply Patch / Upgrade:** Update dependency or apply configuration workaround within the SLA window for `{vuln['severity']}` findings.
---
"""
    return card

def main():
    if len(sys.argv) < 2:
        print("Usage: python vulnbridge.py <CVE-ID> (e.g., python vulnbridge.py CVE-2023-38606)")
        return
    
    target_cve = sys.argv[1]
    print(f"[*] Querying NIST NVD for {target_cve}...")
    details = fetch_cve_details(target_cve)
    
    if details:
        ticket = generate_remediation_card(details)
        print("\n" + ticket)
        
        output_filename = f"{target_cve}_ticket.md"
        with open(output_filename, "w") as f:
            f.write(ticket)
        print(f"[✓] Saved remediation card to {output_filename}")
    else:
        print(f"[!] No record found for {target_cve}.")

if __name__ == "__main__":
    main()
