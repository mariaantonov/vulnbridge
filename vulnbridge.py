import sys
import os
import time
import json
from pathlib import Path
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_score(cve_id: str) -> dict:
    """Fetch 30-day exploit probability and percentile rank from FIRST.org EPSS API."""
    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id.strip().upper()},
            headers={"User-Agent": "VulnBridge-Triage-Tool"},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        records = data.get("data", [])
        if not records:
            return {"available": False}

        record = records[0]
        score = float(record.get("epss", 0.0))
        percentile = float(record.get("percentile", 0.0))

        # Operational EPSS prioritization tiers
        if score >= 0.36:
            tier = "CRITICAL / HIGH PROBABILITY (>=36%)"
        elif score >= 0.10:
            tier = "ELEVATED (10%-35%)"
        else:
            tier = "LOW PROBABILITY (<10%)"

        return {
            "available": True,
            "score": score,
            "percentile": percentile,
            "percentage": f"{score * 100:.2f}%",
            "percentile_rank": f"{percentile * 100:.1f}th percentile",
            "tier": tier,
        }
    except requests.exceptions.RequestException as e:
        print(f"[!] Warning: Unable to check EPSS feed ({e})")
        return {"available": False}


CACHE_DIR = Path.home() / ".cache" / "vulnbridge"
KEV_CACHE_FILE = CACHE_DIR / "cisa_kev.json"
CACHE_TTL_SECONDS = 86400  # 24 hours

def load_cached_kev() -> dict | None:
    """Load CISA KEV from local disk if present and younger than 24 hours."""
    if not KEV_CACHE_FILE.exists():
        return None
    file_age = time.time() - os.path.getmtime(KEV_CACHE_FILE)
    if file_age > CACHE_TTL_SECONDS:
        return None
    try:
        with open(KEV_CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_cached_kev(data: dict) -> None:
    """Write CISA KEV data to disk cache."""
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        with open(KEV_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except OSError:
        pass


def check_cisa_kev(cve_id: str) -> dict:
    """Check if the CVE is in CISA KEV, using local TTL cache when fresh."""
    kev_catalog = load_cached_kev()

    if not kev_catalog:
        try:
            response = requests.get(CISA_KEV_URL, timeout=10)
            response.raise_for_status()
            kev_catalog = response.json()
            save_cached_kev(kev_catalog)
        except requests.exceptions.RequestException as e:
            print(f"[!] Warning: Unable to retrieve CISA KEV feed ({e})")
            return {"is_known_exploited": False}

    for entry in kev_catalog.get("vulnerabilities", []):
        if entry.get("cveID", "").upper() == cve_id.strip().upper():
            return {
                "is_known_exploited": True,
                "date_added": entry.get("dateAdded", "N/A"),
                "due_date": entry.get("dueDate", "N/A"),
                "required_action": entry.get(
                    "requiredAction", "Apply mitigations per vendor guidance."
                ),
            }
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
        desc_text = (
            descriptions[0].get("value", "No description available.")
            if descriptions
            else "No description available."
        )

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
            "description": desc_text,
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {cve_id}: {e}")
        return None


def generate_remediation_card(vuln: dict, kev_data: dict, epss_data: dict) -> str:
    """Format parsed vulnerability into a clean Markdown ticket with threat intel."""
    if not vuln:
        return "Could not generate ticket: CVE not found."

    kev_status = (
        "⚠️ YES (Active In-The-Wild Exploitation)"
        if kev_data.get("is_known_exploited")
        else "No active KEV entry"
    )
    kev_action = (
        kev_data.get("required_action", "Apply vendor patch.")
        if kev_data.get("is_known_exploited")
        else "Standard patching schedule."
    )
    kev_due = (
        kev_data.get("due_date", "Standard SLA")
        if kev_data.get("is_known_exploited")
        else "Standard SLA"
    )

    if epss_data.get("available"):
        epss_prob_str = f"**{epss_data['percentage']}** ({epss_data['tier']})"
        epss_rank_str = f"`{epss_data['percentile_rank']}`"
    else:
        epss_prob_str = "Data unavailable"
        epss_rank_str = "N/A"

    card = f"""### 🛡️ Vulnerability Remediation Ticket: {vuln['id']}

| Attribute | Details |
| :--- | :--- |
| **Vulnerability ID** | `{vuln['id']}` |
| **CVSS Base Score** | **{vuln['score']}** |
| **Severity Tier** | `{vuln['severity']}` |
| **CVSS Vector** | `{vuln['vector']}` |
| **CISA KEV Status** | **{kev_status}** |
| **Federal Due Date** | `{kev_due}` |
| **EPSS Exploit Probability** | {epss_prob_str} |
| **EPSS Percentile Rank** | {epss_rank_str} |

#### 📝 Technical Summary
{vuln['description']}

#### 🚨 Threat Intel & Action Required
- **Mandatory Action:** {kev_action}
- **Triage Context:** EPSS measures probability of exploitation within 30 days. High CVSS with low EPSS suggests lower imminent threat, whereas elevated EPSS demands expedited remediation regardless of CVSS tier.

#### ⚡ Recommended Remediation Steps
1. **Identify Affected Assets:** Cross-reference internal SBOM/dependency manifests.
2. **Review Vendor Advisory:** Check upstream vendor patch notes associated with `{vuln['id']}`.
3. **Emergency Patching:** If listed in CISA KEV or holding an elevated EPSS score, prioritize out-of-band deployment ahead of routine patch cycles.
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

    print(f"[*] Querying FIRST.org EPSS (Exploit Prediction Scoring System)...")
    epss_info = fetch_epss_score(target_cve)

    if details:
        ticket = generate_remediation_card(details, kev_info, epss_info)
        print("\n" + ticket)

        output_filename = f"{target_cve}_ticket.md"
        with open(output_filename, "w") as f:
            f.write(ticket)
        print(f"[✓] Saved remediation card to {output_filename}")
    else:
        print(f"[!] No record found for {target_cve}.")


if __name__ == "__main__":
    main()