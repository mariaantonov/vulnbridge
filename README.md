# VulnBridge 🛡️

A lightweight vulnerability triage and remediation card generator that interfaces with the NIST National Vulnerability Database (NVD) REST API to translate raw CVE identifiers into structured, actionable engineering tickets.

## Features
- **NVD API Integration:** Queries live CVSS v3.1 and v3.0 metrics, severity ratings, and technical vector strings.
- **Automated Ticket Formatting:** Generates clean Markdown/Jira-style cards with triage summaries and recommended remediation workflows.
- **Export Ready:** Automatically writes remediation cards to local markdown artifacts for integration into issue trackers.

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/YOUR_USERNAME/vulnbridge.git](https://github.com/YOUR_USERNAME/vulnbridge.git)
   cd vulnbridge