# Modular Subdomain Recon & Infrastructure Mapping Tool

An automated, lightweight Bash script designed for targeted reconnaissance. The tool automates subdomain discovery, performs single-pass HTTP probing with status code categorization, and executes DNS analysis to map target infrastructure and detect Cloudflare WAF usage.

---

## 🚀 Workflow & Features

1. **Subdomain Enumeration & Fallback Strategy:**
   * **Passive Discovery:** Fetches subdomains directly from `crt.sh` using SSL/TLS certificate logs and filters unique subdomains.
   * **Active Brute-forcing:** Automatically prompts for `ffuf` brute-forcing if `crt.sh` is unavailable or fails.
   * **Manual Input Support:** Allows users to supply an existing `all_subdomains.txt` file directly inside the target directory.

2. **Single-Pass HTTP Probing (`httpx`):**
   * Executes a single `httpx` scan across all discovered subdomains to maximize efficiency and minimize execution time.
   * Categorizes response codes dynamically into individual files inside the `status/` directory:
     * **2xx:** `200.txt`, `201.txt`, `202.txt`, `204.txt`
     * **3xx:** `301.txt`, `302.txt`, `307.txt`, `308.txt`
     * **4xx:** `400.txt`, `401.txt`, `403.txt`, `404.txt`

3. **DNS Enumeration & Cloudflare Detection (`dig`):**
   * Normalizes domain inputs by stripping protocols and path suffixes.
   * Extracts `CNAME` records to highlight third-party aliases and identify potential Subdomain Takeover risks.
   * Resolves IPv4 (`A`) addresses and cross-checks them against known Cloudflare IP ranges to flag protected targets.

---

## 📋 Prerequisites

Ensure the following core system utilities and tools are installed on your Linux environment (e.g., Kali Linux, Debian, or Ubuntu):

### Core System Dependencies
```bash
sudo apt update
sudo apt install curl jq sed grep awk dnsutils -y
```

### Reconnaissance Tools
* **[httpx](https://github.com/projectdiscovery/httpx):** Fast HTTP probing utility.
* **[ffuf](https://github.com/ffuf/ffuf):** Fast web fuzzer (required if `crt.sh` fails or brute-forcing is selected).

---

## 🛠️ Usage

1. **Grant execution permission:**
   ```bash
   chmod +x recon.sh
   ```

2. **Execute the script:**
   ```bash
   ./recon.sh
   ```

3. **Provide target details when prompted:**
   * Enter the domain name (e.g., `example.com`).
   * Choose optional brute-force parameters or manual file flags if prompted.

---

## 📂 Output Directory Structure

The script organizes all output into a domain-specific workspace (`target-<domain>/`):

```text
target-example.com/
├── all_subdomains.txt          # Complete list of discovered subdomains
│
├── status/                     # Categorized HTTP response outputs
│   ├── httpx_raw.txt           # Raw output from httpx
│   ├── 200.txt                 # Targets returning 200 OK
│   ├── 301.txt                 # Targets returning 301 Permanent Redirect
│   ├── 403.txt                 # Targets returning 403 Forbidden
│   ├── 404.txt                 # Targets returning 404 Not Found
│   └── ...                     # Additional status codes (201, 202, 302, 307, 400, etc.)
│
└── dns_info/                   # DNS analysis and infrastructure intelligence
    ├── cnames.txt              # Extracted CNAME alias records
    └── dns_summary.txt         # Consolidated report (Subdomain | Resolved IPs | Cloudflare Status)
```
