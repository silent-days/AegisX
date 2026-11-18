 <div align="center">

<img src="assets/icons/aegisx.png" width="150" alt="AegisX Logo">

# AEGISX

### GLOBAL CYBER THREAT INTELLIGENCE

**Next-Generation Cyber Threat Intelligence Desktop Platform for Kali Linux**

[![Version](https://img.shields.io/badge/Version-1.0-e53935?style=for-the-badge)](https://github.com/silent-days/AegisX)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

**Collect • Analyze • Correlate • Investigate • Protect**

[Installation](#-installation) · [Features](#-key-features) · [Screenshots](#-screenshots) · [API Setup](#-api-configuration) · [Architecture](#-project-architecture)

**Developed by Silent Days**

</div>

---

## Overview

**AegisX** is a next-generation Global Cyber Threat Intelligence platform designed as a native desktop application for Kali Linux.

Built with Python and PySide6, AegisX provides a centralized environment for collecting, analyzing, correlating, and visualizing cyber threat intelligence from multiple OSINT sources.

The platform investigates suspicious IP addresses, domains, and network infrastructure through real intelligence providers, evidence-based risk scoring, interactive visualizations, and professional investigation reports.

AegisX combines multiple intelligence capabilities into one modern desktop interface, helping security researchers and cybersecurity professionals understand and investigate potential threats.

### Intelligence Without Fabrication

AegisX follows an evidence-based intelligence approach:

- Keyless community sources provide real intelligence without API keys.
- Optional API integrations expand intelligence coverage.
- Unconfigured providers are clearly identified.
- Demonstration records use reserved documentation IP ranges and example domains.
- Threat attribution is never presented as fact without supporting evidence.

---

## Screenshots

Explore the AegisX desktop interface and its intelligence capabilities.

### Command Center

| Dashboard | Global Threat Map |
|:---:|:---:|
| ![Dashboard](assets/screenshots/dashboard.png) | ![Global Threat Map](assets/screenshots/global_map.png) |
| **Main Intelligence Dashboard** | **Global Threat Visualization** |

### Threat Investigation

| IP Investigation | Domain Intelligence |
|:---:|:---:|
| ![IP Investigation](assets/screenshots/ip_investigation.png) | ![Domain Intelligence](assets/screenshots/domain_intelligence.png) |

### Intelligence & Analytics

| Threat Analytics | Threat Correlation |
|:---:|:---:|
| ![Analytics](assets/screenshots/analytics.png) | ![Correlation](assets/screenshots/correlation.png) |

| Campaign Intelligence | Infrastructure Analysis |
|:---:|:---:|
| ![Campaigns](assets/screenshots/campaigns.png) | ![Infrastructure](assets/screenshots/infrastructure.png) |

### Investigation & Reporting

| Investigation Workspace | Professional Reports |
|:---:|:---:|
| ![Investigations](assets/screenshots/investigations.png) | ![Reports](assets/screenshots/reports.png) |

### Threat Management

| Threat Intelligence | Intelligence Sources |
|:---:|:---:|
| ![Threat Intelligence](assets/screenshots/threat_intelligence.png) | ![Sources](assets/screenshots/sources.png) |

### Application

| Settings | About AegisX |
|:---:|:---:|
| ![Settings](assets/screenshots/settings.png) | ![About](assets/screenshots/about.png) |

---

## Key Features

### 1. Intelligence Command Center

- Modern centralized security dashboard.
- Animated threat monitoring indicators.
- 3D command gauges and threat statistics.
- Live-style global network topology visualization.
- Severity overview and activity timeline.
- Top threat indicators with filtering.
- Intelligence activity monitoring.

### 2. Advanced Threat Intelligence

- Centralized indicator management.
- IP address and domain investigation.
- Risk-based threat classification.
- Advanced filtering by source, tag, risk, and recency.
- Bulk indicator management.
- Re-analysis and export functionality.

### 3. Global Threat Map

- Interactive world threat visualization.
- Severity-based threat markers.
- Animated attack-flow visualization.
- Global threat activity feed.
- Offline-capable map visualization.

### 4. IP Investigation

- Multi-provider IP reputation analysis.
- IP geolocation and ASN information.
- Abuse confidence and reputation evidence.
- Animated risk gauge.
- MITRE ATT&CK technique associations.
- Provider-based intelligence results.

### 5. Domain Intelligence

- DNS record investigation.
- Domain resolution.
- TLS certificate inspection.
- Certificate transparency subdomain discovery.
- Domain reputation analysis.

### 6. Infrastructure Analysis

- ASN concentration analysis.
- Hosting country statistics.
- Indicator distribution.
- Infrastructure cluster visualization.
- Interactive relationship graphs.

### 7. Threat Correlation

- Evidence-based relationship discovery.
- Shared ASN correlation.
- DNS relationship analysis.
- Campaign and tag similarity.
- Interactive graph visualization.
- Supporting evidence inspection.

### 8. Campaign Intelligence

- Threat campaign clustering.
- Campaign timelines.
- Confidence-based intelligence.
- Related indicator analysis.
- Evidence-based attribution handling.

### 9. Threat Analytics

- Threat activity statistics.
- Severity distribution.
- Confidence analysis.
- Intelligence source contribution.
- MITRE ATT&CK technique frequency.
- PNG chart export.

### 10. Investigation Workspace

- Centralized investigation management.
- Investigation items and evidence.
- Timestamped investigation notes.
- Multi-panel workspace.
- One-click report generation.

### 11. Intelligence Source Management

- Centralized provider configuration.
- Real provider connectivity tests.
- Capability and status indicators.
- Rate-limit management.
- Cache statistics.
- Optional API integrations.

### 12. Professional Reporting

- Branded HTML investigation reports.
- JSON report exports.
- Evidence and source attribution.
- Risk and confidence information.
- Investigation methodology and disclaimers.

---

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3.9+ |
| Desktop GUI | PySide6 / Qt 6 |
| Data Visualization | PyQtGraph |
| Custom Graphics | QPainter |
| Database | SQLite |
| HTTP Requests | Requests |
| Intelligence Engine | Pure Python |
| Security | System Keyring / Encrypted Key Storage |
| Background Tasks | QThreadPool |
| Operating System | Kali Linux / Debian |

---

## Installation

### Requirements

- Kali Linux or compatible Debian-based distribution.
- Python 3.9 or newer.
- Internet connection for initial installation.
- Root privileges for system-wide installation.

### 1. Clone the Repository

```bash
git clone https://github.com/silent-days/AegisX.git
```

### 2. Navigate to the Project

```bash
cd AegisX
```

### 3. Install AegisX

```bash
sudo bash install.sh
```

The installer automatically:

1. Detects the operating system.
2. Checks Python compatibility.
3. Installs required system dependencies.
4. Creates the `/opt/AegisX/` directory.
5. Copies application files.
6. Creates an isolated Python virtual environment.
7. Installs required Python packages.
8. Configures the system-wide launcher.
9. Creates a Kali Applications Menu entry.
10. Installs the application icon.
11. Applies safe file permissions.
12. Validates the installation.

**Note:** The installer is designed to be re-run safely for upgrades while preserving existing user data.

### 4. Launch AegisX

```bash
aegisx
```

Alternatively, open **Kali Applications → Security → AegisX**.

---

## API Configuration

AegisX integrates multiple intelligence providers to expand investigation capabilities.

### Built-in Keyless Intelligence

These community sources work without API keys:

| Provider | Capabilities |
|---|---|
| Community DNS Intel | Spamhaus reputation, Tor exit-node detection, reverse DNS |
| DNS over HTTPS | A, NS, MX, TXT records and DNS intelligence |
| OpenGeo Web | IP geolocation, country, city, ASN, organization |

### Optional Intelligence Providers

| Provider | API Key | Purpose |
|---|:---:|---|
| AbuseIPDB | Required | IP abuse reputation |
| AlienVault OTX | Required | Threat intelligence pulses |
| VirusTotal | Required | Multi-engine threat analysis |
| URLhaus | Free Auth-Key | Malicious URL intelligence |
| ThreatFox | Free Auth-Key | Malware-related IOC intelligence |
| MaxMind GeoIP | Local Database | IP geolocation |

### Configure API Keys

1. Open AegisX.
2. Navigate to **Settings → Intelligence Sources**.
3. Select the provider.
4. Open its configuration dialog.
5. Enter the API key.
6. Test the connection.
7. Save the configuration.

API credentials are stored using the system keyring when available, with an encrypted local-file fallback.

**Important:** URLhaus and ThreatFox require a free abuse.ch Auth-Key for their data queries.

### API Resources

- [AbuseIPDB](https://www.abuseipdb.com/account/api)
- [AlienVault OTX](https://otx.alienvault.com/settings/api)
- [VirusTotal](https://docs.virustotal.com/reference/overview)
- [abuse.ch Authentication](https://auth.abuse.ch/)
- [MaxMind GeoLite2](https://dev.maxmind.com/geoip/docs/databases/city-and-country)

Detailed instructions: [API Setup Guide](docs/API_SETUP.md).

---

## Project Architecture

AegisX uses a modular architecture that separates the graphical interface, intelligence engine, providers, database, visualization, and security components.

```text
AegisX/
│
├── install.sh
├── uninstall.sh
├── upgrade.sh
├── run.sh
├── entrypoint.py
├── requirements.txt
│
├── src/
│   └── aegisx/
│       ├── main.py
│       ├── application.py
│       │
│       ├── core/
│       │   ├── intelligence_engine.py
│       │   ├── correlation_engine.py
│       │   ├── risk_engine.py
│       │   ├── indicator_manager.py
│       │   ├── mitre.py
│       │   └── services.py
│       │
│       ├── providers/
│       │   ├── abuseipdb.py
│       │   ├── otx.py
│       │   ├── virustotal.py
│       │   ├── urlhaus.py
│       │   ├── threatfox.py
│       │   ├── community_dns.py
│       │   ├── dns_over_https.py
│       │   ├── opengeo.py
│       │   └── geoip.py
│       │
│       ├── database/
│       ├── ui/
│       ├── visualization/
│       ├── reports/
│       ├── security/
│       ├── workers/
│       ├── utils/
│       └── styles/
│
├── assets/
│   ├── icons/
│   ├── logos/
│   └── screenshots/
│
├── docs/
│   ├── API_SETUP.md
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md
│   ├── FEATURES.md
│   └── INSTALLATION.md
│
└── tests/
```

---

## Security & Privacy

AegisX is designed with security-conscious development practices.

- **Secure Credentials:** API keys are stored through the system keyring when available, with an encrypted local fallback.
- **HTTPS Communication:** Intelligence providers are accessed through their official endpoints.
- **Request Protection:** Provider requests use timeouts, retry/backoff, rate limiting, and caching.
- **Local Storage:** Investigation data and reports are stored locally.
- **No Telemetry:** No third-party analytics or application telemetry.
- **Honest Intelligence:** Demonstration data is clearly separated from live intelligence.
- **Evidence-Based Analysis:** Findings include source attribution and confidence information.

---

## Development

### Run from Source

```bash
bash run.sh
```

The source launcher creates a virtual environment, installs the required dependencies, and launches the application.

### Run Tests

```bash
python -m pytest tests/
```

### Useful Commands

```bash
aegisx --version
aegisx --info
```

### Upgrade

```bash
sudo bash upgrade.sh
```

Create a backup before upgrading:

```bash
sudo bash upgrade.sh --backup
```

### Uninstall

Remove the application while preserving user data:

```bash
sudo bash uninstall.sh
```

Remove application and user data:

```bash
sudo bash uninstall.sh --purge-data
```

**Warning:** The purge option removes stored configuration, investigations, reports, and logs after confirmation.

---

## Documentation

Additional project documentation:

- [Installation Guide](docs/INSTALLATION.md)
- [API Setup Guide](docs/API_SETUP.md)
- [Architecture Documentation](docs/ARCHITECTURE.md)
- [Development Guide](docs/DEVELOPMENT.md)
- [Features Documentation](docs/FEATURES.md)

---

## Project Information

| Information | Details |
|---|---|
| Project | AegisX |
| Version | 1.0 |
| Category | Cyber Threat Intelligence |
| Platform | Kali Linux |
| Language | Python |
| GUI Framework | PySide6 |
| Developer | Silent Days |
| License | MIT |

## Disclaimer

AegisX is developed for cybersecurity research, defensive security analysis, threat intelligence, and educational purposes.

Users are responsible for ensuring that their investigations and activities comply with applicable laws, regulations, and third-party service terms.

AegisX is an independent project and is not affiliated with or endorsed by Kali Linux, Offensive Security, or any integrated intelligence provider.

---

## License

This project is released under the **MIT License**.

See the [LICENSE](LICENSE) file for details.

---

<div align="center">

<img src="assets/icons/aegisx.png" width="85" alt="AegisX">

### AEGISX

**Global Cyber Threat Intelligence**

Built with precision. Powered by intelligence.

**Developed by Silent Days**

[GitHub Repository](https://github.com/silent-days/AegisX)

*Secure • Analyze • Investigate • Protect*

</div>
