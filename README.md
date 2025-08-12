# SOC Tier 1 Analysis Framework

**IOC Analyzer** is an automated file and URL analysis tool designed to simulate the workflow of a SOC Tier 1 Analyst.  
It helps you quickly analyze suspicious files and URLs, enriches indicators with threat intelligence, and generates professional reports.  
The entire application is containerized with Docker for easy, one-command deployment.

---

## Features

- **Static File Analysis**
  - Calculates MD5, SHA-1, and SHA-256 hashes
  - Measures file entropy
  - Detects suspicious strings
  - Matches YARA rules
  - Flags anomalies in PE files
  - Analyzes files inside ZIP archives

- **Threat Intelligence Enrichment**
  - Enriches file hashes and URLs with the latest VirusTotal scan data

- **Geo-IP Enrichment**
  - Identifies and locates IP addresses found in files

- **AI-Powered Summaries**
  - Uses Gemini API to generate natural language threat summaries
  - Maps findings to the MITRE ATT&CK framework

- **Multi-Format Reporting**
  - Exports results automatically as JSON, CSV, and PDF

- **Graphical User Interface**
  - Simple Tkinter GUI for interactive file and URL analysis

- **Secure & Containerized**
  - Dockerized for easy, secure deployment
  - API keys are handled securely and never stored in the Docker image

---

## Prerequisites

- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

---

## Quick Start

### 1. Create the Environment File

In the project root directory, create a file named `.env` and add your API keys:

```env
# --- API Keys (replace with your actual keys) ---
VIRUSTOTAL_API_KEY=YOUR_VT_API_KEY_HERE
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE

# --- API Endpoints (defaults are usually fine) ---
IP_API_ENDPOINT=http://ip-api.com/json/
GEMINI_ENDPOINT=https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent
```

---

### 2. Authorize GUI Display (Linux/macOS only)

Open a terminal and run (one-time per session):

```sh
xhost +local:docker
```

---

### 3. Build and Run the Container

From the project root directory (where `docker-compose.yml` is), run:

```sh
docker-compose up --build
```

This will build the Docker image, start the container, and launch the application's GUI.

---

##  How to Use

1. **The graphical interface will launch automatically.**
2. **Analyze Files:**  
   Click the `Analyze Files...` button. Select files from the `/scannable_files` directory (securely mapped to your computer).
3. **Analyze URLs:**  
   Paste a URL into the entry box and click `Analyze URL`.
4. **Reports:**  
   All analysis results are saved automatically in `reports/` as JSON, CSV, and PDF.

---

##  Project Structure

- `/scannable_files` — Directory mapped for file analysis
- `/reports` — All output reports saved here

---

##  Notes

- API keys are **never** stored in the Docker image.
- If you encounter issues, make sure Docker and Docker Compose are installed and up to date.

---

##  Need Help?

Open an issue or discussion on GitHub for support or questions!
