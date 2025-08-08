SOC Tier 1 Analysis Framework

This project is an automated file and URL analysis framework designed to simulate the workflow of a SOC Tier 1 Analyst. It performs static file analysis, enriches indicators using VirusTotal, and provides a comprehensive report with a final threat verdict, all packaged in an easy-to-use graphical interface.

The entire application is containerized with Docker, allowing it to be deployed and run with a single command on any machine with Docker installed.
Features

    Static File Analysis: Computes hashes (MD5, SHA-1, SHA-256), entropy, and checks for suspicious strings, YARA rule matches, and PE file anomalies. It can also analyze files within ZIP archives.

    Threat Intelligence Enrichment: Enriches file hashes and URLs with the latest scan data from VirusTotal.

    Geo-IP Enrichment: Identifies and provides location data for any IP addresses found within a file's contents.

    AI-Powered Summaries: Uses the Gemini API to provide a natural language threat summary and map potential adversary behavior to the MITRE ATT&CK framework.

    Multi-Format Reporting: Automatically exports detailed analysis results to JSON, CSV, and professional PDF formats.

    Graphical User Interface: An intuitive Tkinter GUI for interactive analysis of files and URLs.

    Secure & Containerized: Fully containerized with Docker for easy, one-command deployment. API keys are handled securely and are never stored in the Docker image.

Prerequisites

    Docker

    Docker Compose

How to Run
1. Create the Environment File

Before running the application, you must provide your API keys. In the project's root directory, create a new file named .env.

Copy and paste the following template into your .env file and replace the placeholder text with your actual API keys.

# --- API Keys (Replace with your actual keys) ---
VIRUSTOTAL_API_KEY=YOUR_VT_API_KEY_HERE
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE

# --- API Endpoints (Defaults are usually fine) ---
IP_API_ENDPOINT=[http://ip-api.com/json/](http://ip-api.com/json/)
GEMINI_ENDPOINT=[https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-1.5:generateContent](https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-1.5:generateContent)

2. Authorize GUI Display (Linux/macOS Only)

If you are on Linux or macOS, open a terminal and run the following command. This is a one-time step per session that allows Docker to display the application's GUI on your screen.

xhost +local:docker

3. Build and Run the Container

Open a terminal in the project's root directory (the same folder that contains docker-compose.yml) and run the following command:

docker-compose up --build

This command will build the Docker image, start the container, and launch the application's GUI.
How to Use the Application

    The application's graphical interface will launch automatically.

    To analyze files from your computer, click the "Analyze Files..." button. The file dialog will open directly to a /scannable_files directory, which is securely mapped to your computer's filesystem, allowing you to select any file for analysis.

    To analyze a URL, paste it into the entry box and click "Analyze URL".

    All analysis reports are automatically saved in multiple formats (JSON, CSV, PDF) inside the reports folder in the project directory.
