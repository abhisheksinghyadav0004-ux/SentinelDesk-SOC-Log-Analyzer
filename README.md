# SentinelDesk - SOC Log Analyzer

SentinelDesk is a Blue Team security operations tool that converts raw authentication and system logs into investigation-ready SOC alerts.

It helps analysts quickly identify brute-force activity, suspicious source IPs, privileged access events, malicious command patterns, and unauthorized account creation.

## Real-World Problem

Security teams receive thousands of events from VPN gateways, Windows Event Logs, mail servers, endpoint agents, and Linux systems.

Manual log review is slow and risky. Important events such as repeated failed logins, threat-intelligence matches, privilege escalation, and suspicious PowerShell activity can be missed.

SentinelDesk reduces this investigation time by automatically analyzing uploaded logs and presenting high-priority findings with evidence and recommended actions.

## Key Features

- Upload and analyze `.log`, `.txt`, and `.csv` security logs
- Brute-force attack detection from repeated failed login attempts
- Repeated user login failure detection
- Threat-intelligence matching for suspicious IP addresses
- Privilege escalation detection using Windows Event ID `4672`
- New user account creation detection using Windows Event ID `4720`
- Suspicious PowerShell and command execution detection
- Severity-based alerts: Critical, High, Medium, and Low
- Composite risk score from 0 to 100
- Investigation timeline with user, IP, event type, and timestamp
- Searchable event timeline
- Alert filters for All, Critical, and High severity
- Alert lifecycle: New -> Investigating -> Resolved
- Browser-persistent analyst investigation notes
- Downloadable JSON investigation report
- Drag-and-drop log upload
- Responsive SOC dashboard interface

## Detection Logic

| Threat | Detection Method | Severity |
|---|---|---|
| Brute-force attack | Five or more failed attempts from one IP address | Critical |
| Repeated login failures | Three or more failures for one user | High |
| Risky IP activity | Source IP matches local threat-intelligence list | High |
| Privilege escalation | Windows Event ID `4672` or privilege assignment event | High |
| Suspicious PowerShell | Encoded PowerShell or known suspicious command pattern | Critical |
| New account creation | Windows Event ID `4720` or user creation event | Medium |

## Technology Stack

- Python
- Flask
- Flask-CORS
- HTML5
- CSS3
- JavaScript
- Fetch API
- Local Storage
- Git and GitHub

## Project Structure

```text
SOC-Log-Analyzer/
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .venv/
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── sample_logs/
│   ├── demo_security.log
│   └── demo_security.csv
├── .gitignore
└── README.md
---------------------------------------------------------------------------------------------------------
Installation

Clone the repository:
    1) git clone https://github.com/YOUR-USERNAME/SOC-Log-Analyzer.git
    2) cd SOC-Log-Analyzer
---------------------------------------------------------------------------------------------------------
Create and activate a virtual environment:

    1)cd backend
    2)py -m venv .venv
    3).\.venv\Scripts\Activate.ps1
---------------------------------------------------------------------------------------------------------Install dependencies:
    1)pip install -r requirements.txt
    
Run the application:
    1)py app.py

Open in browser:
    1)http://127.0.0.1:5000

Demo Dataset
  Use the included files:
    1)sample_logs/demo_security.log
    2)sample_logs/demo_security.csv  

The demo dataset simulates:
- Five failed VPN logins from a TOR exit node
- A privilege assignment event
- Suspicious encoded PowerShell execution
- A threat-intelligence IP match
- A new account creation event
---------------------------------------------------------------------------------------------------------
SOC Workflow
  Upload Log File
      |
      v
Parse and Normalize Events
      |
      v
Apply Detection Rules
      |
      v
Generate Severity-Based Alerts
      |
      v
Calculate Risk Score
      |
      v
Review Timeline and Evidence
      |
      v
Investigate, Resolve, and Export Report
---------------------------------------------------------------------------------------------------------
Future Improvements
- Integration with VirusTotal and external threat-intelligence feeds
- Real Windows Event Log (.evtx) support
- User authentication and analyst roles
- Database storage for investigations and cases
- PDF investigation reports
- Alert notifications through email or Slack
- Live log streaming with WebSockets
- MITRE ATT&CK technique mapping
---------------------------------------------------------------------------------------------------------
Author
Abhishek Yadav
Cybersecurity Student | Blue Team and SOC Enthusiast