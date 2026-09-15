from collections import Counter
from io import StringIO
from pathlib import Path
import csv
import re

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = Flask(
    __name__,
    static_folder=str(FRONTEND_DIR),
    static_url_path=""
)

CORS(app)

RISKY_IPS = {
    "185.220.101.12": "Known TOR exit node",
    "45.33.32.156": "Threat intelligence watchlist match"
}

SUSPICIOUS_COMMANDS = [
    "powershell.exe -enc",
    "powershell -enc",
    "mimikatz",
    "certutil -urlcache"
]


def get_field(line, field_name):
    match = re.search(
        rf'{field_name}=("[^"]*"|\S+)',
        line,
        re.IGNORECASE
    )

    if not match:
        return "Unknown"

    return match.group(1).strip('"')


def get_timestamp(line):
    match = re.search(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        line
    )

    return match.group(0) if match else "Unknown time"


def classify_event(lower_line):
    if "auth failed" in lower_line or "event_id=4625" in lower_line:
        return "Failed authentication"

    if "auth success" in lower_line or "event_id=4624" in lower_line:
        return "Successful authentication"

    if "event_id=4720" in lower_line or "user_created" in lower_line:
        return "New user account created"

    if "event_id=4672" in lower_line or "privilege_assigned" in lower_line:
        return "Privileged access assigned"

    if "powershell" in lower_line or "mimikatz" in lower_line:
        return "Suspicious process execution"

    return "System security event"


def convert_csv_to_log_text(csv_text):
    reader = csv.DictReader(StringIO(csv_text))
    normalized_lines = []

    for row in reader:
        timestamp = row.get("timestamp") or row.get("time") or "Unknown"
        event = row.get("event") or row.get("event_type") or "SYSTEM EVENT"
        event_id = row.get("event_id") or "Unknown"
        user = row.get("user") or row.get("username") or "Unknown"
        ip = row.get("ip") or row.get("source_ip") or "Unknown"
        host = row.get("host") or row.get("hostname") or "Unknown"
        command = row.get("command") or row.get("process") or "Unknown"

        normalized_lines.append(
            f'{timestamp} {event} event_id={event_id} '
            f'user={user} ip={ip} host={host} command="{command}"'
        )

    return "\n".join(normalized_lines)


def create_alert(severity, title, evidence, recommendation):
    return {
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "status": "New"
    }


def analyze_log_text(log_text):
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]

    failed_logins = []
    successful_logins = 0
    privilege_events = 0
    alerts = []
    timeline = []
    risky_ip_events = {}

    for line in lines:
        lower_line = line.lower()
        user = get_field(line, "user")
        ip = get_field(line, "ip")

        timeline.append({
            "time": get_timestamp(line),
            "event": classify_event(lower_line),
            "user": user,
            "ip": ip
        })

        is_failed_login = (
            "auth failed" in lower_line
            or "event_id=4625" in lower_line
            or "login_failure" in lower_line
        )

        is_successful_login = (
            "auth success" in lower_line
            or "event_id=4624" in lower_line
            or "login_success" in lower_line
        )

        if is_failed_login:
            failed_logins.append({
                "user": user,
                "ip": ip
            })

        if is_successful_login:
            successful_logins += 1

        if "event_id=4672" in lower_line or "privilege_assigned" in lower_line:
            privilege_events += 1

            alerts.append(create_alert(
                "High",
                "Privileged access assigned",
                f"Elevated privileges were assigned to {user} from IP {ip}.",
                "Validate the access change and confirm the approved ticket."
            ))

        if "event_id=4720" in lower_line or "user_created" in lower_line:
            alerts.append(create_alert(
                "Medium",
                "New user account created",
                f"New account creation detected for user {user} from IP {ip}.",
                "Verify the onboarding request and disable the account if it was not authorized."
            ))

        if ip in RISKY_IPS:
            if ip not in risky_ip_events:
                risky_ip_events[ip] = {
                    "count": 0,
                    "users": set(),
                    "reason": RISKY_IPS[ip]
                }

            risky_ip_events[ip]["count"] += 1
            risky_ip_events[ip]["users"].add(user)

        for command in SUSPICIOUS_COMMANDS:
            if command in lower_line:
                alerts.append(create_alert(
                    "Critical",
                    "Suspicious command execution",
                    f"Command pattern '{command}' was detected for user {user}.",
                    "Isolate the affected system and investigate the process."
                ))
                break

    for ip, details in risky_ip_events.items():
        users = ", ".join(sorted(details["users"]))

        alerts.append(create_alert(
            "High",
            "Risky IP address detected",
            f"{details['count']} event(s) from {ip} matched: {details['reason']}. Affected users: {users}.",
            "Investigate the account activity and block the IP if required."
        ))

    failed_by_ip = Counter(
        item["ip"]
        for item in failed_logins
        if item["ip"] != "Unknown"
    )

    for ip, count in failed_by_ip.items():
        if count >= 5:
            targeted_users = sorted(
                {
                    item["user"]
                    for item in failed_logins
                    if item["ip"] == ip
                }
            )

            alerts.append(create_alert(
                "Critical",
                "Probable brute-force attack",
                f"{count} failed login attempts from {ip} targeting: {', '.join(targeted_users)}.",
                "Block the source IP, review account activity, and reset affected credentials."
            ))

    failed_by_user = Counter(
        item["user"]
        for item in failed_logins
        if item["user"] != "Unknown"
    )

    for user, count in failed_by_user.items():
        if count >= 3:
            alerts.append(create_alert(
                "High",
                "Repeated login failures",
                f"{count} failed login attempts were detected for user {user}.",
                "Contact the user and review MFA and account lockout controls."
            ))

    risk_values = {
        "Low": 1,
        "Medium": 3,
        "High": 6,
        "Critical": 10
    }

    risk_score = min(
        100,
        sum(risk_values[alert["severity"]] for alert in alerts) * 3
    )

    return {
        "summary": {
            "eventsProcessed": len(lines),
            "failedLogins": len(failed_logins),
            "successfulLogins": successful_logins,
            "privilegeEvents": privilege_events,
            "alertsGenerated": len(alerts),
            "riskScore": risk_score
        },
        "alerts": alerts,
        "timeline": list(reversed(timeline))
    }


@app.get("/")
def home():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/health")
def health():
    return jsonify({
        "status": "healthy",
        "service": "SOC Log Analyzer"
    })


@app.post("/api/analyze")
def analyze():
    log_file = request.files.get("logFile")

    if not log_file or not log_file.filename:
        return jsonify({
            "error": "Please upload a log file."
        }), 400

    filename = log_file.filename.lower()

    if not filename.endswith((".log", ".txt", ".csv")):
        return jsonify({
            "error": "Only .log, .txt, and .csv files are supported."
        }), 400

    log_text = log_file.read().decode("utf-8", errors="replace")

    if filename.endswith(".csv"):
        log_text = convert_csv_to_log_text(log_text)

    result = analyze_log_text(log_text)
    result["filename"] = log_file.filename

    return jsonify(result)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)