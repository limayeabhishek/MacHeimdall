#!/usr/bin/env python3
"""
MacHeimdall Report Generator.

This script processes log files from the 'Evidence' directory, detects security-relevant events,
generates a summary, and outputs an HTML report with event analysis and a graphical representation
of event counts.

Usage:
  python3 generate_report.py

Input:
  - Evidence/*.txt: System log extracts and other evidence files.

Output:
  - analysis/MacHeimdall_Report.html: The comprehensive forensic analysis report.
  - analysis/event_count_graph.png: A bar chart showing event counts by category.

Dependencies:
  - python-dateutil: For robust timestamp parsing. Install via `pip install python-dateutil`.
  - matplotlib: For generating event count graphs. Install via `pip install matplotlib`.
"""

# Standard library imports
import os
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

# Third-party imports
import matplotlib.pyplot as plt
from dateutil.parser import parse as dateutil_parse

from typing import List, Dict, Any

# ---------- Paths / Configuration ----------
EVIDENCE_DIR = "Evidence"
ANALYSIS_DIR = "analysis"
TEMPLATE_FILE = "scripts/report_template.html"
OUTPUT_FILE = os.path.join(ANALYSIS_DIR, "MacHeimdall_Report.html")
EVENT_GRAPH_FILE = os.path.join(ANALYSIS_DIR, "event_count_graph.png")

# ---------- Globals ----------
alerts: List[str] = [] # Added type hint for clarity

# ---------- Utilities ----------
def parse_timestamp(ts_str: str) -> datetime | None:
    """
    Attempts to parse a timestamp string into a timezone-aware UTC datetime object.

    Args:
        ts_str: The timestamp string to parse.

    Returns:
        A timezone-aware datetime object (in UTC) if parsing is successful, otherwise None.
    """
    if not ts_str:
        return None
    try:
        dt = dateutil_parse(ts_str)
        if dt.tzinfo is None: # If timezone-naive, assume local time and convert to UTC
            # Use astimezone with timezone.utc directly, or localize then convert
            # Given that dateutil_parse might infer local timezone, this conversion is safe.
            return dt.astimezone(timezone.utc)
        return dt.astimezone(timezone.utc) # Convert to UTC if already timezone-aware
    except Exception:
        return None
# Standard list of regexes to match different log formats we saw
# Each pattern includes an example and a brief description of its matched groups.
LOG_PATTERNS = [
    # Pattern 1: ISO 8601-like timestamp (e.g., YYYY-MM-DD HH:MM:SS.microseconds+TZ)
    # Matches: timestamp, hostname/process, process_field (e.g., process[pid]), message
    re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+\-]\d{2}:?\d{2})?)\s+([^\s]+)\s+([^:]+):\s*(.*)$"),
    # Pattern 2: syslog-like timestamp (e.g., Month Day HH:MM:SS)
    # Matches: timestamp, hostname/process, process_field (e.g., process[pid]), message
    re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:]+):\s*(.*)$"),
    # Pattern 3: Fallback for YYYY-MM-DD HH:MM:SS with separate date/time fields
    # Matches: date, time, hostname/process, process_field (e.g., process[pid]), message
    re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([^:]+):\s*(.*)$"),
]

def normalize_message(msg: str) -> str:
    """
    Normalizes a log message by handling empty messages and replacing placeholders.

    Args:
        msg: The original log message string.

    Returns:
        The normalized log message.
    """
    if not msg:
        return "(no message)"
    # Replace private placeholders
    msg = msg.replace("<<private>>", "primary macOS user")
    return msg.strip()

def _parse_log_line(line: str, source_file: str) -> Dict[str, Any] | None:
    """
    Attempts to parse a single log line using predefined LOG_PATTERNS.

    Args:
        line: The log line string to parse.
        source_file: The path to the file from which the log line originated.

    Returns:
        A dictionary containing parsed event data if successful, otherwise None.
    """
    for pat in LOG_PATTERNS:
        m = pat.match(line)
        if not m:
            continue
        groups = m.groups()
        ts_str = ""
        proc_name = ""
        msg = ""

        # Patterns produce slightly different groups - map them based on expected structure
        if len(groups) == 4: # For patterns 1 and 2
            ts_str, _, proc_field, msg = groups
            proc_name = proc_field.split('[')[0].strip() # Extract process name from "process[pid]"
        elif len(groups) == 5: # For pattern 3
            ts_str = f"{groups[0]} {groups[1]}"
            proc_name = groups[2] # This seems to be the process field in this pattern
            msg = groups[4]
        else:
            # If a pattern matches but has an unexpected number of groups,
            # this indicates an issue with the pattern or an unhandled log format.
            # In such cases, we return None to indicate parsing failure for this pattern.
            continue # Continue to next pattern if group count is unexpected

        ts = parse_timestamp(ts_str)
        if not ts:
            # If parsing fails, attempt to prepend the current year.
            # This handles log formats where the year is omitted, assuming
            # the log entry is from the current year.
            try:
                ts_try = f"{datetime.now().year} {ts_str}"
                ts = dateutil_parse(ts_try)
            except Exception:
                ts = None # Still None if even year-prefixing fails
        
        # If a pattern matched and we successfully extracted info, return the event
        if ts is not None and proc_name and msg: # Ensure all critical fields are present
            return {
                "timestamp": ts or datetime.fromtimestamp(0, tz=timezone.utc),
                "process": str(proc_name).strip(),
                "message": normalize_message(msg),
                "source_file": source_file
            }
        
    # Last-resort simple parse if no regex matched
    parts = line.split(None, 3)
    if len(parts) >= 4:
        ts_str = f"{parts[0]} {parts[1]}"
        ts = parse_timestamp(ts_str) or datetime.fromtimestamp(0, tz=timezone.utc)
        proc_name = parts[2]
        msg = normalize_message(parts[3])
        return {"timestamp": ts, "process": proc_name, "message": msg, "source_file": source_file}
        
    return None # No pattern matched, no simple split worked

def load_events() -> List[Dict[str, Any]]:
    """
    Loads events from all .txt files found within the EVIDENCE_DIR.

    Each event is represented as a dictionary containing:
    - 'timestamp': datetime object of the event.
    - 'process': Name of the process associated with the event.
    - 'message': The normalized log message.
    - 'source_file': The file path from which the event was loaded.

    Returns:
        A list of dictionaries, each representing a parsed event.
        Returns an empty list if the EVIDENCE_DIR is not found or no events are loaded.
    """
    events: List[Dict[str, Any]] = []
    if not os.path.isdir(EVIDENCE_DIR):
        print(f"Error: Evidence directory '{EVIDENCE_DIR}' not found.")
        return events

    for fn in sorted(os.listdir(EVIDENCE_DIR)):
        if not fn.lower().endswith(".txt"):
            continue
        # Skip system_profile.txt as its content is handled by get_host_summary
        if fn.lower() == "system_profile.txt":
            continue
        path = os.path.join(EVIDENCE_DIR, fn)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    event_data = _parse_log_line(line, path)
                    if event_data:
                        events.append(event_data)
                    else:
                        print(f"Warning: Could not parse log line in {path}: {line}")
        except Exception as e:
            print(f"Error reading {path}: {e}")
    print(f"Loaded {len(events)} events from Evidence.")
    return events

# ---------- Event classification for graphs ----------
def classify_event(e: Dict[str, Any]) -> str:
    """
    Classifies an event into predefined categories based on its message and process.

    Args:
        e: A dictionary representing an event, expected to have 'message' and 'process' keys.

    Returns:
        A string representing the classification category of the event.
    """
    m = e["message"].lower()
    p = e["process"].lower()
    if "failed to authenticate" in m or "failed to authenticate" in p:
        return "Failed Logins"
    if "sudo" in p or "sudo" in m:
        return "Sudo Events"
    if "authorizationhost" in p or "authorization" in p:
        return "Authorization"
    if "login" in p or "sshd" in p:
        return "Login Events"
    return "System Events"

# ---------- Detection modules ----------
def detect_failed_logins(events: List[Dict[str, Any]]) -> List[tuple[datetime, int]]:
    """
    Detects clusters of failed authentication attempts within the event stream.
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.

    Returns:
        A list of tuples, where each tuple contains (timestamp, count) representing
        a detected cluster of failed login attempts.
    """
    failed = [e for e in events if "failed to authenticate" in e["message"].lower() or "failed to authenticate" in e["process"].lower()]
    failed.sort(key=lambda x: x["timestamp"])
    clusters: List[tuple[datetime, int]] = []
    # sliding window: count > threshold within window_minutes
    threshold = 5
    window = timedelta(minutes=10)
    for i in range(len(failed)):
        start_ts = failed[i]["timestamp"]
        # count how many within window from start_ts
        cnt = 1
        j = i + 1
        while j < len(failed) and (failed[j]["timestamp"] - start_ts) <= window:
            cnt += 1
            j += 1
        if cnt >= threshold:
            # identify user if possible
            user_search = re.search(r"user\s+'?([^'\s,]+)'?", failed[i]["message"], re.IGNORECASE)
            user = user_search.group(1) if user_search else "primary macOS user"
            alerts.append(f"Potential Brute-Force Attack: >={cnt} failed logins for user '{user}' within {window} around {start_ts.isoformat()}")
            clusters.append((start_ts, cnt))
            # Deduplicate clusters by timestamp.
            # This converts the list to a dict using isoformat as key to ensure uniqueness,
            # then back to a list, effectively removing duplicates while preserving order.
            unique: Dict[str, tuple[datetime, int]] = {}
            for t, c in clusters:
                unique[t.isoformat()] = (t, c)
            return list(unique.values())
def detect_sudo(events: List[Dict[str, Any]]) -> None:
    """
    Detects suspicious sudo-related activities, such as failures and off-hours usage.
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    sudo_events = [e for e in events if "sudo" in e["process"].lower() or "sudo" in e["message"].lower()]
    for e in sudo_events:
        m = e["message"].lower()
        if "failed to authenticate" in m:
            alerts.append(f"Suspicious sudo failure: {e['message']} at {e['timestamp']}")

def detect_unusual_logins(events: List[Dict[str, Any]]) -> None:
    """
    Detects unusual login activities, specifically logins occurring at off-hours.
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    login_events = [e for e in events if "login" in e["process"].lower() or "sshd" in e["process"].lower() or "login" in e["message"].lower()]
    for e in login_events:
        hour = e["timestamp"].hour if isinstance(e["timestamp"], datetime) else 0
        # unusual hours heuristics: 0-5
        if hour < 5: # Assuming 00:00-04:59 are off-hours
            alerts.append(f"Off-Hours Login: {e['message']} at {e['timestamp']}")

def detect_rapid_failed_logins(events: List[Dict[str, Any]]) -> None:
    """
    Detects very rapid bursts of failed login attempts (e.g., >10 fails in 10 seconds).
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    failed = [e for e in events if "failed to authenticate" in e["message"].lower()]
    failed.sort(key=lambda x: x["timestamp"])
    for i in range(len(failed)):
        j = i + 10
        if j < len(failed):
            if (failed[j]["timestamp"] - failed[i]["timestamp"]) <= timedelta(seconds=10):
                alerts.append(f"High-frequency failed login burst: >10 failed attempts between {failed[i]['timestamp']} and {failed[j]['timestamp']}")

def detect_unusual_sudo_usage(events: List[Dict[str, Any]]) -> None:
    """
    Detects unusual sudo usage patterns, such as invocation by unexpected users or processes.
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    sudo_events = [e for e in events if "sudo" in e["process"].lower() or "sudo" in e["message"].lower()]
    for e in sudo_events:
        # detect odd command strings or root usage strings
        if re.search(r"\b(root|/bin/sh|-c)\b", e["message"], re.IGNORECASE):
            alerts.append(f"Suspicious sudo command or root usage: {e['message']} at {e['timestamp']}")

def detect_authorizationhost_spam(events: List[Dict[str, Any]]) -> None:
    """
    Detects repeated calls to 'authorizationhost' within short intervals, indicative of spamming.
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    auth_events = [e for e in events if "authorizationhost" in e["process"].lower() or "authorizationhost" in e["message"].lower()]
    auth_events.sort(key=lambda x: x["timestamp"])
    for i in range(len(auth_events) - 10):
        if (auth_events[i+10]["timestamp"] - auth_events[i]["timestamp"]) < timedelta(seconds=10):
            alerts.append(f"Authorization Service Spam: >10 calls to 'authorizationhost' in 10s around {auth_events[i]['timestamp']}")

def detect_unexpected_user_activity(events: List[Dict[str, Any]]) -> None:
    """
    Detects activity associated with unexpected or potentially unused user accounts
    (e.g., 'guest', 'test', 'admin').
    Appends relevant alerts to the global 'alerts' list.

    Args:
        events: A list of event dictionaries to analyze.
    """
    unexpected_users = ["guest", "test", "admin", "_mbsetupuser", "unknown"]
    for e in events:
        for user in unexpected_users:
            if user in e["message"].lower():
                alerts.append(f"Anomalous User Activity: Activity detected for a potentially suspicious account '{user}' at {e['timestamp']}")

def detect_log_volume_spike(events: List[Dict[str, Any]]) -> None:
    """
    Detects spikes in logging volume by comparing minute-by-minute event counts
    against an average baseline. Appends alerts if volume exceeds 20% above average.

    Args:
        events: A list of event dictionaries to analyze.
    """
    if not events:
        return
    
    security_processes = ["authorizationhost", "loginwindow", "login", "sshd", "sudo", "authd"]
    ui_processes = ["WindowServer", "BackBoard", "SkyLight", "UIKit"] # Removed "animation/event delivery frameworks" as it's not a process name

    # Filter events based on process names
    filtered_events = []
    for e in events:
        process_name_lower = e["process"].lower()
        is_security_process = any(p in process_name_lower for p in security_processes)
        is_ui_process = any(p in process_name_lower for p in ui_processes)
        
        # Only include if it's a security-relevant process and NOT a UI process
        if is_security_process and not is_ui_process:
            filtered_events.append(e)

    if not filtered_events:
        return

    timeline: Dict[datetime, int] = defaultdict(int)
    for e in filtered_events:
        minute = (e["timestamp"].replace(second=0, microsecond=0) if isinstance(e["timestamp"], datetime) else datetime.fromtimestamp(0))
        timeline[minute] += 1
    if not timeline:
        return
    avg = sum(timeline.values()) / len(timeline)
    for t, count in timeline.items():
        if avg > 0 and count > avg * 1.2:
            alerts.append(f"Log Volume Anomaly: {count} events at {t}, >20% above average ({avg:.1f}). (Security-relevant processes)")

# ---------- Reporting helpers ----------
def format_alerts_html(alerts_list: List[str]) -> str:
    """
    Formats a list of alert strings into HTML divs, removing duplicates while preserving order.

    Args:
        alerts_list: A list of alert messages (strings).

    Returns:
        A single string containing HTML formatted alerts, joined by newlines.
    """
    # remove duplicates while preserving order
    seen = set()
    out = []
    for a in alerts_list:
        if a in seen:
            continue
        seen.add(a)
        out.append(f'<div class="alert"><span class="alert-icon">⚠️</span>{a}</div>')
    return "\n".join(out)

def format_events_table(events: List[Dict[str, Any]], limit: int = 500) -> str:
    """
    Formats a list of event dictionaries into HTML table rows.

    Args:
        events: A list of event dictionaries.
        limit: The maximum number of events to include in the table.

    Returns:
        A string containing HTML table rows for the events.
    """
    rows = []
    for e in events[:limit]:
        ts = e["timestamp"].isoformat() if isinstance(e["timestamp"], datetime) else str(e["timestamp"])
        proc = e["process"]
        msg = e["message"].replace('"', '&quot;')
        rows.append(f"<tr><td>{ts}</td><td>{proc}</td><td>{msg}</td></tr>")
    return "\n".join(rows)

def get_top_messages(events: List[Dict[str, Any]], n: int = 10) -> str:
    """
    Identifies and returns the most common security-relevant messages from the events.

    Args:
        events: A list of event dictionaries.
        n: The number of top messages to retrieve.

    Returns:
        An HTML-formatted string listing the top security-relevant messages and their counts.
    """
    security_processes = ["sudo", "auth", "authorization", "login", "sshd"]
    security_events = [e["message"] for e in events if any(p in e["process"].lower() for p in security_processes)]
    if not security_events:
        return "<li>No security-relevant messages found.</li>"
    top = Counter(security_events).most_common(n)
    return "\n".join([f"<li>{msg}: {count}</li>" for msg, count in top])

def calculate_risk_score(alerts_list: List[str]) -> tuple[int, str]:
    """
    Calculates a risk score based on the detected alerts and assigns a risk status.

    Args:
        alerts_list: A list of alert messages (strings).

    Returns:
        A tuple containing the calculated risk score (int) and its corresponding status (str).
    """
    score = 0
    for a in alerts_list:
        la = a.lower()
        if "high-frequency" in la or "brute-force" in la or "high-frequency failed" in la:
            score += 20
        elif "authorization service spam" in la:
            score += 15
        elif "off-hours" in la or "suspicious sudo" in la or "unexpected user" in la or "anomalous user" in la:
            score += 10
        else:
            score += 5
    score = min(score, 100)
    if score == 0:
        status = "No Risk Detected"
    elif score < 50:
        status = "Moderate Risk"
    else:
        status = "High Risk"
    return score, status

# ---------- Network overview ----------
def get_network_anomaly_overview() -> str:
    """
    Retrieves a best-effort overview of listening TCP ports using `lsof`.

    Returns:
        An HTML string containing a table of listening TCP ports, or an error message
        if `lsof` fails or no ports are found.
    """
    try:
        out = subprocess.check_output("lsof -iTCP -sTCP:LISTEN -n -P", shell=True, text=True, stderr=subprocess.DEVNULL)
        lines = out.strip().splitlines()
        if len(lines) <= 1:
            return "<tr><td colspan='6'>No listening TCP ports found or insufficient privileges.</td></tr>"
        table_rows = []
        header_skipped = lines[0] # lsof header line
        for line in lines[1:]:
            parts = line.split()
            # show the first columns (COMMAND, PID, USER, FD, TYPE, DEVICE, SIZE/OFF, NODE, NAME)
            # We'll join safely up to available columns
            table_rows.append("<tr><td>" + "</td><td>".join(parts[:9]) + "</td></tr>")
        return "\n".join(table_rows)
    except Exception:
        return "<tr><td colspan='6'>Error getting network information (lsof may require sudo).</td></tr>"

# ---------- Graph generation ----------
def generate_event_count_graph(events: List[Dict[str, Any]]) -> None:
    """
    Generates and saves a bar graph of event counts by category.

    Args:
        events: A list of event dictionaries to be categorized and counted.
    """
    if not events:
        return
    categories = [classify_event(e) for e in events]
    counts = Counter(categories)
    # create analysis dir if missing
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    plt.figure(figsize=(8,5))
    plt.bar(list(counts.keys()), list(counts.values()))
    plt.xlabel("Event category")
    plt.ylabel("Count")
    plt.title("Event Count by Category")
    plt.tight_layout()
    plt.savefig(EVENT_GRAPH_FILE)
    plt.close()


# ---------- Host summary ----------
def get_host_summary() -> Dict[str, str]:
    """
    Gathers various host-related information such as macOS version, uptime, and kernel details.

    Returns:
        A dictionary containing host summary information.
    """
    summary: Dict[str, str] = {}
    cmds = {
        "macOS_version": "sw_vers -productVersion",
        "hostname": "hostname",
        "uptime": "uptime",
        "last_reboot": "last reboot | head -n 1",
        "users": "users",
        "filevault_status": "fdesetup status || echo 'Unknown'"
    }
    for k, cmd in cmds.items():
        try:
            summary[k] = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            summary[k] = "Unavailable"
    # extra: kernel version
    try:
        sp = subprocess.check_output("system_profiler SPSoftwareDataType", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in sp.splitlines():
            if "Kernel Version" in line:
                summary["kernel_version"] = line.split(":",1)[1].strip()
            if "Boot Volume" in line:
                summary["boot_volume"] = line.split(":",1)[1].strip()
    except Exception:
        summary.setdefault("kernel_version", "Unavailable")
        summary.setdefault("boot_volume", "Unavailable")
    return summary

import hashlib

def calculate_file_hashes() -> List[Dict[str, str]]:
    """
    Calculates SHA256 hashes for all files in the EVIDENCE_DIR.

    Returns:
        A list of dictionaries, each containing 'filename' and 'hash' (SHA256).
    """
    file_hashes: List[Dict[str, str]] = []
    if not os.path.isdir(EVIDENCE_DIR):
        print(f"Error: Evidence directory '{EVIDENCE_DIR}' not found.")
        return file_hashes

    for fn in sorted(os.listdir(EVIDENCE_DIR)):
        path = os.path.join(EVIDENCE_DIR, fn)
        if os.path.isfile(path):
            try:
                sha256_hash = hashlib.sha256()
                with open(path, "rb") as f:
                    # Read and update hash in chunks to handle large files
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                file_hashes.append({"filename": fn, "hash": sha256_hash.hexdigest()})
            except Exception as e:
                print(f"Error calculating hash for {path}: {e}")
                file_hashes.append({"filename": fn, "hash": "Error calculating hash"})
    return file_hashes

# ---------- HTML generation ----------
def generate_html(events: List[Dict[str, Any]], brute_force_clusters: List[tuple[datetime, int]]) -> None:
    """
    Generates the final HTML report by populating a template with analyzed data.

    Args:
        events: A list of event dictionaries used for various report sections.
        brute_force_clusters: A list of (timestamp, count) tuples representing brute force clusters.
    """
    # compute values
    unique_alerts = list(dict.fromkeys(alerts))  # dedupe
    score, status = calculate_risk_score(unique_alerts)
    status_class = status.lower().replace(" ", "-")
    brute_force_count = sum([c for (t, c) in brute_force_clusters]) if brute_force_clusters else 0
    host_summary = get_host_summary()
    network_overview = get_network_anomaly_overview()
    top_messages = get_top_messages(events)
    file_hashes = calculate_file_hashes() # Get file hashes
    generate_event_count_graph(events)

    # read template
    try:
        with open(TEMPLATE_FILE, "r", encoding="utf-8") as tf:
            template = tf.read()
    except Exception:
        # fallback to a small embedded template if not present
        template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MacHeimdall Security Report</title>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
            <style>
                :root {
                    --primary-color: #4a90e2; /* A modern blue */
                    --secondary-color: #50e3c2; /* A fresh teal */
                    --danger-color: #d0021b; /* A strong red */
                    --warning-color: #f5a623; /* A vibrant orange */
                    --info-color: #7ed321;   /* A calming green for success/info */
                    --light-bg: #f8f9fa; /* Lighter background for sections */
                    --dark-bg: #343a40;  /* Darker background for accents/footer */
                    --text-color: #333d47; /* Darker, more readable text */
                    --light-text: #6c757d; /* Lighter text for secondary info */
                    --border-color: #e0e6ed;
                    --border-radius: 8px;
                    --box-shadow: 0 4px 12px rgba(0,0,0,0.08); /* Softer, larger shadow */
                    --font-family: 'Roboto', sans-serif;
                }

                body {
                    font-family: var(--font-family);
                    margin: 0;
                    padding: 30px 20px;
                    background-color: var(--light-bg);
                    color: var(--text-color);
                    line-height: 1.6;
                }

                .container {
                    max-width: 1100px;
                    margin: auto;
                    background: #ffffff;
                    padding: 40px;
                    box-shadow: var(--box-shadow);
                    border-radius: var(--border-radius);
                    margin-bottom: 30px;
                }

                header {
                    text-align: center;
                    border-bottom: 1px solid var(--border-color);
                    padding-bottom: 25px;
                    margin-bottom: 35px;
                }

                header h1 {
                    color: var(--dark-bg);
                    margin: 0;
                    font-weight: 700;
                    font-size: 2.5em;
                }

                header p {
                    color: var(--light-text);
                    margin: 10px 0 0;
                    font-size: 1.1em;
                }

                .section-title {
                    color: var(--dark-bg);
                    border-bottom: 1px solid var(--border-color);
                    padding-bottom: 15px;
                    margin-top: 40px;
                    margin-bottom: 25px;
                    font-weight: 600;
                    font-size: 1.8em;
                    display: flex;
                    align-items: center;
                }

                .section-title .icon {
                    margin-right: 10px;
                    font-size: 1.2em;
                    color: var(--primary-color);
                }

                .grid-container {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                    gap: 25px;
                    margin-bottom: 30px;
                }

                .card {
                    background: #ffffff;
                    padding: 25px;
                    border-radius: var(--border-radius);
                    box-shadow: var(--box-shadow);
                    transition: transform 0.2s ease-in-out;
                    border: 1px solid var(--border-color);
                    display: flex;
                    flex-direction: column;
                }

                .card:hover {
                    transform: translateY(-8px);
                }

                #brute-force-card:hover {
                    transform: none;
                }

                .card h2 {
                    color: var(--dark-bg);
                    font-size: 1.4em;
                    font-weight: 600;
                    margin-top: 0;
                    margin-bottom: 15px;
                    padding-bottom: 10px;
                    border-bottom: 1px solid var(--border-color);
                }
                
                .card p {
                    margin: 0;
                    font-size: 1em;
                    color: var(--text-color);
                }

                .card .big-number {
                    font-size: 3em;
                    font-weight: 700;
                    text-align: center;
                    color: var(--primary-color);
                    margin-top: 10px;
                }

                .risk-status .big-number {
                    font-size: 3.2em;
                }

                .risk-status.low-risk .big-number { color: var(--info-color); }
                .risk-status.moderate-risk .big-number { color: var(--warning-color); }
                .risk-status.high-risk .big-number { color: var(--danger-color); }

                .alerts-container .alert {
                    background: var(--light-bg);
                    padding: 15px 20px;
                    border-left: 5px solid var(--warning-color);
                    margin: 15px 0;
                    border-radius: var(--border-radius);
                    display: flex;
                    align-items: flex-start;
                    font-weight: 400;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                    line-height: 1.4;
                }
                .alerts-container .alert-icon {
                    font-size: 20px;
                    margin-right: 15px;
                    color: var(--warning-color);
                }

                /* Specific alert styles (if needed) */
                .alerts-container .alert.danger { border-color: var(--danger-color); color: var(--danger-color); }
                .alerts-container .alert.danger .alert-icon { color: var(--danger-color); }

                #event-table {
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 30px;
                    box-shadow: var(--box-shadow);
                    border-radius: var(--border-radius);
                    overflow: hidden;
                }

                #event-table th, #event-table td {
                    border: 1px solid var(--border-color);
                    padding: 12px 15px;
                    text-align: left;
                }

                #event-table th {
                    background-color: var(--dark-bg);
                    color: var(--light-bg);
                    cursor: pointer;
                    font-weight: 600;
                    position: sticky;
                    top: 0;
                    z-index: 1;
                }

                #event-table tbody tr:nth-child(even) {
                    background-color: var(--light-bg);
                }

                #event-table tbody tr:hover {
                    background-color: #e9ecef;
                    transition: background-color 0.1s ease-in-out;
                }
                
                .search-bar {
                    width: 100%;
                    padding: 12px 15px;
                    margin-bottom: 20px;
                    border: 1px solid var(--border-color);
                    border-radius: var(--border-radius);
                    box-sizing: border-box;
                    font-size: 1em;
                    transition: border-color 0.2s;
                }
                .search-bar:focus {
                    border-color: var(--primary-color);
                    outline: none;
                }

                .pagination {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin-top: 30px;
                    gap: 10px;
                }
                
                .pagination button {
                    background-color: var(--primary-color);
                    color: #ffffff;
                    border: none;
                    padding: 10px 18px;
                    cursor: pointer;
                    border-radius: 5px;
                    transition: background-color 0.2s ease-in-out, transform 0.1s ease-in-out;
                    font-size: 0.95em;
                    font-weight: 500;
                }
                
                .pagination button:hover:not(:disabled) {
                    background-color: #3a82cc;
                    transform: translateY(-2px);
                }
                .pagination button.active {
                    background-color: var(--dark-bg);
                    transform: translateY(-2px);
                }
                .pagination button:disabled {
                    background-color: #ced4da;
                    cursor: not-allowed;
                    transform: none;
                }

                .graph-container {
                    text-align: center;
                    margin-top: 40px;
                    padding-top: 30px;
                    border-top: 1px solid var(--border-color);
                }
                .graph-container img {
                    max-width: 100%;
                    height: auto;
                    border-radius: var(--border-radius);
                    box-shadow: var(--box-shadow);
                }
                .graph-container p {
                    color: var(--light-text);
                    margin-top: 15px;
                    font-size: 0.95em;
                }

                footer {
                    text-align: center;
                    margin-top: 50px;
                    padding-top: 25px;
                    border-top: 1px solid var(--border-color);
                    color: var(--light-text);
                    font-size: 0.9em;
                }

                /* Responsive adjustments */
                @media (max-width: 768px) {
                    body {
                        padding: 15px;
                    }
                    .container {
                        padding: 25px;
                    }
                    .grid-container {
                        grid-template-columns: 1fr;
                    }
                    .card h2 {
                        font-size: 1.2em;
                    }
                    .card .big-number {
                        font-size: 2.5em;
                    }
                    header h1 {
                        font-size: 2em;
                    }
                    .section-title {
                        font-size: 1.5em;
                    }
                }
            </style>
        </head>
        <body>
            <div class="container">
                <header>
                    <h1>MacHeimdall Forensic Security Report</h1>
                    <p>Generated on: {generation_date}</p>
                </header>

                <div class="grid-container">
                    <div class="card risk-score">
                        <h2>Risk Score</h2>
                        <span class="big-number">{score}/100</span>
                    </div>
                    <div class="card risk-status {status_class}">
                        <h2>Status</h2>
                        <span class="big-number">{status}</span>
                    </div>
                    <div class="card" id="brute-force-card">
                        <h2>Brute Force Attempts</h2>
                        <span class="big-number">{brute_force_count}</span>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title"><span class="icon">💻</span> Host System Summary</h2>
                    <div class="grid-container">
                        <div class="card">
                            <p><strong>Operating System:</strong> {macOS_version}</p>
                            <p><strong>Kernel Version:</strong> {kernel_version}</p>
                            <p><strong>Hostname:</strong> {hostname}</p>
                            <p><strong>Boot Volume:</strong> {boot_volume}</p>
                            <p><strong>System Uptime:</strong> {uptime}</p>
                            <p><strong>Last Reboot Time:</strong> {last_reboot}</p>
                            <p><strong>Current Users:</strong> {users}</p>
                            <p><strong>FileVault Encryption Status:</strong> {filevault_status}</p>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title"><span class="icon">🚨</span> Detected Alerts</h2>
                    <div class="alerts-container">
                        {alerts}
                    </div>
                </div>
                
                <div class="card">
                    <h2 class="section-title"><span class="icon">🗃️</span> Evidence File Hashes</h2>
                    <div class="table-responsive">
                        <table id="file-hashes-table">
                            <thead>
                                <tr>
                                    <th>Filename</th>
                                    <th>SHA256 Hash</th>
                                </tr>
                            </thead>
                            <tbody>
                                {file_hashes_table}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title"><span class="icon">📡</span> Network Anomaly Overview (LSOF)</h2>
                    <div class="table-responsive">
                        <table id="network-table">
                            <thead>
                                <tr>
                                    <th>COMMAND</th><th>PID</th><th>USER</th><th>FD</th><th>TYPE</th><th>DEVICE</th><th>SIZE/OFF</th><th>NODE</th><th>NAME</th>
                                </tr>
                            </thead>
                            <tbody>
                                {network_anomaly_overview}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div class="card">
                    <h2 class="section-title"><span class="icon">💬</span> Top Security Messages</h2>
                    <ol>{top_messages}</ol>
                </div>

                <div class="card">
                    <h2 class="section-title"><span class="icon">📊</span> Event Count Graph</h2>
                    <div class="graph-container">
                        <img src="event_count_graph.png" alt="Event Count by Category Graph">
                        <p>Distribution of events by category.</p>
                    </div>
                </div>
            </div>

            <footer>
                <p>Report generated by MacHeimdall. For forensic analysis only.</p>
            </footer>

            <script>
                // Basic JavaScript for table sorting and pagination
                function sortTable(n) {
                    const table = document.getElementById("event-table"); // Assuming event-table is still there for sorting logic
                    if (!table) return; // Add a check to prevent errors if the table is removed
                    // ... (sorting logic)
                }

                const rowsPerPage = 50;
                let currentPage = 1;
                let filteredRows = [];
                let allEventsRows = []; // To store all event rows before filtering

                // This function is still needed for any sorting or filtering that might be applied to other tables,
                // or if the event-table is re-introduced. Currently, it will not be called for the main event table.
                function initPagination() {
                    const table = document.getElementById("event-table");
                    if (!table) return; // Add a check to prevent errors if the table is removed
                    const tr = table.getElementsByTagName("tr");
                    allEventsRows = Array.from(tr).slice(1); // Exclude header row
                    filteredRows = [...allEventsRows];
                    showPage(1);
                }

                function showPage(page) {
                    const tbody = document.getElementById("events-tbody"); // Assuming events-tbody is still there
                    if (!tbody) return; // Add a check to prevent errors if the tbody is removed
                    tbody.innerHTML = '';
                    const start = (page - 1) * rowsPerPage;
                    const end = start + rowsPerPage;
                    const paginatedRows = filteredRows.slice(start, end);

                    paginatedRows.forEach(row => tbody.appendChild(row));
                    updatePaginationControls(filteredRows.length);
                }

                function nextPage() {
                    if (currentPage * rowsPerPage < filteredRows.length) {
                        currentPage++;
                        showPage(currentPage);
                    }
                }

                function prevPage() {
                    if (currentPage > 1) {
                        currentPage--;
                        showPage(currentPage);
                    }
                }

                function updatePaginationControls(totalRows) {
                    const paginationDiv = document.querySelector(".search-and-pagination .pagination");
                    if (!paginationDiv) return; // Add a check
                    const pageInfo = document.getElementById("pageInfo");
                    const prevBtn = document.getElementById("prevBtn");
                    const nextBtn = document.getElementById("nextBtn");
                    
                    const pageCount = Math.ceil(totalRows / rowsPerPage);
                    if (pageInfo) pageInfo.innerText = `Page ${currentPage} of ${pageCount}`;
                    if (prevBtn) prevBtn.disabled = currentPage === 1;
                    if (nextBtn) nextBtn.disabled = currentPage === pageCount;
                }

                const searchInput = document.getElementById("searchInput");
                if (searchInput) { // Add a check to prevent errors if the searchInput is removed
                    searchInput.addEventListener("keyup", function() {
                        const filter = searchInput.value.toLowerCase();
                        filteredRows = allEventsRows.filter(row => row.innerText.toLowerCase().includes(filter));
                        currentPage = 1;
                        showPage(currentPage);
                    });
                }

                // Add event listeners for sorting other tables if they exist
                document.querySelectorAll('table th').forEach(headerCell => {
                    headerCell.addEventListener('click', () => {
                        const table = headerCell.closest('table');
                        if (!table) return;

                        const column = headerCell.cellIndex;
                        const order = headerCell.classList.contains('sorted-asc') ? 'desc' : 'asc';
                        const tbody = table.querySelector('tbody');
                        if (!tbody) return;
                        
                        const rows = Array.from(tbody.querySelectorAll('tr'));

                        rows.sort((a, b) => {
                            let aVal = a.cells[column].innerText;
                            let bVal = b.cells[column].innerText;
                            
                            // Basic type conversion for sorting (e.g., numbers)
                            if (!isNaN(parseFloat(aVal)) && isFinite(aVal) && !isNaN(parseFloat(bVal)) && isFinite(bVal)) {
                                aVal = parseFloat(aVal);
                                bVal = parseFloat(bVal);
                            } else if (column === 0 && (table.id === "event-table" || table.id === "file-hashes-table")) { // Assuming timestamp or filename column
                                // Attempt to parse as Date for timestamp column, otherwise compare as string
                                try {
                                    aVal = new Date(aVal);
                                    bVal = new Date(bVal);
                                } catch (e) {
                                    // Fallback to string comparison
                                }
                            }

                            if (order === 'asc') {
                                return aVal > bVal ? 1 : -1;
                            } else {
                                return aVal < bVal ? 1 : -1;
                            }
                        });

                        tbody.innerHTML = '';
                        rows.forEach(row => tbody.appendChild(row));
                        
                        table.querySelectorAll('th').forEach(th => th.classList.remove('sorted-asc', 'sorted-desc'));
                        headerCell.classList.add(order === 'asc' ? 'sorted-asc' : 'sorted-desc');
                    });
                });

                window.onload = initPagination;
            </script>
        </body>
        </html>
"""

    # Format file hashes into HTML table rows
    file_hashes_html_rows = ""
    if file_hashes:
        file_hashes_html_rows = "\n".join([f"<tr><td>{f['filename']}</td><td>{f['hash']}</td></tr>" for f in file_hashes])
    else:
        file_hashes_html_rows = "<tr><td colspan='2'>No evidence files found or hashes could not be calculated.</td></tr>"

    # Replace braces safely: template may use Jinja-like braces. We'll replace placeholders used in your template.
    # Prepare mapping:
    mapping = {
        "{generation_date}": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "{score}": str(score),
        "{status}": status,
        "{status_class}": status_class,
        "{alerts}": format_alerts_html(unique_alerts),
        "{brute_force_count}": str(brute_force_count),
        "{network_anomaly_overview}": network_overview,
        "{top_messages}": top_messages,
        "{file_hashes_table}": file_hashes_html_rows, # New placeholder for file hashes
        "{macOS_version}": host_summary.get("macOS_version", "Unknown"),
        "{kernel_version}": host_summary.get("kernel_version", "Unknown"),
        "{hostname}": host_summary.get("hostname", "Unknown"),
        "{boot_volume}": host_summary.get("boot_volume", "Unknown"),
        "{uptime}": host_summary.get("uptime", "Unknown"),
        "{last_reboot}": host_summary.get("last_reboot", "Unknown"),
        "{users}": host_summary.get("users", "Unknown"),
        "{filevault_status}": host_summary.get("filevault_status", "Unknown"),
    }

    # Replace placeholders in the template. Supports both {key} and {{key}} formats.
    for k, v in mapping.items():
        # First, try to replace {{key}} style placeholders
        template = template.replace("{{" + k.strip("{}") + "}}", v)
        # Then, replace {key} style placeholders
        template = template.replace(k, v)

    # Ensure analysis dir
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f:
        out_f.write(template)

    print("Wrote report to:", OUTPUT_FILE)
    print("Wrote event graph to:", EVENT_GRAPH_FILE)

# ---------- Main pipeline ----------
def main() -> None:
    """
    Main function to orchestrate the report generation process.
    Loads events, runs detectors, and generates the final HTML report.
    """
    alerts.clear()
    events = load_events()
    if not events:
        print("No events loaded. Put log .txt files in the Evidence/ directory and retry.")
        return
    # normalize and sort
    events = sorted(events, key=lambda x: x["timestamp"])

    # Run all detectors (order doesn't matter, but keep consistent)
    brute_force = detect_failed_logins(events)        # returns list of (ts,count)
    detect_sudo(events)
    detect_unusual_logins(events)
    detect_rapid_failed_logins(events)
    detect_unusual_sudo_usage(events)
    detect_authorizationhost_spam(events)
    detect_unexpected_user_activity(events)
    detect_log_volume_spike(events)

    # generate HTML
    generate_html(events, brute_force)

if __name__ == "__main__":
    main()
