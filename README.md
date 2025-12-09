# MacHeimdall — macOS Intrusion Detection & Log Forensic Analysis  
*“Heimdall sees all. So do the logs.”*

MacHeimdall is a DFIR-focused macOS investigation project designed to analyze authentication anomalies, suspicious activity, and system behavior using native macOS logging frameworks.  
This case study simulates unauthorized login attempts and reconstructs an incident timeline using system logs, unified logs, and forensic methodology.

## Objectives
- Extract and analyze macOS Unified Logs
- Identify failed and successful authentication attempts
- Investigate user activity post-login
- Detect suspicious behavior using log predicates
- Correlate findings into a DFIR-style attack timeline
- Map behaviors to MITRE ATT&CK techniques

## Tools Used
- macOS Unified Logging (`log show`)
- Console.app
- System logs (/var/log/system.log, /var/log/secure.log)
- zsh shell analysis
- Python (optional log parsing)
- MITRE ATT&CK mapping

## Evidence
Raw logs and extracted artifacts will be stored in `/evidence/`.

## Analysis
Parsed events, filtered logs, and insights will be documented in `/analysis/`.

## Report
The final DFIR report (PDF) will be placed in `/report/`.

## Status
🟦 Active — Evidence generation begins next.
