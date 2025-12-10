# 🔱 MacHeimdall – macOS Forensic Evidence Analyzer

**MacHeimdall** is a lightweight, offline, evidence-driven macOS forensic analysis toolkit built in Python.  
It performs **log extraction, event correlation, intrusion detection, anomaly scoring**, and generates a complete human-readable **HTML forensic report** with charts, file integrity hashes, and host metadata.

Designed for:
- 🕵️‍♂️ Digital Forensics Students  
- 🔐 Incident Responders  
- 📊 Security Researchers  
- 🧪 macOS Internals Learners  

Heimdall, the guardian who sees all nine realms, now watches over your **macOS logs**.

---

## ⚡ Key Features

### 🔍 **Evidence Parsing**
- Reads macOS log extracts (`system.log`, Unified Log dumps, auth logs, sudo logs, etc.)
- Auto-detects multiple timestamp formats  
- Normalizes and sanitizes messages

### 🛡️ **Detection Engine**
MacHeimdall includes several forensic detection modules:

- 🚫 **Brute Force Attack Detection**  
- 🔑 **Rapid Authentication Failure Bursts**  
- 🕒 **Off-hours Login/Sudo Activity**  
- 👤 **Suspicious User Accounts (guest, test, etc.)**  
- ⚙️ **Authorization Service Spam (authorizationhost)**  
- 📈 **Log Volume Spike Detection**

All alerts contribute to a computed **Risk Score (0–100)**.

---

## 📄 **Automated Forensic Report**
Generates a fully offline HTML report containing:

### 🧭 **Host Summary**
- macOS version  
- Kernel version  
- Uptime  
- Boot volume  
- Logged-in users  
- FileVault status  

### 🔐 **Evidence File Hashes (SHA-256)**
Ensures **integrity & admissibility** in legal proceedings.

### 📊 **Visualizations**
- Event category bar graph  
- (Optional) Heatmaps, timelines, and more  

### ⚠️ **Alert Summary**
- All detections explained
- Brute-force clusters highlighted
- Suspicious sequences visualized

---

## 🗂️ Project Structure

MacHeimdall/
│
├── Evidence/              # Log files
├── analysis/              # Generated reports + graphs
├── scripts/               # Python engine + HTML template
├── Screenshots/           # Example outputs
├── requirements.txt
└── README.md


---

## 🚀 How to Use

### 1️⃣ Install dependencies  

### 2️⃣ Place macOS log files into `Evidence/`

The toolkit supports:
- extracted unified logs  
- `/var/log/system.log`  
- authentication logs  
- sudo logs  
- snapshot/process reports  

### 3️⃣ Generate the forensic report

Your report appears at:

analysis/MacHeimdall_Report.html

Open in any browser.

---

## 🎯 Why This Project Matters

macOS forensics often relies on massive frameworks or GUI tools.  
MacHeimdall is:

- **Portable**  
- **Offline-first**  
- **Beginner-friendly**  
- **Court-admissible (via evidence hashing)**  
- **Designed for real-world IR workflows**

Perfect for cybersecurity portfolios, blue-team automation, DFIR learning, and academic demonstrations.

---

## 🧠 Roadmap

- [ ] Add timeline visualization  
- [ ] Add signature-based IOC detection  
- [ ] Add TTP mapping to MITRE ATT&CK  
- [ ] Support ZIP ingestion for evidence bundles  
- [ ] Create a command-line interactive dashboard  

---

## 📜 License
Released under the MIT License (see below).

---

## 👨‍💻 Author
**Abhishek Limaye**  
Cybersecurity & Digital Forensics Enthusiast  
Creator of MacHeimdall – macOS Forensics Toolkit  

If you use this tool, give the repo a ⭐ and contribute!
