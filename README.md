# Home Intrusion Detection & Prevention System (IDPS)

![Python](https://img.shields.io/badge/python-3.13-blue)
![Platform](https://img.shields.io/badge/platform-Windows%2011-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

This project provides a simple and effective Intrusion Detection & Prevention System (IDPS) that monitors network traffic for suspicious activity, logs alerts, and auto-blocks attacks in real time on **Windows 11**.

---

## 📌 Key Features
- **Real-time Traffic Monitoring**: Captures and analyzes network packets to detect and block online attacks.

---

## 📂 Components
This project consists of the following main files:

- `idps_engine.py`: The core of the IDS. It listens for network traffic, applies detection rules, and logs alerts.
- `ids_alerts.json`: Stores all network alerts in a JSON format.
- `blocked_ips.json`: Contains a list of IP addresses that have been blocked by the IDPS.
- `ids_rules.json`: Defines the rules used to monitor for various attacks.

---

## ⚙️ Prerequisites

1. ### Install Python 3
   Download and install Python 3 from the official website:  
   [Python 3.13.7 (Windows x64 Installer)](https://www.python.org/ftp/python/3.13.7/python-3.13.7-amd64.exe)

   > **Note:** During installation, select the options to install **pip** and **Add Python to PATH**.

---

2. ### Install Wireshark (Npcap)
   Download and install Wireshark from the official website:  
   [Wireshark 4.4.9 (Windows x64 Installer)](https://2.na.dl.wireshark.org/win64/Wireshark-4.4.9-x64.exe)

   > **Important:** When prompted, ensure you select these options:
   - "Install Npcap in WinPcap API-compatible mode"
   - "Install Support raw 802.11 traffic (and monitor mode) for wireless adapters"

---

3. ### Verify Python Installation
   Open **Command Prompt (`cmd`)** and run:

   ```bash
   python --version
   ```

   Expected output (example):

   ```bash
   Python 3.13.7
   ```

---

4. ### Install Required Libraries
   Navigate to the project directory in Command Prompt and run:

   ```bash
   pip install -r requirements.txt
   ```

---

## ▶️ How to Run

1. In the extracted project folder, rename the file `run.txt` to `run.bat`.  
2. Double-click on `run.bat`.  
3. When the **User Account Control (UAC)** prompt appears, select **"Yes"** to run the script with administrator privileges.  
   > This is necessary for network traffic monitoring.

---

## 📝 Notes
- If Windows Defender or your antivirus flags the script, allow it through temporarily (only if you trust the source).  
- Wireshark/Npcap installation may require a **system restart**.  
