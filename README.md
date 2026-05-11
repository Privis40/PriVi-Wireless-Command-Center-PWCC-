# PriVi Wireless Command Center (PWCC) v1.0
### RF Intelligence & Wireless Audit Platform
**Developed by Prince Ubebe | [PriViSecurity](https://github.com/Privis40)**

---

## ⚠️ Legal Notice

> **This tool is intended ONLY for use on wireless networks you own or have explicit written authorization to audit.**
> Deauthentication testing against networks you do not own is illegal under the Computer Misuse Act, the CFAA (Computer Fraud and Abuse Act), and equivalent cybercrime laws worldwide.
> **PriViSecurity accepts no liability for unauthorized or malicious use of this tool.**

If you are conducting a professional engagement, ensure you hold a signed **Letter of Authorization (LoA)** from the network owner before running any active mode.

---

## What It Does

PriVi Wireless Command Center is a wireless security audit platform built for penetration testers and security analysts operating in **authorized environments**. It combines passive RF surveillance, EAPOL handshake capture, evil twin detection, and 802.11w MFP analysis into a single Rich terminal dashboard — with a branded PDF audit report generated at the end of every session.

It is designed for:
- Wireless penetration testers conducting authorized WiFi security assessments
- Network administrators auditing their own wireless infrastructure
- Security researchers studying 802.11 behaviour in controlled lab environments
- CTF participants in wireless challenge categories

---

## Features

| Feature | Description |
|---|---|
| 📡 Passive Surveillance | Channel-hopping beacon scan with live Rich dashboard |
| 👾 Evil Twin Detection | Flags APs broadcasting your monitored SSID with a different BSSID |
| 🔐 802.11w MFP Analysis | Detects whether Management Frame Protection is enabled per AP |
| 🤝 EAPOL Handshake Capture | Monitors for WPA/WPA2 handshakes during authentication events |
| ⚠️ Targeted Deauth Test | Deauths a specific client from a specific AP (authorized use, double-gated) |
| ⚠️ Broadcast Deauth Test | Deauths all clients from a specific AP (authorized use, double-gated) |
| 📋 PDF Audit Report | Branded client-ready PDF with findings and recommendations |
| 🔒 Dual Authorization Gates | Startup gate + secondary confirmation for all active/disruptive modes |

---

## Requirements

```bash
pip install scapy rich fpdf2
```

Your wireless interface must be in **monitor mode** before launching:

```bash
sudo airmon-ng start wlan0
# This typically creates wlan0mon
```

---

## Installation

```bash
git clone https://github.com/Privis40/PriVi-Wireless-Command-Center-PWCC-.git
cd PriVi-Wireless-Command-Center-PWCC-
pip install -r requirements.txt
```

---

## Usage

```bash
sudo python3 privi_wireless_cc.py
```

The tool requires root privileges for raw packet access.

The tool will:
1. Display the legal authorization gate — type `AGREE` to confirm
2. Prompt for your monitor-mode interface and lab SSID/BSSID for evil twin detection
3. Present the audit mode menu
4. Launch the selected mode with a live Rich dashboard
5. Generate a PDF report on exit (Ctrl+C)

### Example Session

```
Monitor-mode interface [wlan0mon]: wlan0mon
Your lab/authorized SSID: PriVi_Lab_WiFi
Your lab/authorized BSSID: AA:BB:CC:DD:EE:FF

  No.  Mode                      Type        Description
  1    Passive Surveillance      Read-only   Channel hopping, network discovery
  2    EAPOL Handshake Capture   Read-only   Monitor for WPA/WPA2 handshakes
  3    Targeted Deauth Test      Active ⚠   Deauth specific client (extra auth)
  4    Broadcast Deauth Test     Active ⚠   Deauth all clients on AP (extra auth)

Select audit mode: 1

» 14:32:01 | Passive surveillance active. Channel hopping started.
» 14:32:08 | ⚠ EVIL TWIN DETECTED — BSSID: BB:CC:DD:EE:FF:AA | SSID: PriVi_Lab_WiFi

[+] Report saved: PWCC_Wireless_Audit_20260511_143220.pdf
```

---

## Audit Modes

**Mode 1 — Passive Surveillance**
Purely read-only. Channel hops across bands 1–13, discovers all broadcasting APs, checks 802.11w MFP status, and monitors for evil twin activity. No frames are transmitted.

**Mode 2 — EAPOL Handshake Capture**
Monitors for WPA/WPA2 4-way handshake frames during client authentication events. Purely passive — no deauth frames are sent to force handshakes. Captured handshakes are logged and counted in the PDF report.

**Mode 3 — Targeted Deauth Test**
Sends IEEE 802.11 deauthentication frames to a specific client MAC on a specific AP. Requires a second explicit authorization confirmation before executing. **For authorized penetration testing only.**

**Mode 4 — Broadcast Deauth Test**
Sends broadcast deauth frames to all clients associated with a specific AP. Requires a second explicit authorization confirmation before executing. **For authorized penetration testing only.**

---

## PDF Report Sections

1. Audit Summary (analyst, mode, date, network count, handshake count)
2. Detected Networks (BSSID, SSID, channel, signal, MFP status)
3. Security Observations (evil twins, unprotected networks, handshakes)
4. Recommendations (MFP hardening, rogue AP detection, WPA3 migration)
5. Legal & Scope Declaration

---

## What This Tool Does NOT Do

- ❌ Does **not** crack or decrypt WPA/WPA2 passphrases
- ❌ Does **not** perform deauth automatically without explicit confirmation
- ❌ Does **not** inject or modify traffic
- ❌ Does **not** associate with or connect to any access point

---

## Tested On

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- Python 3.10+
- Compatible adapters: Alfa AWUS036ACH, TP-Link TL-WN722N v1

---

## Author & Brand

**Prince Ubebe**
Cybersecurity Analyst | Security Automation Engineer | Founder, PriViSecurity

- GitHub: [github.com/Privis40](https://github.com/Privis40)
- LinkedIn: [linkedin.com/in/prince-ubebe-291573321](https://www.linkedin.com/in/prince-ubebe-291573321)
- YouTube: [@princeubebecyber](https://youtube.com/@princeubebecyber)
- HackerOne / Bugcrowd: Active researcher

---

## License

This tool is released for **authorized security research and professional use only.**
Redistribution or modification for malicious purposes is strictly prohibited.

© 2026 PriViSecurity. All rights reserved.
