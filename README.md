# Windows-Threat-Detection-Incident-Report
Incident response report and attack chain analysis for Windows Initial Access vectors using Security.evtx and Sysmon logs.
# Incident Investigation Report: Windows Initial Access Analysis

## Executive Summary
This report details the investigation of a multi-vector attack against a Windows host using event log analysis. The investigation uncovered initial access attempts via **RDP Brute-Force**, **Phishing (Double-Extension Payloads)**, and **Infected USB Media**. The compromise was fully analyzed using native Windows Security logs and System Monitor (Sysmon) telemetry.

---

## Technical Findings & Attack Timelines

### 1. Remote Desktop (RDP) Initial Access
* **Initial Vector:** RDP Brute-Force attack targeting local user accounts.
* **Security Logs Ingested:** `Security.evtx`
* **Analysis:**
  * **Event ID 4625 (Failed Logon):** Detected high-frequency login failures targeting user accounts.
  * **Event ID 4624 (Successful Logon):** Confirmed successful initial access via **Logon Type 10** (Remote Interactive).
* **Attacker Artifacts:**
  * **Attacker IP:** `[10.11.27.182]`
  * **Logon ID:** `[0x19B6F]`
  * **Attacker Workstation Name:** `[WORKSTATION-ATTACK]`

---

### 2. User-Driven Attack (Phishing)
* **Initial Vector:** Phishing email leading to execution of a double-extension archive file.
* **Sysmon Logs Ingested:** `Phishing-Sysmon.evtx`
* **Analysis & Artifacts:**
  * **Downloaded File (Event ID 11):** `top-cats.zip` downloaded via browser.
  * **Extracted Malware (Event ID 11):** Unarchived to `[C:\Users\Administrator\Desktop\Phishing Case 3\]`.
  * **Process Execution (Event ID 1):** Malware launched with **Process ID:** `[5828]`.
  * **Command & Control (Event ID 22):** Malware made DNS queries to domain `[c2-server.com]`.

---

### 3. Removable Media (Infected USB)
* **Initial Vector:** Execution of malicious executable disguised as legitimate content on a USB drive.
* **Sysmon Logs Ingested:** `USB-Sysmon.evtx`
* **Analysis & Artifacts:**
  * **Execution Path (Event ID 1):** Executable launched directly from removable drive `E:\`.
  * **Payload Drop (Event ID 11):** Dropped payload to disk at `C:\Users\Public\Documents\winupdate.exe`.

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Artifact / Evidence |
| :--- | :--- | :--- | :--- |
| **Initial Access** | `T1110` | Brute Force | Multiple Event ID `4625` entries |
| **Initial Access** | `T1078` | Valid Accounts | Event ID `4624` (Logon Type 10) |
| **Execution** | `T1204.002` | User Execution: Malicious File | `ParentImage` launching extracted binary |
| **Defense Evasion** | `T1036.007` | Double Extension | File ending in `.pdf.exe` / disguised icons |
| **Command & Control** | `T1071.001` | Web Protocols | Sysmon Event ID `22` DNS query |

---

## Detection Logic (Sigma Rules)

```yaml
title: Detect Suspicious Process Execution from Removable Drives
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|contains:
      - 'E:\'
      - 'F:\'
  condition: selection
level: high
