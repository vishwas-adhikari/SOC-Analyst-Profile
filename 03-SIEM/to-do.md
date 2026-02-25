
# 📔 Module 5: Post-Installation & Core Configuration (QRadar Focus)

## 1. Licensing & Authorized Services (The "Key")
Before you can ingest a single log, the "engine" must be unlocked.
*   **Licensing:** QRadar is usually licensed by **EPS (Events Per Second)** and **FPM (Flows Per Minute)**. 
    *   *Senior Tip:* Monitor your license usage daily. If you exceed your EPS limit, QRadar will move excess events into a "License Overflow" queue. If that fills up, you start **dropping logs.**
*   **Authorized Services (Tokens):** These are API keys. You need these to connect external tools (like WinCollect for Windows logs) to QRadar.
    *   *Security Note:* **Never lose the token.** As your notes say, once you click "Save," the token is hidden forever for security. If you lose it, you have to recreate it and update all your agents.

---

## 2. Network Hierarchy (The "Secret Sauce")
This is the most important step in QRadar. If you don't define your Network Hierarchy, QRadar won't know the difference between a "Hack from Russia" and a "Scan from your internal IT team."

*   **What it does:** It tells the SIEM which IP ranges belong to your "Inside" network (DMZ, Workstations, Servers).
*   **Why it matters:** 
    *   It helps identify **Reconnaissance** (Scanning).
    *   It reduces False Positives in the **"Offense"** tab.
    *   It allows the SIEM to detect **Data Exfiltration** (Internal -> External traffic).
*   **Example:** If `10.0.0.50` scans your network, but you haven't defined `10.0.0.0/24` as "Internal," QRadar might flag it as an "External Attack," causing panic.

---

## 3. Data Retention & The Ariel Database
The **Ariel Database** is QRadar's proprietary storage engine for events and flows.

*   **Event Retention:** Default is 1 month. 
    *   *Senior Logic:* You should create **Retention Buckets.**
    *   *Bucket 1 (Compliance):* Firewall logs stored for 1 year (Compressed/Cold).
    *   *Bucket 2 (Investigation):* Windows/Endpoint logs stored for 3 months (Searchable/Hot).
*   **Why?** Storing everything for 1 year on high-speed disks is too expensive. Tiered retention saves money and keeps the system fast.

---

## 4. Log Source Management & Grouping
When you have 5,000 log sources, you can't manage them in one big list.

*   **Grouping:** Organize by **Location** (New York vs. London) or **Function** (Firewalls vs. Databases).
*   **Pro-Tip:** Use **Log Source Groups** to apply different retention policies or to limit which Analysts can see which logs (RBAC).

---

## 5. System Settings & Monitoring (The "Vitals")
Think of these as the "BIOS settings" of your SIEM.

*   **Auto Updates:** Ensure you are getting the latest **DSM (Device Support Modules)**. These are the "drivers" that help QRadar understand logs from new versions of Checkpoint, Cisco, or Windows.
*   **Email (SMTP):** If this isn't configured, you won't get "High Severity" alerts in your inbox at 3 AM.
*   **Ariel Database Settings:** This controls how much disk space is used before the SIEM starts deleting the oldest logs to protect itself (Data Integrity).

---

## 6. SNMP & Health Monitoring
How do you know if the SIEM is dying? 
*   **SNMP:** Use this to send the "Health" of the QRadar server (CPU, RAM, Disk) to your IT Monitoring tool (like Zabbix or SolarWinds).
*   **Senior Tip:** Always set an alert for **"Disk Usage > 85%."** If a SIEM runs out of disk space, the database can become corrupted.

---

### 🛠 The SIEM Engineer’s "Day 1" Checklist

1.  **Time Sync (NTP):** Check this again. If QRadar is 1 minute off from the Domain Controller, correlation rules will fail.
2.  **Backup Configuration:** Enable "Config Backups" immediately. If you break a rule or a dashboard, you want to be able to roll back.
3.  **Geo Location:** Configure the **Geographic Settings** so that your "Offense" map actually shows where threats are coming from.

---

### 🎓 Answer for your Question:
**Question:** In the IBM QRadar solution, where can you access the 'Geo Location' information on the Admin screen menu?

**Answer:** **System Settings**
*(Wait! Based on your notes, the actual path is: `QRadar -> Admin -> System Configuration -> System Settings -> Geographic Settings`. The specific menu header in the Admin screen is **System Settings**.)*

---
