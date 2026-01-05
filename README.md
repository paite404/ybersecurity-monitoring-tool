# Enhanced Cybersecurity Monitoring Tool

A Python-based, menu-driven cybersecurity monitoring and analysis tool designed for **educational, defensive, and authorized security use**.  
This project provides hands-on exposure to system monitoring, network analysis, and basic security assessments using Python.

---

## 📌 Overview

The **Enhanced Cybersecurity Monitoring Tool** is a terminal-based application developed to help cybersecurity students and junior security practitioners understand:

- System performance and resource usage
- Network visibility and device discovery
- Basic security posture assessment
- Log inspection and reporting

The tool is intentionally defensive and includes ethical warnings where sensitive features are involved.

---

## ✨ Features

### 🔹 System Monitoring
- Real-time CPU, memory, disk, and network usage
- Top running processes analysis
- Visual progress bars in terminal

### 🔹 Network & Analysis Tools
- Local network scanning (ARP-based)
- TCP port scanner
- IP address geolocation lookup
- Phone number metadata lookup (ethical consent required)

### 🔹 User & Session Analysis
- User account enumeration
- Active login session monitoring
- Process ownership analysis

### 🔹 Security Checks
- Firewall (UFW) status verification
- Detection of commonly exposed ports
- System update status check

### 🔹 Logs & Reporting
- System log retrieval (journalctl, dmesg, auth logs)
- Automatic report generation (JSON and TXT)
- Timestamped reports for auditing and review

### 🔹 Dependency Awareness
- Automatic detection of missing libraries
- Graceful feature limitation when dependencies are unavailable
