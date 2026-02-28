# 🔐 SOC Dashboard – Security Monitoring & Incident Response

## 📌 Project Overview

This project is a SOC (Security Operations Center) Dashboard built using Flask, designed to simulate real-world security monitoring and incident response workflows.

The system generates login activity logs and applies multiple detection rules to identify suspicious behavior such as brute force attacks, unusual login patterns, and multi-user access from the same IP.

Based on these detections, alerts are created with different severity levels (LOW, MEDIUM, HIGH), along with recommended actions. The dashboard allows analysts to review alerts, take action, and close incidents, mimicking a real SOC environment.

This project focuses on practical implementation of log analysis, threat detection, and incident handling rather than theoretical concepts.

## 🧾 1. Log Analysis

In this project, system-generated logs simulate real-world authentication activity such as successful logins, failed login attempts, and user access patterns.

Each log entry contains important details like username, IP address, timestamp, and login status. These logs are continuously monitored to identify abnormal behavior.

Normal activity includes:
- Successful login from a known user and IP
- Regular login timing patterns

Suspicious activity includes:
- Multiple failed login attempts
- Login from a new or unknown IP address
- Login at unusual hours
- Multiple users logging in from the same IP

By analyzing these patterns, the system distinguishes between normal and potentially malicious behavior, which forms the foundation for detection and alert generation.

## 🚨 2. Detection Logic

The system uses predefined detection rules to identify suspicious activities from login logs. Each rule is designed based on common real-world attack patterns.

### 🔴 Brute Force Detection (HIGH)
If multiple failed login attempts are detected within a short time frame, it indicates a possible brute force attack.
**Reason:** Attackers try multiple passwords to gain unauthorized access.

### 🟠 New Location Login (MEDIUM)
If a user logs in from an IP address that has not been seen before, it is flagged as suspicious.
**Reason:** This may indicate account compromise or unauthorized access.

### 🟡 Suspicious Activity (LOW)
Unusual login behavior that does not strongly indicate an attack but is still abnormal.
**Reason:** Early warning signs of potential threats.

### 🟠 Odd Hours Login (MEDIUM)
If login occurs at unusual hours (e.g., late night), it is considered suspicious.
**Reason:** Legitimate users usually follow consistent usage patterns.

### 🔴 Same IP Multiple Users (HIGH)
If multiple user accounts are accessed from the same IP address, it is flagged.
**Reason:** This may indicate credential stuffing or shared malicious access.

## ⚠️ 3. Incident Classification & Response

In this system, detected threats are classified into three severity levels based on their impact and risk.

### 🟡 LOW Severity
These are minor or early-stage anomalies.
**Examples:**
- Slightly unusual login behavior

**Response:**
- Monitor activity
- No immediate action required

---

### 🟠 MEDIUM Severity
These indicate suspicious activity that may require attention.
**Examples:**
- Login from a new IP address
- Login at unusual hours

**Response:**
- Verify user identity
- Monitor further activity
- Alert administrator if needed

---

### 🔴 HIGH Severity
These indicate strong signs of an attack.
**Examples:**
- Brute force login attempts
- Multiple users accessing from the same IP

**Response:**
- Block IP address
- Force password reset
- Escalate to administrator
- Investigate immediately

## 🔄 4. Alert Workflow

The project simulates a simplified SOC alert workflow similar to real-world security operations.

### Workflow Steps:

1. **Detection**
   - The system analyzes login logs using predefined detection rules.

2. **Alert Generation**
   - If suspicious activity is detected, an alert is created with a severity level (LOW, MEDIUM, HIGH).

3. **Analyst Review**
   - The SOC analyst reviews the alert details such as user, IP address, and activity.

4. **Action Taken**
   - Based on severity, appropriate actions are taken (monitor, verify, block, escalate).

5. **Incident Closure**
   - Once the issue is resolved, the alert is marked as closed in the dashboard.

This workflow demonstrates how security incidents are identified, analyzed, and handled in a structured manner within a SOC environment.

## 🖥️ Screenshots

All screenshots are available in the `screenshots/` folder.

### 🔐 Login Page
![Login Page](screenshots/login_page.png)

### 📊 Dashboard Overview
![Dashboard Top](screenshots/dashboard/dashboard_top.png)

### 📜 Logs Monitoring
![Logs](screenshots/dashboard/dashboard_logs.png)

### 🚨 Alerts Detection
![Alerts](screenshots/dashboard/dashboard_alerts.png)

### 🔄 Alert Lifecycle (Open → Closed)
![Alert Close](screenshots/dashboard/alert_close.png)

## 🚀 Future Improvements

- Integration with real-time log sources (e.g., system logs, network logs)
- Automated alert response (auto-block suspicious IPs)
- Advanced detection using anomaly detection or machine learning
- User behavior analytics for better threat detection
- Email/SMS alert notifications for critical incidents

## 📚 What I Learned

Through this project, I gained practical understanding of how real-world security monitoring systems work.

- How to analyze authentication logs and identify suspicious patterns
- How to create detection rules based on real attack scenarios
- Understanding of brute force attacks, unusual login behavior, and IP-based anomalies
- How to classify incidents into LOW, MEDIUM, and HIGH severity
- How to define appropriate response actions for each type of threat
- Understanding the complete SOC workflow: Detection → Alert → Review → Action → Closure
- Hands-on experience building a full-stack security tool using Flask
- Importance of clean UI and clear alert visibility for security analysts