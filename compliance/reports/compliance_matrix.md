# Compliance Coverage Matrix

**Generated**: 2026-06-14
**Platform**: Detection Engineering & IR Validation Platform
**Techniques Mapped**: 15

## Summary

| Framework | Controls Covered | Techniques Mapped |
|-----------|-----------------|-------------------|
| NIST CSF | 12 | 15 |
| CIS Controls v8 | 21 | 15 |
| ISO 27001:2022 | 18 | 15 |

---

## NIST Cybersecurity Framework (CSF)

### Controls Covered

| Control ID | Control Name | Techniques Mapped |
|------------|-------------|-------------------|
| DE.CM-1 | Network is monitored | T1059.001, T1003.001, T1110.001, T1490, T1055.001, T1218.011, T1021.002 |
| DE.CM-3 | Personnel activity is monitored | T1053.005, T1070.001 |
| DE.CM-4 | Malicious code is detected | T1566.001 |
| DE.CM-7 | Monitoring for unauthorized activity | T1547.001, T1083, T1082 |
| PR.AC-1 | Identities and credentials managed | T1003.001 |
| PR.AC-3 | Remote access is managed | T1021.002 |
| PR.AC-4 | Access permissions are managed | T1053.005 |
| PR.AC-6 | Identities are proofed | T1078 |
| PR.AC-7 | Users are authenticated | T1110.001 |
| PR.AT-1 | All users are trained | T1566.001 |
| PR.IP-4 | Backups are conducted | T1486, T1490 |
| PR.PT-1 | Audit/log records | T1070.001 |
| RC.RP-1 | Response plan is executed | T1486 |
| RS.AN-1 | Notifications investigated | T1059.001 |

---

## CIS Controls v8

### Controls Covered

| Control ID | Control Name | Techniques Mapped |
|------------|-------------|-------------------|
| 2.5 | Allowlist Authorized Software | T1218.011 |
| 3.3 | Configure Data Access Control Lists | T1083, T1486 |
| 4.1 | Secure Configuration Process | T1053.005, T1547.001, T1082 |
| 4.7 | Manage Default Accounts | T1110.001 |
| 4.8 | Disable Unnecessary Services | T1059.001, T1218.011 |
| 5.1 | Account Inventory | T1078 |
| 5.2 | Use Unique Passwords | T1003.001, T1110.001 |
| 5.3 | Disable Dormant Accounts | T1078 |
| 5.4 | Restrict Admin Privileges | T1053.005, T1003.001, T1078, T1021.002, T1070.001, T1490 |
| 6.3 | Require MFA | T1078, T1110.001 |
| 6.7 | DNS Filtering | T1110.001 |
| 8.2 | Collect Audit Logs | T1059.001, T1053.005, T1003.001, T1078, T1110.001, T1083, T1082, T1021.002, T1070.001, T1486 |
| 8.3 | Adequate Log Storage | T1070.001 |
| 8.8 | Command-Line Audit Logs | T1059.001, T1055.001, T1218.011, T1083, T1082, T1490, T1566.001 |
| 8.9 | Centralize Audit Logs | T1070.001 |
| 9.1 | Supported Browsers/Email | T1566.001 |
| 9.6 | Block Unnecessary File Types | T1566.001 |
| 10.1 | Anti-Malware Software | T1059.001, T1055.001 |
| 10.2 | Anti-Malware Signature Updates | T1547.001 |
| 10.5 | Anti-Exploitation Features | T1003.001, T1055.001 |
| 11.1 | Data Recovery Practice | T1486, T1490 |
| 11.2 | Automated Backups | T1486 |
| 11.3 | Protect Recovery Data | T1490 |
| 12.2 | Secure Network Architecture | T1021.002 |
| 12.8 | Dedicated Admin Computing | T1021.002 |
| 13.4 | Traffic Filtering | T1021.002 |
| 13.7 | Host-Based IDS | T1053.005, T1547.001, T1003.001, T1055.001, T1218.011, T1083, T1082, T1486, T1566.001 |
| 14.1 | Security Awareness Program | T1566.001 |

---

## ISO 27001:2022

### Controls Covered

| Control ID | Control Name | Techniques Mapped |
|------------|-------------|-------------------|
| 5.12 | Classification of Information | T1083 |
| 5.15 | Access Control | T1083, T1021.002 |
| 5.16 | Identity Management | T1078, T1110.001 |
| 5.17 | Authentication Information | T1078, T1003.001, T1110.001 |
| 5.18 | Access Rights | T1078, T1003.001 |
| 5.25 | Assessment of Security Events | T1059.001, T1547.001, T1055.001, T1566.001 |
| 5.26 | Response to Incidents | T1003.001, T1486 |
| 5.28 | Collection of Evidence | T1070.001 |
| 5.29 | Info Security During Disruption | T1486 |
| 5.30 | ICT Readiness for Continuity | T1486, T1490 |
| 5.33 | Protection of Records | T1070.001, T1490 |
| 5.37 | Documented Operating Procedures | T1053.005, T1082 |
| 6.3 | Security Awareness Training | T1566.001 |
| 8.7 | Protection Against Malware | T1059.001, T1055.001, T1566.001 |
| 8.9 | Configuration Management | T1547.001, T1218.011, T1082 |
| 8.13 | Information Backup | T1486, T1490 |
| 8.15 | Logging | All 15 techniques |
| 8.16 | Monitoring Activities | All 15 techniques |
| 8.17 | Clock Synchronization | T1070.001 |
| 8.18 | Privileged Utility Programs | T1053.005 |
| 8.19 | Software Installation | T1218.011 |
| 8.20 | Networks Security | T1021.002 |
| 8.21 | Security of Network Services | T1021.002 |
| 8.22 | Web Filtering | T1055.001 |
| 8.23 | Web Filtering | T1566.001 |

---

## Cross-Reference Matrix: Technique × Framework

| Technique | NIST CSF | CIS Controls v8 | ISO 27001:2022 |
|-----------|----------|-----------------|----------------|
| T1059.001 | DE.CM-1, RS.AN-1 | 8.2, 8.8, 10.1, 4.8 | 8.15, 8.16, 8.7, 5.25 |
| T1053.005 | DE.CM-3, PR.AC-4 | 8.2, 5.4, 4.1, 13.7 | 8.15, 8.16, 5.37, 8.18 |
| T1547.001 | DE.CM-7 | 8.2, 4.1, 13.7, 10.2 | 8.15, 8.16, 8.9, 5.25 |
| T1078 | PR.AC-6 | 5.1, 5.3, 5.4, 6.3, 8.2 | 5.16, 5.17, 5.18, 8.15, 8.16 |
| T1003.001 | PR.AC-1, DE.CM-1 | 5.4, 10.5, 13.7, 8.2, 5.2 | 5.17, 5.18, 8.16, 8.15, 5.26 |
| T1110.001 | DE.CM-1, PR.AC-7 | 5.2, 6.3, 8.2, 6.7, 4.7 | 5.17, 8.15, 8.16, 5.16 |
| T1055.001 | DE.CM-1 | 13.7, 10.5, 8.8, 10.1 | 8.7, 8.16, 8.22, 5.25 |
| T1218.011 | DE.CM-1 | 2.5, 8.8, 13.7, 4.8 | 8.19, 8.16, 8.15, 8.9 |
| T1083 | DE.CM-7 | 8.2, 3.3, 8.8, 13.7 | 8.15, 8.16, 5.12, 5.15 |
| T1082 | DE.CM-7 | 8.8, 8.2, 13.7, 4.1 | 8.15, 8.16, 5.37, 8.9 |
| T1021.002 | DE.CM-1, PR.AC-3 | 12.2, 8.2, 5.4, 12.8, 13.4 | 8.20, 8.15, 5.15, 8.16, 8.21 |
| T1070.001 | PR.PT-1, DE.CM-3 | 8.2, 8.3, 8.9, 5.4 | 8.15, 8.17, 5.33, 8.16, 5.28 |
| T1486 | RC.RP-1, PR.IP-4 | 11.1, 11.2, 13.7, 8.2, 3.3 | 8.13, 5.30, 8.16, 5.26, 5.29 |
| T1490 | PR.IP-4, DE.CM-1 | 11.1, 11.3, 8.8, 5.4 | 8.13, 5.30, 8.15, 8.16, 5.33 |
| T1566.001 | PR.AT-1, DE.CM-4 | 9.1, 9.6, 14.1, 8.8, 13.7 | 8.23, 6.3, 8.7, 8.16, 5.25 |

---

## Coverage Gaps

All ATT&CK tactics represented in this platform have at least one compliance control mapping across all three frameworks. There are no unmapped tactics.

| Tactic | Coverage Status |
|--------|----------------|
| Initial Access | ✅ Fully mapped (T1566.001) |
| Execution | ✅ Fully mapped (T1059.001) |
| Persistence | ✅ Fully mapped (T1053.005, T1547.001) |
| Privilege Escalation | ✅ Mapped via T1055.001, T1078 |
| Defense Evasion | ✅ Fully mapped (T1078, T1055.001, T1218.011, T1070.001) |
| Credential Access | ✅ Fully mapped (T1003.001, T1110.001) |
| Discovery | ✅ Fully mapped (T1083, T1082) |
| Lateral Movement | ✅ Fully mapped (T1021.002) |
| Impact | ✅ Fully mapped (T1486, T1490) |
