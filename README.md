# 🛡️ Network Penetration Testing with Real-World Exploits and Security Remediation

This project simulates real-world network attacks and defense strategies in a controlled lab environment, using **Kali Linux** as the attacker machine and **Metasploitable 2** as the target. The primary goal is to understand how vulnerabilities are exploited and how they can be remediated. It covers scanning, enumeration, exploitation, password cracking, and security hardening — all performed ethically for educational purposes.

---

## 🎯 Objectives

- Understand and simulate real-world network attacks
- Perform scanning, enumeration, and exploitation using tools like Nmap and Metasploit
- Crack Linux password hashes using John the Ripper
- Identify outdated services and recommend appropriate security remediations

---

## 💻 Lab Setup

### 🖥️ Operating Systems
- **Kali Linux** – Attacker Machine
- **Metasploitable 2** – Target Machine

### 🛠️ Tools Used
- `nmap` – Port, OS, and service version scanning
- `Metasploit` – Exploitation framework
- `John the Ripper` – Password hash cracking
- Linux built-in commands – User management and enumeration

---

## 🚀 Tasks Performed

### 🔍 Network Scanning
- `nmap -v IP` – Basic scan
- `nmap -v -p- IP` – Full port scan
- `nmap -sV IP` – Service version detection
- `nmap -O IP` – OS detection

**Hidden Ports Discovered:**  
Ports like `8787`, `36588`, `53204`, etc., found through full port scans.

---

### 📡 Enumeration
- **Operating System:** Linux 2.6.x (Metasploitable)
- **Open Services:** vsftpd, OpenSSH, Apache, MySQL, Samba, etc.
- **Vulnerable Ports:** 21 (FTP), 445 (SMB), 512–514 (R Services)

---

### 💥 Exploitation
- **vsftpd 2.3.4** – Exploited using known backdoor vulnerability (CVE-2011-2523)
- **SMB (Samba 3.0.20)** – Exploited via Metasploit module
- **Rexec/Rlogin/Rsh** – Exploited using custom scripts

---

### 👤 Privilege Escalation
- Created user `rahul` with root-level privileges
- Extracted and cracked password hash using **John the Ripper**

---

### 🔧 Remediation Steps

| Service      | Vulnerability                        | Fix                                      |
|--------------|--------------------------------------|------------------------------------------|
| vsftpd       | Backdoor (CVE-2011-2523)             | Upgrade to 3.0.5 / use SFTP              |
| SMB          | RCE, Null Sessions                   | Upgrade to Samba 4.20.1                  |
| R Services   | Plaintext credentials (CVE-1999-0651)| Disable and use SSH instead             |

---

## 📚 Major Learning

- Performed user creation and privilege escalation in Linux
- Identified system weaknesses using `nmap -sV`, `nmap -O`, and `john`
- Understood how legacy services like FTP, SMB, and R Services expose systems to high risks
- Learned remediation techniques for real-world vulnerabilities

---

## ⚠️ Disclaimer

This project was conducted **solely for educational purposes**. All penetration testing was performed in a **safe, isolated lab environment**. Do not attempt these techniques on any live or production networks without **explicit permission**.

---

## 📎 References

- [CVE-2011-2523 – vsftpd Backdoor Vulnerability](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523)
- [Metasploit Documentation](https://docs.metasploit.com/)
- [John the Ripper](https://www.openwall.com/john/)
- [Apache Vulnerabilities](https://httpd.apache.org/security_report.html)

---


