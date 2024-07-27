# Cybersecurity Tools and Resources

Welcome to the **Cybersecurity Tools and Resources** repository! This collection provides a curated list of essential tools, operating systems, and resources for cybersecurity professionals and enthusiasts. Whether you're setting up a lab environment, conducting penetration testing, or improving your organization's security posture, this repository has you covered.

## Table of Contents
1. [Virtual Machines](#virtual-machines)
2. [Operating Systems for Virtual Machines](#operating-systems-for-virtual-machines)
3. [Dictionary Files](#dictionary-files)
4. [Security Tools](#security-tools)
5. [Password Security Tools](#password-security-tools)
6. [Security Frameworks and Guidelines](#security-frameworks-and-guidelines)
7. [Network Security Monitoring Tools](#network-security-monitoring-tools)
8. [Encryption Tools](#encryption-tools)
9. [Web Vulnerability Scanning Tools](#web-vulnerability-scanning-tools)
10. [Penetration Testing](#penetration-testing)
11. [Incident Response](#incident-response)
12. [Antivirus Software](#antivirus-software)
13. [Network Intrusion Detection](#network-intrusion-detection)
14. [Packet Sniffers](#packet-sniffers)
15. [Firewall Tools](#firewall-tools)
16. [Managed Detection Services](#managed-detection-services)
17. [Endpoint Protection](#endpoint-protection)
18. [Security Information and Event Management (SIEM)](#security-information-and-event-management-siem)

## Virtual Machines
Software-based emulations of physical computers used to run multiple operating systems on a single physical machine for testing and development.
- **VMWare Workstation Player** - [Link](https://www.vmware.com/products/workstation-player.html)
	- **Description:** A free virtualization tool for personal use, offering robust performance and a user-friendly interface. VMware Workstation Pro offers additional features for a fee.
- **Virtual Box** - [Link](https://www.virtualbox.org/)
	- **Description:** A free and open-source virtualization platform that supports various guest operating systems. It is widely used due to its ease of use and extensive feature set.
- **VMware ESXi** - [Link](https://www.vmware.com/products/esxi-and-esx.html)
	- **Description:** A type-1 hypervisor that runs directly on hardware. It's used for enterprise-level virtualization and offers high performance and scalability.
- **KVM (Kernel-based Virtual Machine)** - [Link](https://www.linux-kvm.org/page/Main_Page)
	- **Description:** A Linux kernel module that turns the Linux kernel into a hypervisor. It provides high performance and integrates well with Linux-based systems.

## Operating Systems for Virtual Machines
Various operating systems used within virtual machines for testing, development, and security purposes.
- **Kali Linux** - [Link](https://www.kali.org/)
	-  **Description:** A popular Linux distribution specifically designed for penetration testing and security research. It comes with a wide range of pre-installed security tools.
- **Parrot Security OS** - [Link](https://www.parrotsec.org/)
	- **Description:** Another Linux distribution geared towards security and privacy. It includes a suite of security tools and features focused on digital forensics, penetration testing, and privacy.
- **Ubuntu** - [Link](https://ubuntu.com/)
	- **Description:** A widely used Linux distribution that is user-friendly and suitable for a variety of purposes, including security testing. It is a good choice for general-purpose virtual machines.
- **Windows 10/11** - [Link](https://www.microsoft.com/windows)
	- **Description:** Commonly used for a range of applications, including security testing. It is useful for compatibility testing and running security tools that are specific to the Windows environment.
- **Windows Server** - [Link](https://www.microsoft.com/windows-server)
	- **Description:** For enterprise environments, Windows Server versions are used to simulate server setups, network configurations, and security scenarios.
- **BackBox** - [Link](https://www.backbox.org/)
	- **Description:** A Linux distribution designed for security assessment and analysis. It includes a collection of security tools and is designed for ease of use in security operations.

## Dictionary Files
Collections of words or phrases used in security testing, such as password cracking and vulnerability assessments.
- **SecLists** - [SecLists GitHub Repository](https://github.com/danielmiessler/SecLists)
	- **Description:** A comprehensive collection of wordlists for security testing, including passwords, usernames, and other useful lists for penetration testing and vulnerability assessment.
- **RockYou** - [Link](https://wiki.skullsecurity.org/Passwords)
	- **Description:** A well-known password list derived from a data breach involving the RockYou website. It contains millions of passwords and is commonly used in password cracking.
- **FuzzDB** - [FuzzDB GitHub Repository](https://github.com/fuzzdb-project/fuzzdb)
	- **Description:** A database of attack patterns, predictable file and directory names, and other information useful for web application security testing. It includes various dictionary files.
- **CrackStation** - [Link](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
	- **Description:** A large collection of password hashes and dictionary files used for password cracking. It includes lists compiled from various sources.
-  **Weakpass** - [Link](https://weakpass.com/)
	- **Description:** A site offering various wordlists, including those for password cracking and testing. It includes lists compiled from real-world breaches.
- **John the Ripper Community Wordlists** - [Link](https://github.com/openwall/john/tree/bleeding-jumbo/run)
	- **Description:** A collection of wordlists used with John the Ripper, a popular password cracking tool. These lists are curated for use with various password cracking techniques.

## Security Tools
Software and applications designed to identify, assess, and mitigate security threats and vulnerabilities.
- **Virus Total** - [Link](https://www.virustotal.com/gui/)
	- **Description:** You can use this link if you suspect a file is malicious. It checks the file against multiple antivirus programs.
- **Cuckoo Sandbox** - [Link](https://cuckoosandbox.org/)
	- **Description:** An open-source automated malware analysis system that helps analyze suspicious files and URLs in a controlled environment.
- **Exploit Database Website** - [Link](https://www.exploit-db.com/)
	- **Description:** A comprehensive collection of exploits and vulnerable software information. It provides details on various security vulnerabilities and their exploits, which can be useful for penetration testing and understanding potential threats.
- **Shodan** - [Link](https://www.shodan.io/)
	- **Description:** A search engine for discovering devices and services connected to the internet. It can find a wide range of devices, including servers, routers, webcams, and even unusual items like refrigerators. Useful for exploring device security and identifying exposed services.
- **Metasploit Framework** - [Link](https://www.metasploit.com/)
	- **Description:** An open-source penetration testing framework that provides tools for discovering and exploiting vulnerabilities in systems.

## Password Security Tools
Tools and resources used to assess, manage, and enhance password strength and security.
- **Have I Been Pwned Password Checker** - [Link](https://haveibeenpwned.com/Passwords)
	- **Description:** Allows you to check if your password has been exposed in data breaches. Note that it only checks against known breaches and does not store or share your passwords.
- **Password Checker Online** - [Link](https://password-checker.online-domain-tools.com/)
	- **Description:** Provides an assessment of password strength and suggests improvements.
- **NordPass Password Strength Checker** - [Link](https://nordpass.com/password-strength-checker/)
	- **Description:** Evaluates your password strength and offers tips for creating stronger passwords.
- **Kaspersky Password Check** - [Link](https://password.kaspersky.com/)
	- **Description:** Checks the strength of your password and offers guidance on how to improve it.

## Security Frameworks and Guidelines
Established sets of best practices and standards for managing and implementing security measures to protect information systems and networks.
- **CIS Top 18** - [Link](https://www.cisecurity.org/)
	- **Description:** A set of requirements for implementing security measures to protect an enterprise network. It provides best practices and guidelines to enhance network security and can be used to assess and improve your clients' security posture.
- **NIST Cybersecurity Framework (CSF)** - [Link](https://www.nist.gov/cyberframework)
	- **Description:** A framework developed by the National Institute of Standards and Technology that provides guidelines for improving cybersecurity practices. It is widely used for establishing and enhancing security measures.
- **ISO/IEC 27001** - [Link](https://www.iso.org/isoiec-27001-information-security.html)
	- **Description:** An international standard for information security management systems (ISMS). It provides a systematic approach to managing sensitive company information and ensuring data security.
- **COBIT (Control Objectives for Information and Related Technologies)** - [Link](https://www.isaca.org/resources/cobit)
	- **Description:** A framework for developing, implementing, monitoring, and improving IT governance and management practices.

## Network Security Monitoring Tools
These tools are used to analyze network data and detect network-based threats.
- **Wireshark**: [Download Wireshark](https://www.wireshark.org/download.html)
	- **Description:** A free and open-source packet analyzer. It captures and displays data packets passing through a network, making it a valuable tool for network troubleshooting, analysis, and security monitoring.
- **Snort**: [Download Snort](https://www.snort.org/downloads)
	- **Description:** An open-source network intrusion detection system (NIDS) capable of real-time traffic analysis and packet logging. It is widely used for detecting and preventing network-based attacks.
- **Zeek (formerly Bro)**: [Download Zeek](https://zeek.org/download/)
	- **Description:** An open-source network analysis framework that provides a comprehensive platform for network monitoring, threat detection, and incident response.
- **Suricata**: [Download Suricata](https://suricata-ids.org/download/)
	- **Description:** An open-source network threat detection engine that includes capabilities for intrusion detection (IDS), intrusion prevention (IPS), and network security monitoring (NSM).

## Encryption Tools
Software and resources used to encrypt and decrypt data to ensure its confidentiality and integrity.
- **VeraCrypt**: [Download VeraCrypt](https://www.veracrypt.fr/en/Downloads.html)
	- **Description:** A free and open-source disk encryption software that provides secure encryption for your data. It supports creating encrypted volumes and partitions.
- **GnuPG (GPG)**: [Download GnuPG](https://gnupg.org/download/)
	- **Description:** A free and open-source encryption software that provides cryptographic privacy and authentication for data communication. It supports encryption, decryption, and digital signatures.
- **OpenSSL**: [Download OpenSSL](https://www.openssl.org/source/)
	- **Description:** A robust, full-featured open-source toolkit implementing the Secure Sockets Layer (SSL) and Transport Layer Security (TLS) protocols. It is widely used for securing communications over computer networks.
- **BitLocker**: [More about BitLocker](https://support.microsoft.com/en-us/help/4028713/windows-10-turn-on-device-encryption)
	- **Description:** A disk encryption program included with Windows operating systems. It provides full disk encryption to protect data on Windows devices.

## Web Vulnerability Scanning Tools
These tools are used to identify and assess vulnerabilities in web applications.
- **Burp Suite**: [Download Burp Suite](https://portswigger.net/burp/releases/community/latest)
	- **Description:** A comprehensive web vulnerability scanner and security testing tool. It includes various features for detecting and exploiting web vulnerabilities.
- **OWASP ZAP (Zed Attack Proxy)**: [Download OWASP ZAP](https://www.zaproxy.org/download/)
	- **Description:** An open-source web application security scanner developed by the OWASP community. It helps find security vulnerabilities in web applications and APIs.
- **Nikto**: [Download Nikto](https://cirt.net/Nikto2)
	- **Description:** An open-source web server scanner that identifies potential issues and security vulnerabilities. It performs checks against various items, including outdated software versions and insecure configurations.

## Penetration Testing
Software and resources used to simulate attacks on computer systems to identify and exploit vulnerabilities.
- **Metasploit Framework**: [Download Metasploit](https://www.metasploit.com/get-started)
	- **Description:** A widely used open-source penetration testing framework that provides tools for discovering and exploiting vulnerabilities in systems.
- **Nmap**: [Download Nmap](https://nmap.org/download.html)
	- **Description:** A free and open-source network scanner used to discover hosts and services on a computer network. It provides various features for network exploration and security auditing.
- **OWASP Offensive Security Tooling**: [OWASP Tools](https://owasp.org/)
	- **Description:** A collection of open-source security tools and resources developed by the OWASP community. It includes various tools for penetration testing and security assessments.
- **ExploitDB**: [Visit ExploitDB](https://www.exploit-db.com/)
	- **Description:** A comprehensive collection of exploits and vulnerable software information. It provides details on various security vulnerabilities and their exploits.

## Incident Response
Tools and resources used to respond to and manage cybersecurity incidents.
- **TheHive**: [Download TheHive](https://thehive-project.org/)
	- **Description:** An open-source incident response platform designed to help security teams manage and investigate security incidents efficiently.
- **MISP (Malware Information Sharing Platform)**: [Download MISP](https://www.misp-project.org/download/)
	- **Description:** An open-source threat intelligence platform for sharing, storing, and correlating indicators of compromise (IoCs) and threat data.
- **GRR Rapid Response**: [Download GRR](https://grr.dev/)
	- **Description:** An open-source incident response framework focused on remote live forensics. It enables security teams to perform digital forensics and incident response on large-scale networks.

## Antivirus Software
Software used to detect, prevent, and remove malware and other malicious software.
- **ClamAV**: [Download ClamAV](https://www.clamav.net/downloads)
	- **Description:** An open-source antivirus engine for detecting various types of malware. It is commonly used on Unix-based systems.
- **Windows Defender**: [Learn more about Windows Defender](https://www.microsoft.com/en-us/windows/comprehensive-security)
	- **Description:** A built-in antivirus program for Windows operating systems. It provides real-time protection against malware, viruses, and other threats.
- **Avira Free Antivirus**: [Download Avira](https://www.avira.com/en/free-antivirus-windows)
	- **Description:** A free antivirus program that offers protection against various types of malware. It includes features for real-time scanning and threat detection.
- **AVG Antivirus Free**: [Download AVG](https://www.avg.com/en-us/free-antivirus-download)
	- **Description:** A free antivirus program that provides protection against malware, viruses, and other threats. It includes features for real-time scanning and threat detection.
- **Malwarebytes**: [Download Malwarebytes](https://www.malwarebytes.com/mwb-download)
	- **Description:** A comprehensive anti-malware tool that provides protection against various types of malware. It includes features for real-time scanning, threat detection, and removal.

## Network Intrusion Detection
Tools and resources used to detect and respond to network-based attacks and intrusions.
- **Snort**: [Download Snort](https://www.snort.org/downloads)
	- **Description:** An open-source network intrusion detection system (NIDS) capable of real-time traffic analysis and packet logging. It is widely used for detecting and preventing network-based attacks.
- **Zeek (formerly Bro)**: [Download Zeek](https://zeek.org/download/)
	- **Description:** An open-source network analysis framework that provides a comprehensive platform for network monitoring, threat detection, and incident response.
- **Suricata**: [Download Suricata](https://suricata-ids.org/download/)
	- **Description:** An open-source network threat detection engine that includes capabilities for intrusion detection (IDS), intrusion prevention (IPS), and network security monitoring (NSM).
- **Security Onion**: [Download Security Onion](https://securityonionsolutions.com/software/)
	- **Description:** An open-source Linux distribution for intrusion detection, network security monitoring, and log management. It includes various tools for network security and threat detection.

## Packet Sniffers
Tools and resources used to capture and analyze network traffic at the packet level.
- **Wireshark**: [Download Wireshark](https://www.wireshark.org/download.html)
	- **Description:** A free and open-source packet analyzer. It captures and displays data packets passing through a network, making it a valuable tool for network troubleshooting, analysis, and security monitoring.
- **tcpdump**: [Download tcpdump](https://www.tcpdump.org/)
	- **Description:** A command-line packet analyzer tool that captures and displays network traffic. It is widely used for network troubleshooting and security analysis.
- **Tshark**: [Learn more about Tshark](https://www.wireshark.org/docs/man-pages/tshark.html)
	- **Description:** A command-line network protocol analyzer and a part of the Wireshark suite. It provides similar functionality to Wireshark but operates in a command-line environment.
- **NetworkMiner**: [Download NetworkMiner](https://www.netresec.com/?page=NetworkMiner)
	- **Description:** A network forensic analysis tool for capturing, analyzing, and reconstructing network traffic. It is used for investigating network security incidents.

## Firewall Tools
Software and resources used to monitor and control incoming and outgoing network traffic based on predetermined security rules.
- **pfSense**: [Download pfSense](https://www.pfsense.org/download/)
	- **Description:** An open-source firewall and router platform based on FreeBSD. It provides a wide range of features for network security, including firewalling, routing, and VPN support.
- **IPFire**: [Download IPFire](https://www.ipfire.org/download)
	- **Description:** An open-source firewall and router platform based on Linux. It includes features for network security, including firewalling, routing, and intrusion detection.
- **OPNsense**: [Download OPNsense](https://opnsense.org/download/)
	- **Description:** An open-source firewall and routing platform based on FreeBSD. It offers a range of features for network security, including firewalling, routing, and VPN support.
- **UFW (Uncomplicated Firewall)**: [Learn more about UFW](https://wiki.ubuntu.com/UncomplicatedFirewall)
	- **Description:** A user-friendly front-end for managing iptables firewall rules. It is commonly used on Ubuntu and other Linux distributions to simplify firewall configuration.

## Managed Detection Services
Services that provide outsourced monitoring and management of security systems and devices.
- **CrowdStrike Falcon**: [Learn more about CrowdStrike Falcon](https://www.crowdstrike.com/)
	- **Description:** A cloud-based endpoint protection platform that includes managed detection and response (MDR) services. It provides real-time threat detection, investigation, and response.
- **FireEye Helix**: [Learn more about FireEye Helix](https://www.fireeye.com/solutions/helix.html)
	- **Description:** A security operations platform that includes managed detection and response (MDR) services. It provides real-time threat detection, investigation, and response.
- **Palo Alto Networks Cortex XDR**: [Learn more about Cortex XDR](https://www.paloaltonetworks.com/cortex/cortex-xdr)
	- **Description:** A cloud-based security platform that includes managed detection and response (MDR) services. It provides real-time threat detection, investigation, and response.

## Endpoint Protection
Tools and resources used to protect individual devices (endpoints) from security threats.
- **CrowdStrike Falcon**: [Learn more about CrowdStrike Falcon](https://www.crowdstrike.com/)
	- **Description:** A cloud-based endpoint protection platform that provides real-time threat detection, investigation, and response.
- **Symantec Endpoint Protection**: [Learn more about Symantec Endpoint Protection](https://www.broadcom.com/products/cyber-security/endpoint)
	- **Description:** A comprehensive endpoint protection solution that includes antivirus, anti-malware, and threat detection features.
- **Trend Micro Apex One**: [Learn more about Trend Micro Apex One](https://www.trendmicro.com/en_us/business/products/user-protection/sps/endpoint-security/advanced.html)
	- **Description:** An endpoint protection platform that provides real-time threat detection, investigation, and response.

## Security Information and Event Management (SIEM)
Tools and resources used to collect, analyze, and respond to security-related data from various sources.
- **Splunk**: [Learn more about Splunk](https://www.splunk.com/)
	- **Description:** A platform for searching, monitoring, and analyzing machine-generated big data. It is widely used for security information and event management (SIEM) and log management.
- **IBM QRadar**: [Learn more about IBM QRadar](https://www.ibm.com/security/security-intelligence/qradar)
	- **Description:** A comprehensive security information and event management (SIEM) solution that provides real-time threat detection, investigation, and response.
- **Elastic Stack (ELK Stack)**: [Learn more about Elastic Stack](https://www.elastic.co/elastic-stack)
	- **Description:** A collection of open-source tools (Elasticsearch, Logstash, and Kibana) used for searching, analyzing, and visualizing log data. It is widely used for log management and security information and event management (SIEM).
- **ArcSight**: [Learn more about ArcSight](https://www.microfocus.com/en-us/cyberres/secops/arcsight)
	- **Description:** A security information and event management (SIEM) solution that provides real-time threat detection, investigation, and response.

## License
This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

