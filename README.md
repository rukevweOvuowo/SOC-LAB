# SOC Analyst Playbook 

**A comprehensive knowledge base and investigation guide** for SOC (Security Operations Center) Analysts.  
This repository contains methodologies, analysis notes, and practical workflows for detecting, investigating, and responding to security incidents across different domains of cybersecurity.  

>  **Beginner to Advanced:** This playbook is structured to help learners progress from foundational concepts to advanced SOC analysis techniques.  


##  Areas Covered  

This playbook is organized into different sections of SOC analysis:  

- **Network Traffic Analysis** – Investigating suspicious traffic, anomalies, data exfiltration, DNS tunneling, and C2 communications.  
- **Endpoint & Host Investigations** – Malware detection, process analysis, persistence mechanisms, registry changes, and forensic artifacts.  
- **User & Identity Behavior** – Analyzing suspicious logins, brute force attempts, privilege escalation, and insider threat activity.  
- **Cloud & SaaS Security** – Monitoring Microsoft 365, Google Workspace, AWS, Azure, and GCP for account compromise or misconfigurations.  
- **Web & Application Security** – Analyzing web server logs, exploit attempts, API abuse, and web shell detection.  
- **Threat Hunting & OSINT** – Using open-source intelligence and proactive hunting techniques to find indicators of compromise (IOCs).  
- **Phishing & Email Security** – Breaking down email headers, analyzing suspicious links/attachments, and verifying domains.  


##  Tools Used  

The playbook demonstrates the use of **OSINT and analysis tools** to enrich investigations:  

- **[VirusTotal](https://www.virustotal.com/)** – For scanning domains, IPs, URLs, and file hashes against multiple AV vendors.  
- **[CyberChef](https://gchq.github.io/CyberChef/)** – For decoding, decrypting, and analyzing encoded payloads (e.g., Base64 commands).  
- **[Abuse.ch](https://abuse.ch/)** – For malware and threat intelligence (AsyncRAT, TrickBot, Emotet, etc.).  
- **[DomainTools / WHOIS](https://whois.domaintools.com/)** – For domain registration lookups and age verification.  
- **[Wireshark](https://www.wireshark.org/)** – For deep packet inspection and network protocol analysis.  
- **[Notepad++](https://notepad-plus-plus.org/)** – For analyzing email headers and raw logs with syntax highlighting.  
- **[Shodan](https://www.shodan.io/)** – For finding exposed systems, services, and attacker infrastructure.  
- **[Hybrid Analysis](https://www.hybrid-analysis.com/)** – For sandboxing malware samples and extracting behavioral reports.
