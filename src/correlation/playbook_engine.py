"""
Response Playbook Engine for CyberVision.
Provides standardized, safe NIST SP 800-61 Rev 2 aligned incident response guidance
mapped directly to MITRE ATT&CK techniques and detected threat categories.
Strictly non-destructive: all containment guidance requires explicit human analyst approval.
"""

from typing import Dict, Any, List, Optional


class ResponsePlaybookEngine:
    """Generates actionable, safe, non-destructive incident response guidance."""

    PLAYBOOK_CATALOG: Dict[str, Dict[str, Any]] = {
        "T1046": {
            "playbook_id": "PB-REC-01",
            "name": "Network Reconnaissance & Port Scan Containment",
            "mitre_id": "T1046",
            "threat_category": "PortScan / Reconnaissance",
            "severity_default": "Medium",
            "rationale": "High volumetric port scan activity detected across enterprise subnets without prior authorization.",
            "safe_investigation_steps": [
                "1. Verify whether the source IP belongs to an internal vulnerability scanner (e.g., Nessus/Qualys) or approved penetration test.",
                "2. Cross-reference source IP reputation against AbuseIPDB and GreyNoise cache.",
                "3. Query firewall/NetFlow logs for subsequent SYN-ACK completions to determine if any probed ports are open.",
                "4. Check destination host OS versions to verify if open ports host unpatched services."
            ],
            "containment_guidance": [
                "• Recommended Action: Apply temporary border firewall rate-limiting rule (drop TCP SYN > 100/s from source IP).",
                "• Required Gate: Human Analyst Sign-off required before updating perimeter ACLs.",
                "• Safety Assurance: Non-destructive; legitimate internal services remain operational."
            ],
            "eradication_and_recovery": [
                "• Close unneeded listening ports identified during the scan.",
                "• Ensure administrative interfaces (SSH/RDP) are bound strictly to internal management subnets behind VPN."
            ]
        },
        "T1110": {
            "playbook_id": "PB-CRED-02",
            "name": "Brute Force & Credential Access Triage",
            "mitre_id": "T1110.001",
            "threat_category": "SSH_Patator / FTP_Patator / Credential Access",
            "severity_default": "High",
            "rationale": "Multiple repeated authentication failures observed within a compressed temporal correlation window.",
            "safe_investigation_steps": [
                "1. Audit authentication logs (auth.log / Security Event 4625) for target accounts.",
                "2. Check whether any authentication attempts succeeded immediately following the failure burst (Event 4624).",
                "3. Check user location/IP geolocation against typical baseline travel patterns.",
                "4. Verify whether compromised accounts have administrative or domain privileges."
            ],
            "containment_guidance": [
                "• Recommended Action: Prompt user for mandatory MFA re-challenge and invalidate active Kerberos/OAuth session tokens.",
                "• Required Gate: Tier-2 SOC Analyst authorization required before user session revocation.",
                "• Safety Assurance: Account is not locked out; user can re-authenticate via out-of-band MFA."
            ],
            "eradication_and_recovery": [
                "• Force secure password rotation for targeted accounts.",
                "• Enable fail2ban or adaptive lockout policies on exposed authentication endpoints."
            ]
        },
        "T1548": {
            "playbook_id": "PB-PRIV-03",
            "name": "Host Privilege Escalation & setuid Execution",
            "mitre_id": "T1548",
            "threat_category": "Kernel_PrivEsc_Setuid / Namespace Escape",
            "severity_default": "Critical",
            "rationale": "eBPF kernel telemetry captured setuid(0) or namespace modification executed by unprivileged process tree.",
            "safe_investigation_steps": [
                "1. Inspect parent process binary hash on disk and calculate SHA-256 for VirusTotal lookup.",
                "2. Examine eBPF execve telemetry to identify command-line arguments and environment variables passed.",
                "3. Review `/etc/sudoers` and file permission changes within 10 minutes prior to the event.",
                "4. Check for active root shell persistence (cron jobs, systemd units, authorized_keys modifications)."
            ],
            "containment_guidance": [
                "• Recommended Action: Place affected host endpoint into an isolated containment VLAN (allow only forensic collection).",
                "• Required Gate: SOC Lead / Incident Commander approval required before host network quarantine.",
                "• Safety Assurance: Memory snapshot is preserved before any shutdown or reboot."
            ],
            "eradication_and_recovery": [
                "• Terminate rogue spawned child processes using PID verification.",
                "• Patch underlying Linux kernel / sudo vulnerability to latest patched vendor release."
            ]
        },
        "T1048": {
            "playbook_id": "PB-EXFIL-04",
            "name": "Unauthorized Data Exfiltration & Cloud Staging",
            "mitre_id": "T1048",
            "threat_category": "Cloud_Staging_Exfil / Removable_USB_Exfil",
            "severity_default": "High",
            "rationale": "Large anomalous outbound file transfer or USB device write volume detected during off-hours window.",
            "safe_investigation_steps": [
                "1. Identify the exact destination IP / domain / cloud bucket receiving the transferred data payload.",
                "2. Inspect DLP (Data Loss Prevention) file classification tags on files accessed prior to transfer.",
                "3. Review user role, department, and historical data transfer baseline for the past 90 days.",
                "4. Check if a formal off-boarding or project completion ticket is open for the user."
            ],
            "containment_guidance": [
                "• Recommended Action: Apply egress traffic policy block to destination cloud endpoint on perimeter firewall.",
                "• Required Gate: Human Security Operations approval required before firewall rule deployment.",
                "• Safety Assurance: Internal file access is maintained; only outbound transfer to unapproved target is halted."
            ],
            "eradication_and_recovery": [
                "• Notify data privacy officer and legal counsel if PII/customer data was staged.",
                "• Revoke cloud bucket API keys and regenerate enterprise storage credentials."
            ]
        },
        "T1498": {
            "playbook_id": "PB-DOS-05",
            "name": "Network Denial of Service (DoS / DDoS) Mitigation",
            "mitre_id": "T1498",
            "threat_category": "DoS_Hulk / DDoS_LOIT",
            "severity_default": "High",
            "rationale": "High-volume volumetric flood exceeding baseline bandwidth thresholds by greater than 50x.",
            "safe_investigation_steps": [
                "1. Identify flood characteristics: UDP amplification, SYN flood, or HTTP application-layer GET/POST flood.",
                "2. Determine whether attack originates from external botnet pool or compromised internal zombie hosts.",
                "3. Check target service CPU/RAM utilization and connection backlog pool health."
            ],
            "containment_guidance": [
                "• Recommended Action: Activate upstream cloud scrubbing center / CDN DDoS mitigation shield.",
                "• Required Gate: Network Operations approval required before routing BGP prefixes to scrubbing center.",
                "• Safety Assurance: Legitimate traffic is proxy-inspected; service availability is restored."
            ],
            "eradication_and_recovery": [
                "• Implement ingress SYN cookies and rate limiting at the perimeter switch layer.",
                "• Cleanse identified internal compromised hosts participating in the flood."
            ]
        },
        "T1190": {
            "playbook_id": "PB-EXP-06",
            "name": "Exploit Public-Facing Application (SQLi / Web Exploit)",
            "mitre_id": "T1190",
            "threat_category": "Exploits / Web_SQLi_XSS",
            "severity_default": "Critical",
            "rationale": "HTTP payload telemetry contains SQL injection, directory traversal, or shellcode patterns.",
            "safe_investigation_steps": [
                "1. Check Web Application Firewall (WAF) logs and web server access logs for HTTP 500 / 200 responses.",
                "2. Verify whether SQL query succeeded in dumping database tables or returning error stack traces.",
                "3. Check whether web server process spawned unexpected sub-shells (`/bin/sh`, `/bin/bash`)."
            ],
            "containment_guidance": [
                "• Recommended Action: Deploy virtual patch on WAF to block specific injection payload regex.",
                "• Required Gate: Web Application Owner & SOC approval required.",
                "• Safety Assurance: Fix applies only to malicious payloads; normal transactions continue unaffected."
            ],
            "eradication_and_recovery": [
                "• Parameterize underlying database query in application source code.",
                "• Sanitize user inputs and update WAF signatures."
            ]
        },
        "DEFAULT": {
            "playbook_id": "PB-GEN-99",
            "name": "Anomalous Intrusion & Zero-Day Triage Guide",
            "mitre_id": "T1000",
            "threat_category": "Zero-Day / Statistical Telemetry Anomaly",
            "severity_default": "Medium",
            "rationale": "Deep Autoencoder or Isolation Forest detected anomalous metric deviations exceeding 99th percentile threshold.",
            "safe_investigation_steps": [
                "1. Review TreeSHAP attribution ranking to identify which telemetry features drove the anomaly score.",
                "2. Verify whether abnormal metric corresponds to scheduled maintenance, software deployment, or legitimate bulk backup.",
                "3. Correlate with concurrent host and application logs across identical host/user entities.",
                "4. Capture PCAP packet capture and forensic host memory dump for sandbox inspection."
            ],
            "containment_guidance": [
                "• Recommended Action: Increase telemetry verbosity on affected host from standard to debug level.",
                "• Required Gate: SOC Analyst review required.",
                "• Safety Assurance: Observational monitoring only; zero impact on production workloads."
            ],
            "eradication_and_recovery": [
                "• If malicious intent is confirmed by sandbox analysis, formulate customized detection signature.",
                "• If verified as benign operational anomaly, incorporate profile into unsupervised retraining baseline."
            ]
        }
    }

    @classmethod
    def get_playbook_for_alert(cls, mitre_technique_id: str, attack_category: str = "") -> Dict[str, Any]:
        """Returns the appropriate playbook matching MITRE technique or attack category."""
        # Check by prefix / exact technique
        tech_prefix = mitre_technique_id.split(".")[0].upper() if mitre_technique_id else ""
        if tech_prefix in cls.PLAYBOOK_CATALOG:
            return cls.PLAYBOOK_CATALOG[tech_prefix]

        # Check by attack category keywords
        cat_lower = attack_category.lower()
        if "port" in cat_lower or "scan" in cat_lower or "recon" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1046"]
        elif "patator" in cat_lower or "brute" in cat_lower or "cred" in cat_lower or "logon" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1110"]
        elif "priv" in cat_lower or "setuid" in cat_lower or "root" in cat_lower or "escape" in cat_lower or "spawn" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1548"]
        elif "exfil" in cat_lower or "usb" in cat_lower or "staging" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1048"]
        elif "dos" in cat_lower or "ddos" in cat_lower or "flood" in cat_lower or "loit" in cat_lower or "hulk" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1498"]
        elif "exploit" in cat_lower or "sqli" in cat_lower or "xss" in cat_lower or "fuzzer" in cat_lower:
            return cls.PLAYBOOK_CATALOG["T1190"]

        return cls.PLAYBOOK_CATALOG["DEFAULT"]
