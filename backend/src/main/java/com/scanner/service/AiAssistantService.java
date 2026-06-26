package com.scanner.service;

import org.springframework.stereotype.Service;
import java.util.HashMap;
import java.util.Map;

@Service
public class AiAssistantService {

    public String generateSecurityAdvice(String message) {
        if (message == null || message.trim().isEmpty()) {
            return "Please enter a valid cybersecurity query (e.g., 'Why is Port 445 dangerous?').";
        }

        String query = message.toLowerCase().trim();

        // 1. Port 445 (SMB)
        if (query.contains("445") || query.contains("smb")) {
            return "### 🛡️ Port 445 (Microsoft-DS / SMB) Vulnerability Report\n\n" +
                    "**Risk Level:** 🔴 CRITICAL\n\n" +
                    "**Threat Overview:** Port 445 runs Server Message Block (SMB). Outdated versions (like SMBv1) are vulnerable to remote code execution (RCE) exploits such as **EternalBlue (MS17-010)**, famously used in WannaCry and NotPetya ransomware attacks.\n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Windows (Disable SMBv1):**\n" +
                    "  `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`\n" +
                    "* **Linux (Block Port via iptables):**\n" +
                    "  `sudo iptables -A INPUT -p tcp --dport 445 -j DROP`\n" +
                    "* **Windows Firewall (Block incoming 445):**\n" +
                    "  `netsh advfirewall firewall add rule name=\"Block SMB 445\" protocol=TCP localport=445 action=block dir=in`";
        }

        // 2. Port 21 (FTP)
        if (query.contains("21") || query.contains("ftp")) {
            return "### 🛡️ Port 21 (File Transfer Protocol) Vulnerability Report\n\n" +
                    "**Risk Level:** 🟠 HIGH\n\n" +
                    "**Threat Overview:** Standard FTP on Port 21 transmits login credentials and session payloads in plaintext, leaving it vulnerable to credential sniffing and man-in-the-middle (MITM) attacks. Older installations (e.g., vsFTPd 2.3.4) also harbor backdoors.\n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Action Plan:** Switch to SFTP (SSH File Transfer Protocol) running securely on Port 22.\n" +
                    "* **Linux (Disable FTP service):**\n" +
                    "  `sudo systemctl stop vsftpd && sudo systemctl disable vsftpd`\n" +
                    "* **Linux (Block Port via iptables):**\n" +
                    "  `sudo iptables -A INPUT -p tcp --dport 21 -j DROP`";
        }

        // 3. Port 23 (Telnet)
        if (query.contains("23") || query.contains("telnet")) {
            return "### 🛡️ Port 23 (Telnet) Vulnerability Report\n\n" +
                    "**Risk Level:** 🔴 CRITICAL (Violation of PCI-DSS & CIS Controls)\n\n" +
                    "**Threat Overview:** Telnet communicates entirely in cleartext. Any attacker sniffing traffic on the network can capture your administrative credentials. \n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Action Plan:** Migrate immediately to SSH (Secure Shell) on Port 22.\n" +
                    "* **Linux (Stop Telnet service):**\n" +
                    "  `sudo systemctl stop inetd` or `sudo systemctl stop xinetd`\n" +
                    "* **Linux (Block Port via iptables):**\n" +
                    "  `sudo iptables -A INPUT -p tcp --dport 23 -j DROP`";
        }

        // 4. SYN Flood (DDoS)
        if (query.contains("syn") || query.contains("ddos") || query.contains("flood")) {
            return "### 🛡️ SYN Flood DDoS Mitigation Report\n\n" +
                    "**Threat Overview:** A SYN Flood consumes server TCP socket resource tables by transmitting a massive volume of SYN request packets without completing the three-way handshake.\n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Linux (Enable TCP SYN Cookies):**\n" +
                    "  `sysctl -w net.ipv4.tcp_syncookies=1`\n" +
                    "* **Linux (Limit TCP SYN connection rates):**\n" +
                    "  `sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 4 -j ACCEPT`\n" +
                    "  `sudo iptables -A INPUT -p tcp --syn -j DROP`";
        }

        // 5. ARP Spoofing
        if (query.contains("arp") || query.contains("spoof")) {
            return "### 🛡️ ARP Spoofing / Poisoning Defense\n\n" +
                    "**Threat Overview:** Attacking nodes send spoofed Address Resolution Protocol (ARP) responses to the local network to link their MAC address with the IP of the gateway router, enabling man-in-the-middle (MITM) credential sniffing.\n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Enterprise Mitigation:** Implement Dynamic ARP Inspection (DAI) on corporate network switches.\n" +
                    "* **Linux (Bind Gateway IP static MAC):**\n" +
                    "  `arp -s 192.168.1.1 00:11:22:33:44:55` (Replace with your actual router MAC)\n" +
                    "* **Windows (Bind Gateway static MAC):**\n" +
                    "  `netsh interface ipv4 add neighbors \"Ethernet\" \"192.168.1.1\" \"00-11-22-33-44-55\"`";
        }

        // 6. CVE-2011-2523 (vsFTPd backdoor)
        if (query.contains("cve-2011-2523") || query.contains("vsftpd 2.3.4")) {
            return "### 🛡️ Exploit Mitigation: CVE-2011-2523\n\n" +
                    "**Risk Level:** 🔴 CRITICAL (RCE Backdoor Exploit)\n\n" +
                    "**Threat Overview:** The vsFTPd 2.3.4 package contains a built-in backdoor. If a connection payload ends with a smiley face `:)` on port 21, the daemon opens an unauthenticated root command shell on Port 6200.\n\n" +
                    "**Mitigation Commands:**\n" +
                    "* **Upgrade Packages immediately:**\n" +
                    "  `sudo apt-get update && sudo apt-get install --only-upgrade vsftpd`\n" +
                    "* **Block Port 6200 backdoor entry:**\n" +
                    "  `sudo iptables -A INPUT -p tcp --dport 6200 -j DROP`";
        }

        // Generic cybersecurity query default response
        return "### 🤖 AI Cybersecurity Assistant Analysis\n\n" +
                "**Query Analyzed:** \"" + message + "\"\n\n" +
                "To optimize security for this asset, apply standard hardening practices:\n" +
                "1. **Audit Open Services:** Close unused logical ports on your host firewall.\n" +
                "2. **Force Strong Encryption:** Transition cleartext configurations (FTP, Telnet, HTTP) to secure tunnels (SFTP, SSH, HTTPS).\n" +
                "3. **Update Daemon Softwares:** Regularly map application versions to vulnerability databases and install patches.\n\n" +
                "*Tip: Ask me about ports (e.g. 'Port 445', 'Port 23'), attacks ('SYN Flood', 'ARP Spoofing'), or exploits ('CVE-2011-2523') for direct terminal mitigation commands!*";
    }
}
