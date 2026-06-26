import React, { useState, useEffect, useRef } from 'react';
import './App.css';

// SVG Icons to avoid Lucide React peer dependency issues in React 19
const DashboardIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>
);
const ScanIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>
);
const ShieldIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
);
const MapIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/></svg>
);
const HistoryIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
);
const IntelIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/></svg>
);
const AssistantIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/></svg>
);

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isDemoMode, setIsDemoMode] = useState(false);
  const [backendConnected, setBackendConnected] = useState(false);

  // Authentication & RBAC States
  const [user, setUser] = useState(null); // { username, role, token }
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);
  const [registerRole, setRegisterRole] = useState('VIEWER');

  // Port Scanner States
  const [targetHost, setTargetHost] = useState('127.0.0.1');
  const [startPort, setStartPort] = useState('1');
  const [endPort, setEndPort] = useState('1024');
  const [timeout, setTimeoutVal] = useState('200');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [scanResults, setScanResults] = useState([]);
  
  // IDS & Sniffer States
  const [snifferActive, setSnifferActive] = useState(true);
  const [packets, setPackets] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [packetStats, setPacketStats] = useState({ total: 0, rate: 0, bandwidth: 0 });

  // Map / Topology State
  const [selectedNode, setSelectedNode] = useState(null);

  // History State
  const [historyList, setHistoryList] = useState([]);

  // Threat Intel States (Module 9)
  const [intelIp, setIntelIp] = useState('185.190.140.23');
  const [intelResult, setIntelResult] = useState(null);
  const [intelLoading, setIntelLoading] = useState(false);

  // AI Security Assistant States
  const [chatMessages, setChatMessages] = useState([
    { sender: 'ai', text: "Hello! I am your AI Security Assistant. Ask me about vulnerabilities, ports (e.g., 'Port 445'), attacks ('SYN Flood'), or exploits ('CVE-2011-2523') to get instant mitigation advice." }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);

  const API_BASE = 'http://localhost:8080/api';

  // Check Backend Connection and session on Mount
  useEffect(() => {
    const savedUser = localStorage.getItem('cyber_user');
    if (savedUser) {
      try {
        const parsed = JSON.parse(savedUser);
        setUser(parsed);
        verifyBackendConnection(parsed.token);
      } catch (e) {
        localStorage.removeItem('cyber_user');
        verifyBackendConnection(null);
      }
    } else {
      verifyBackendConnection(null);
    }
  }, []);

  const verifyBackendConnection = (token) => {
    fetch(`${API_BASE}/auth/ping`)
      .then(res => {
        if (res.ok) {
          setBackendConnected(true);
          setIsDemoMode(false);
          if (token) {
            const headers = { 'Authorization': `Bearer ${token}` };
            fetch(`${API_BASE}/history`, { headers })
              .then(histRes => {
                if (histRes.status === 401 || histRes.status === 403) {
                  handleLogout();
                } else {
                  loadHistory(token);
                  loadTopology(token);
                }
              })
              .catch(() => {
                handleLogout();
              });
          }
        } else {
          setBackendConnected(false);
          setIsDemoMode(true);
        }
      })
      .catch(() => {
        setBackendConnected(false);
        setIsDemoMode(true);
      });
  };

  const loadHistory = (token) => {
    const activeToken = token || (user ? user.token : null);
    const headers = activeToken ? { 'Authorization': `Bearer ${activeToken}` } : {};
    
    fetch(`${API_BASE}/history`, { headers })
      .then(res => {
        if (res.status === 401 || res.status === 403) {
          handleLogout();
          return [];
        }
        return res.json();
      })
      .then(data => setHistoryList(data))
      .catch(err => console.error("Error loading history: ", err));
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    setAuthError('');

    if (isDemoMode) {
      // Mock login check for offline/demo presentation
      const u = authUsername.toLowerCase();
      if ((u === 'admin' && authPassword === 'admin123') ||
          (u === 'analyst' && authPassword === 'analyst123') ||
          (u === 'viewer' && authPassword === 'viewer123')) {
        
        let role = 'VIEWER';
        if (u === 'admin') role = 'ADMIN';
        if (u === 'analyst') role = 'ANALYST';

        const mockUser = { username: authUsername, role, token: 'mock-jwt-token' };
        setUser(mockUser);
        localStorage.setItem('cyber_user', JSON.stringify(mockUser));
      } else {
        setAuthError('Invalid credentials (use the demo logins below).');
      }
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: authUsername, password: authPassword })
      });

      if (!res.ok) {
        const errData = await res.json();
        setAuthError(errData.message || 'Login failed.');
        return;
      }

      const data = await res.json();
      const authenticatedUser = { username: data.username, role: data.role, token: data.token };
      setUser(authenticatedUser);
      localStorage.setItem('cyber_user', JSON.stringify(authenticatedUser));
      loadHistory(data.token);
    } catch (err) {
      setAuthError('Failed to connect to authentication backend.');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setAuthError('');

    try {
      const res = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: authUsername, password: authPassword, role: registerRole })
      });

      if (!res.ok) {
        const errData = await res.json();
        setAuthError(errData.message || 'Registration failed.');
        return;
      }

      alert('Registration successful! Please login.');
      setIsRegistering(false);
      setAuthPassword('');
    } catch (err) {
      setAuthError('Failed to connect to authentication backend.');
    }
  };

  const handleLogout = () => {
    setUser(null);
    localStorage.removeItem('cyber_user');
    setAuthUsername('');
    setAuthPassword('');
    setAuthError('');
  };

  const queryIntel = async (ipToQuery) => {
    const ip = ipToQuery || intelIp;
    setIntelLoading(true);
    setIntelResult(null);

    if (isDemoMode) {
      await new Promise(r => setTimeout(r, 600));
      const mockResult = {
        ip,
        isPublic: !ip.startsWith("127.") && !ip.startsWith("192.168."),
        ipVersion: 4,
        isMocked: true
      };

      if (ip === '8.8.8.8') {
        mockResult.abuseConfidenceScore = 0;
        mockResult.countryCode = 'US';
        mockResult.usageType = 'DNS Server';
        mockResult.isp = 'Google LLC';
        mockResult.domain = 'google.com';
        mockResult.totalReports = 0;
        mockResult.lastReportedAt = 'N/A';
      } else if (ip === '185.190.140.23') {
        mockResult.abuseConfidenceScore = 95;
        mockResult.countryCode = 'NL';
        mockResult.usageType = 'Data Center';
        mockResult.isp = 'Creanova Hosting Solutions Ltd';
        mockResult.domain = 'creanovahost.net';
        mockResult.totalReports = 142;
        mockResult.lastReportedAt = new Date().toISOString();
      } else {
        const isPrivate = ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("10.");
        mockResult.abuseConfidenceScore = isPrivate ? 0 : Math.floor(Math.random() * 85);
        mockResult.countryCode = isPrivate ? 'Local' : 'US';
        mockResult.usageType = isPrivate ? 'Intranet' : 'Commercial';
        mockResult.isp = isPrivate ? 'LAN Link' : 'DigitalOcean LLC';
        mockResult.domain = isPrivate ? 'local.net' : 'digitalocean.com';
        mockResult.totalReports = isPrivate ? 0 : Math.floor(Math.random() * 30);
        mockResult.lastReportedAt = isPrivate ? 'N/A' : new Date().toISOString();
      }

      setIntelResult(mockResult);
      setIntelLoading(false);
      return;
    }

    try {
      const token = user ? user.token : null;
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      const res = await fetch(`${API_BASE}/intel?ip=${ip}`, { headers });
      if (res.status === 401 || res.status === 403) {
        handleLogout();
        return;
      }
      const data = await res.json();
      setIntelResult(data);
    } catch (err) {
      console.error(err);
      alert("Error calling Threat Intelligence API. Falling back to Demo Mode.");
    } finally {
      setIntelLoading(false);
    }
  };

  const sendChatMessage = async (e) => {
    if (e) e.preventDefault();
    if (!chatInput.trim()) return;

    const userText = chatInput;
    setChatMessages(prev => [...prev, { sender: 'user', text: userText }]);
    setChatInput('');
    setChatLoading(true);

    if (isDemoMode) {
      await new Promise(r => setTimeout(r, 650));
      let reply = "I am operating in offline demo mode. Please launch the Spring Boot backend to query my full knowledge base.";
      const q = userText.toLowerCase();
      if (q.includes("445") || q.includes("smb")) {
        reply = "### 🛡️ Port 445 (Microsoft-DS / SMB) Vulnerability Report\n\n**Risk Level:** 🔴 CRITICAL\n\n**Threat Overview:** Port 445 runs SMB. Outdated versions are vulnerable to RCE exploits like **EternalBlue (MS17-010)**, used in WannaCry.\n\n**Mitigation Commands:**\n`sudo iptables -A INPUT -p tcp --dport 445 -j DROP`";
      } else if (q.includes("21") || q.includes("ftp")) {
        reply = "### 🛡️ Port 21 (FTP) Vulnerability Report\n\n**Risk Level:** 🟠 HIGH\n\n**Threat Overview:** Plaintext credentials leaks.\n\n**Mitigation Commands:**\n`sudo iptables -A INPUT -p tcp --dport 21 -j DROP`";
      } else if (q.includes("23") || q.includes("telnet")) {
        reply = "### 🛡️ Port 23 (Telnet) Vulnerability Report\n\n**Risk Level:** 🔴 CRITICAL\n\n**Threat Overview:** Insecure plaintext Telnet administrative connection sniffing.\n\n**Mitigation Commands:**\n`sudo iptables -A INPUT -p tcp --dport 23 -j DROP`";
      } else if (q.includes("syn") || q.includes("flood")) {
        reply = "### 🛡️ SYN Flood DDoS Mitigation Report\n\n**Threat Overview:** TCP connection table starvation.\n\n**Mitigation Commands:**\n`sysctl -w net.ipv4.tcp_syncookies=1`";
      } else if (q.includes("arp") || q.includes("spoof")) {
        reply = "### 🛡️ ARP Spoofing / Poisoning Defense\n\n**Threat Overview:** Local network IP redirection.\n\n**Mitigation Commands:**\n`arp -s 192.168.1.1 00:11:22:33:44:55`";
      }

      setChatMessages(prev => [...prev, { sender: 'ai', text: reply }]);
      setChatLoading(false);
      return;
    }

    try {
      const token = user ? user.token : null;
      const headers = { 'Content-Type': 'application/json' };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const res = await fetch(`${API_BASE}/ai/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: userText })
      });

      if (res.ok) {
        const data = await res.json();
        setChatMessages(prev => [...prev, { sender: 'ai', text: data.response }]);
      } else {
        setChatMessages(prev => [...prev, { sender: 'ai', text: "Error: Failed to retrieve security guidance from AI service." }]);
      }
    } catch (err) {
      setChatMessages(prev => [...prev, { sender: 'ai', text: "Error connecting to AI chat backend." }]);
    } finally {
      setChatLoading(false);
    }
  };

  const renderAdviceText = (text) => {
    if (!text) return null;
    return text.split('\n').map((line, idx) => {
      let clean = line.trim();
      if (clean.startsWith("### ")) {
        return <h3 key={idx} style={{ color: 'var(--cyber-blue)', marginTop: '14px', marginBottom: '8px', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '4px' }}>{clean.substring(4)}</h3>;
      }
      if (clean.startsWith("* ")) {
        return <li key={idx} style={{ marginLeft: '20px', listStyleType: 'square', color: 'var(--text-primary)', margin: '4px 0', fontSize: '13px' }}>{clean.substring(2)}</li>;
      }
      if (clean.startsWith("`") && clean.endsWith("`")) {
        const cmd = clean.replaceAll("`", "");
        return (
          <pre key={idx} style={{ background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-subtle)', borderRadius: '6px', padding: '10px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: '#10b981', margin: '8px 0', overflowX: 'auto', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <code>{cmd}</code>
            <button 
              className="btn" 
              style={{ padding: '2px 8px', fontSize: '10px', height: '20px', background: 'rgba(255, 255, 255, 0.05)', border: '1px solid var(--border-subtle)' }}
              onClick={() => navigator.clipboard.writeText(cmd)}
            >
              Copy
            </button>
          </pre>
        );
      }
      if (clean.includes("**")) {
        const parts = clean.split("**");
        return (
          <p key={idx} style={{ margin: '6px 0', fontSize: '13px' }}>
            {parts.map((p, i) => i % 2 === 1 ? <strong key={i} style={{ color: '#fff' }}>{p}</strong> : p)}
          </p>
        );
      }
      return <p key={idx} style={{ margin: '4px 0', color: 'var(--text-secondary)', fontSize: '13px' }}>{line}</p>;
    });
  };

  // Live packet polling (Module 6 & Module 7 IDS)
  useEffect(() => {
    let intervalId;

    const fetchSnifferData = async () => {
      if (isDemoMode) {
        // Generate mock packet
        const protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'ARP', 'ICMP', 'SSH', 'HTTPS'];
        const protocol = protocols[Math.floor(Math.random() * protocols.length)];
        const localIPs = ['192.168.1.1', '192.168.1.12', '192.168.1.45', '192.168.1.100', '192.168.1.15'];
        const externalIPs = ['8.8.8.8', '142.250.190.46', '185.190.140.23', '23.45.67.89'];
        
        const src = localIPs[Math.floor(Math.random() * localIPs.length)];
        const dst = Math.random() > 0.4 
          ? externalIPs[Math.floor(Math.random() * externalIPs.length)]
          : localIPs[Math.floor(Math.random() * localIPs.length)];
          
        const len = Math.floor(Math.random() * 1200) + 40;
        
        let info = 'Generic communication';
        if (protocol === 'HTTP') info = 'GET /index.html HTTP/1.1';
        if (protocol === 'HTTPS') info = 'Client Hello TLSv1.3';
        if (protocol === 'DNS') info = 'Standard query A google.com';
        if (protocol === 'ARP') info = `Who has ${dst}? Tell ${src}`;
        if (protocol === 'ICMP') info = 'Echo (ping) request';
        if (protocol === 'SSH') info = 'SSH-2.0-OpenSSH_8.2p1';

        const newPacket = {
          time: new Date().toLocaleTimeString(),
          protocol,
          src,
          dst,
          len,
          info
        };

        setPackets(prev => [newPacket, ...prev.slice(0, 49)]);
        
        // Update Stats
        setPacketStats(prev => {
          const newTotal = prev.total + 1;
          const newRate = Math.floor(Math.random() * 15) + 5;
          const newBandwidth = Math.floor(newRate * len * 8 / 1000);
          return { total: newTotal, rate: newRate, bandwidth: newBandwidth };
        });

        // Occasional IDS Trigger (Module 7)
        if (Math.random() > 0.95) {
          const attacks = [
            { type: 'Port Scan', severity: 'medium', desc: 'Rapid sequential port connection requests detected.', rec: 'Configure local firewall (iptables) to rate-limit connections.' },
            { type: 'SYN Flood', severity: 'high', desc: 'High rate of TCP SYN packets without finishing handshake.', rec: 'Enable SYN Cookies on the host operating system.' },
            { type: 'ARP Spoofing', severity: 'critical', desc: 'Duplicate IP associations detected for Gateway (192.168.1.1).', rec: 'Configure Static ARP tables and implement dynamic ARP inspection.' },
            { type: 'Brute Force Attempt', severity: 'high', desc: 'Repeated failed SSH logins detected from external IP.', rec: 'Install Fail2ban and temporarily block offender IP.' }
          ];
          const attack = attacks[Math.floor(Math.random() * attacks.length)];
          const newAlert = {
            id: Date.now(),
            time: new Date().toLocaleTimeString(),
            source: externalIPs[Math.floor(Math.random() * externalIPs.length)],
            ...attack
          };
          setAlerts(prev => [newAlert, ...prev]);
        }
      } else {
        // Real Backend Query
        const token = user ? user.token : null;
        const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
        
        try {
          // Fetch Packets
          const resPackets = await fetch(`${API_BASE}/sniffer/packets`, { headers });
          if (resPackets.ok) {
            const dataPackets = await resPackets.json();
            setPackets(dataPackets);
            
            // Calculate dynamic stats
            setPacketStats(prev => {
              const total = dataPackets.length;
              const rate = snifferActive ? Math.min(15, Math.max(1, total - prev.total)) : 0;
              const avgLen = dataPackets.length > 0 ? dataPackets[0].len : 500;
              const bandwidth = Math.floor(rate * avgLen * 8 / 1000);
              return { total: Math.max(prev.total, total), rate, bandwidth };
            });
          }

          // Fetch Alerts
          const resAlerts = await fetch(`${API_BASE}/sniffer/alerts`, { headers });
          if (resAlerts.ok) {
            const dataAlerts = await resAlerts.json();
            setAlerts(dataAlerts);
          }
        } catch (err) {
          console.error("Error polling sniffer: ", err);
        }
      }
    };

    if (snifferActive) {
      fetchSnifferData();
      intervalId = setInterval(fetchSnifferData, 1000);
    }
  }, [snifferActive, isDemoMode, user]);

  const toggleSnifferStatus = async () => {
    const nextState = !snifferActive;
    setSnifferActive(nextState);

    if (!isDemoMode) {
      const token = user ? user.token : null;
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      try {
        await fetch(`${API_BASE}/sniffer/toggle`, {
          method: 'POST',
          headers
        });
      } catch (err) {
        console.error("Error toggling backend sniffer: ", err);
      }
    }
  };

  // Port Scanning Handler (Module 2, 3, 4, 5)
  const triggerScan = async () => {
    setIsScanning(true);
    setScanProgress(0);
    setScanResults([]);

    if (isDemoMode) {
      // Run Simulated Scan for Demo Mode
      const start = parseInt(startPort);
      const end = parseInt(endPort);
      const total = end - start + 1;
      
      const portsToOpen = [21, 22, 23, 80, 443, 3306, 8080];
      const simulatedData = [];

      for (let i = 0; i <= total; i++) {
        await new Promise(r => setTimeout(r, 15)); // simulate latency
        const currentPort = start + i;
        setScanProgress(Math.floor((i / total) * 100));

        if (portsToOpen.includes(currentPort)) {
          let service = 'Unknown';
          let banner = 'No banner';
          let riskLevel = 'LOW';
          let cves = [];

          if (currentPort === 21) { service = 'FTP'; banner = 'vsFTPd 2.3.4'; riskLevel = 'HIGH'; cves = ['CVE-2011-2523 (Backdoor)']; }
          if (currentPort === 22) { service = 'SSH'; banner = 'OpenSSH 7.2'; riskLevel = 'HIGH'; cves = ['CVE-2016-6210 (User enum)', 'CVE-2016-3115']; }
          if (currentPort === 23) { service = 'Telnet'; banner = 'Linux telnetd'; riskLevel = 'HIGH'; cves = ['Plaintext Credentials Protocol']; }
          if (currentPort === 80) { service = 'HTTP'; banner = 'Apache/2.2.15 (CentOS)'; riskLevel = 'CRITICAL'; cves = ['CVE-2017-5638 (RCE)']; }
          if (currentPort === 443) { service = 'HTTPS'; banner = 'Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1'; riskLevel = 'LOW'; }
          if (currentPort === 3306) { service = 'MySQL'; banner = 'MySQL 5.5.62'; riskLevel = 'MEDIUM'; cves = ['CVE-2012-2122 (Auth Bypass)']; }

          const result = {
            id: Date.now() + currentPort,
            host: targetHost,
            port: currentPort,
            state: 'OPEN',
            service,
            banner,
            riskLevel,
            cves: cves.join(', ') || 'None',
            scanTime: new Date().toLocaleString()
          };
          simulatedData.push(result);
          setScanResults(prev => [...prev, result]);
        }
      }
      setIsScanning(false);
      setScanProgress(100);
      
      // Save simulated result to mock history
      setHistoryList(prev => [...simulatedData, ...prev]);
    } else {
      // Backend Real Scan API Call
      const token = user ? user.token : null;
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};

      try {
        const res = await fetch(`${API_BASE}/scan?host=${targetHost}&startPort=${startPort}&endPort=${endPort}&timeout=${timeout}`, {
          method: 'POST',
          headers
        });

        if (res.status === 401 || res.status === 403) {
          alert("Access Denied! You do not have the privileges required to run network scans (Require Admin/Analyst).");
          if (res.status === 401) handleLogout();
          return;
        }

        const data = await res.json();
        
        // Enrich data with CVE descriptions (Module 5 Client side simulation mapping)
        const enriched = data.map(item => {
          let cves = 'None';
          if (item.port === 21 && (item.banner && item.banner.includes('2.3.4'))) cves = 'CVE-2011-2523 (Backdoor)';
          if (item.port === 22 && (item.banner && item.banner.includes('7.2'))) cves = 'CVE-2016-6210, CVE-2016-3115';
          if (item.port === 80 && (item.banner && item.banner.includes('2.2'))) cves = 'CVE-2017-5638 (Remote Code Execution)';
          return { ...item, cves };
        });

        setScanResults(enriched);
        loadHistory(token);
      } catch (err) {
        alert("Error connecting to Spring Boot backend. Switching to Demo Mode.");
        setIsDemoMode(true);
      } finally {
        setIsScanning(false);
        setScanProgress(100);
      }
    }
  };

  const downloadPdfReport = (host) => {
    if (isDemoMode) {
      alert("Generating offline PDF report from findings. Start the Spring Boot backend to enable the OpenPDF template.");
      
      // If scan has been performed, print actual scan findings. Otherwise, print standard demo findings.
      const resultsToPrint = scanResults.length > 0 ? scanResults : [
        { port: 21, service: 'FTP', banner: 'vsFTPd 2.3.4', riskLevel: 'HIGH' },
        { port: 22, service: 'SSH', banner: 'OpenSSH 7.2', riskLevel: 'HIGH' },
        { port: 23, service: 'Telnet', banner: 'Linux telnetd', riskLevel: 'HIGH' },
        { port: 80, service: 'HTTP', banner: 'Apache/2.2.15 (CentOS)', riskLevel: 'CRITICAL' },
        { port: 443, service: 'HTTPS', banner: 'Apache/2.4.41 (Ubuntu)', riskLevel: 'LOW' },
        { port: 3306, service: 'MySQL', banner: 'MySQL 5.5.62', riskLevel: 'MEDIUM' }
      ];

      let tableRows = "";
      resultsToPrint.forEach(res => {
        const portStr = String(res.port).padEnd(8, ' ');
        const serviceStr = res.service.substring(0, 8).padEnd(10, ' ');
        const bannerStr = (res.banner || 'N/A').substring(0, 24).padEnd(26, ' ');
        const riskStr = res.riskLevel;
        tableRows += `0 -15 Td\n(${portStr}${serviceStr}${bannerStr}${riskStr}) Tj\n`;
      });

      const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> /MediaBox [0 0 595 842] /Contents 5 0 R >>
endobj
4 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>
endobj
5 0 obj
<< /Length 2500 >>
stream
BT
/F1 18 Tf
50 780 Td
(VULNERABILITY SCAN AUDIT REPORT) Tj
/F1 10 Tf
0 -35 Td
(Host Target IP : ${host}) Tj
0 -15 Td
(Scan Timestamp : ${new Date().toLocaleString()}) Tj
0 -15 Td
(Execution Mode : Offline Audit Scan \(Demo Mode\)) Tj
0 -30 Td
(1. Executive Summary) Tj
0 -15 Td
(A network security assessment was run. Discovered services are listed below.) Tj
0 -30 Td
(2. Audit Findings List) Tj
0 -20 Td
(Port    Service   Version/Banner            Severity) Tj
0 -10 Td
(----------------------------------------------------) Tj
${tableRows}0 -35 Td
(3. Recommendations & Mitigations) Tj
0 -15 Td
(- Upgrade outdated host daemons \(Apache 2.2 / OpenSSH 7.2\).) Tj
0 -15 Td
(- Terminate unencrypted plaintext connections \(Telnet / FTP\).) Tj
0 -15 Td
(- Secure relational database listeners with firewall filtering.) Tj
ET
endstream
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000060 00000 n 
0000000119 00000 n 
0000000242 00000 n 
0000000311 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
512
%%EOF`;

      const blob = new Blob([pdfContent], { type: 'application/pdf' });
      const element = document.createElement("a");
      element.href = URL.createObjectURL(blob);
      element.download = "scan-report-" + host + ".pdf";
      document.body.appendChild(element);
      element.click();
      document.body.removeChild(element);
    } else {
      const token = user ? user.token : null;
      const headers = token ? { 'Authorization': `Bearer ${token}` } : {};
      fetch(`${API_BASE}/report/pdf?host=${host}`, { headers })
        .then(res => {
          if (res.status === 401 || res.status === 403) {
            alert("Access Denied! You do not have the privileges required to download reports (Require Admin/Analyst).");
            if (res.status === 401) handleLogout();
            return null;
          }
          return res.blob();
        })
        .then(blob => {
          if (!blob) return;
          const element = document.createElement("a");
          element.href = URL.createObjectURL(blob);
          element.download = "scan-report-" + host + ".pdf";
          document.body.appendChild(element);
          element.click();
          document.body.removeChild(element);
        })
        .catch(err => console.error("Error downloading PDF: ", err));
    }
  };

  // Node details for Interactive Topology (Module 1, 10 & 17)
  const [networkNodes, setNetworkNodes] = useState([
    { id: 'gateway', label: 'Gateway Router', ip: '192.168.1.1', mac: '00:1A:2B:3C:4D:5E', vendor: 'Cisco Systems', os: 'IOS XE', latency: '2 ms', ports: '80, 443', risk: 'LOW', x: 250, y: 80 },
    { id: 'laptop', label: 'Workstation Dell', ip: '192.168.1.12', mac: 'BC:83:85:D9:D2:11', vendor: 'Dell Inc.', os: 'Windows 11', latency: '15 ms', ports: '135, 139, 445', risk: 'MEDIUM', x: 100, y: 220 },
    { id: 'server', label: 'Database Server', ip: '192.168.1.45', mac: '00:50:56:AB:CD:12', vendor: 'VMware', os: 'Ubuntu Server 22.04', latency: '4 ms', ports: '22, 80, 3306', risk: 'CRITICAL', x: 250, y: 220 },
    { id: 'printer', label: 'HP Network Printer', ip: '192.168.1.100', mac: 'A4:5E:60:DF:1E:54', vendor: 'HP Inc.', os: 'Embedded RTOS', latency: '22 ms', ports: '9100, 631', risk: 'LOW', x: 400, y: 220 },
    { id: 'phone', label: 'Android SmartPhone', ip: '192.168.1.15', mac: 'F8:E9:03:77:88:AC', vendor: 'Samsung', os: 'Android 13', latency: '35 ms', ports: 'None Open', risk: 'LOW', x: 250, y: 350 }
  ]);
  const [loadingTopology, setLoadingTopology] = useState(false);

  const loadTopology = async (token) => {
    const activeToken = token || (user ? user.token : null);
    if (!activeToken) return;

    setLoadingTopology(true);
    const headers = activeToken ? { 'Authorization': `Bearer ${activeToken}` } : {};

    try {
      const res = await fetch(`${API_BASE}/devices`, { headers });
      if (res.ok) {
        const data = await res.json();
        if (data && data.length > 0) {
          setNetworkNodes(data);
        }
      }
    } catch (err) {
      console.error("Error loading network topology: ", err);
    } finally {
      setLoadingTopology(false);
    }
  };

  const getOverallRisk = () => {
    let maxRisk = 'LOW';
    networkNodes.forEach(node => {
      const risk = node.risk ? node.risk.toUpperCase() : 'LOW';
      if (risk === 'CRITICAL') maxRisk = 'CRITICAL';
      else if (risk === 'HIGH' && maxRisk !== 'CRITICAL') maxRisk = 'HIGH';
      else if (risk === 'MEDIUM' && maxRisk !== 'CRITICAL' && maxRisk !== 'HIGH') maxRisk = 'MEDIUM';
    });

    if (maxRisk === 'CRITICAL') return { score: 90, grade: 'CRITICAL RISK', color: 'var(--color-critical)' };
    if (maxRisk === 'HIGH') return { score: 72, grade: 'HIGH RISK', color: 'var(--color-high)' };
    if (maxRisk === 'MEDIUM') return { score: 45, grade: 'MODERATE RISK', color: 'var(--color-medium)' };
    return { score: 15, grade: 'LOW RISK', color: 'var(--color-low)' };
  };

  if (!user) {
    return (
      <div className="landing-grid">
        {/* Left Column: Hero Branding & Feature Details */}
        <div className="hero-side">
          <div className="hero-badge">NSPECT // SECURITY AUDIT SUITE</div>
          <h1>Network Security Vulnerability Scanner & IDS</h1>
          <p className="hero-desc">
            A comprehensive, dual-use computer network diagnostics toolkit. NSPECT enables real-time service discovery, active version banner analysis, CVE vulnerability checking, traffic packet analysis, and heuristic intrusion detection.
          </p>

          <div className="landing-features">
            <div className="landing-feat-item">
              <div className="feat-num">01</div>
              <div className="feat-details">
                <h3>Vulnerability & Port Analyzer</h3>
                <p>Scans subnet ports concurrently and maps running service versions to known NVD vulnerability databases (CVEs).</p>
              </div>
            </div>

            <div className="landing-feat-item">
              <div className="feat-num">02</div>
              <div className="feat-details">
                <h3>Intrusion Detection Heuristics</h3>
                <p>Sniffs packet interfaces to flag abnormal traffic spikes, duplicate gateway ARP matches, or incomplete TCP SYN streams.</p>
              </div>
            </div>

            <div className="landing-feat-item">
              <div className="feat-num">03</div>
              <div className="feat-details">
                <h3>Interactive Network Topology</h3>
                <p>Auto-detects active local subnet hosts and plots device properties, manufacturer vendors, and evolution risk maps.</p>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Embedded Login Card */}
        <div className="login-side">
          <div className="login-card">
            <div className="login-header">
              <h2>Auditor Sign-In</h2>
              <p style={{ color: 'var(--text-secondary)' }}>
                {isRegistering ? "Register your security credentials" : "Access the diagnostic scan terminal"}
              </p>
            </div>

            {authError && <div className="auth-error">{authError}</div>}

            <form className="auth-form" onSubmit={isRegistering ? handleRegister : handleLogin}>
              <div className="form-group">
                <label>Auditor Username</label>
                <input 
                  type="text" 
                  className="cyber-input" 
                  placeholder="e.g. admin" 
                  value={authUsername} 
                  onChange={e => setAuthUsername(e.target.value)} 
                  required 
                />
              </div>

              <div className="form-group">
                <label>Security Password</label>
                <input 
                  type="password" 
                  className="cyber-input" 
                  placeholder="••••••••" 
                  value={authPassword} 
                  onChange={e => setAuthPassword(e.target.value)} 
                  required 
                />
              </div>

              {isRegistering && (
                <div className="form-group">
                  <label>Audit Authority Role</label>
                  <select 
                    className="cyber-input" 
                    value={registerRole} 
                    onChange={e => setRegisterRole(e.target.value)}
                  >
                    <option value="VIEWER">Viewer (Read Only)</option>
                    <option value="ANALYST">Analyst (Scan & Export)</option>
                    <option value="ADMIN">Admin (Full Control)</option>
                  </select>
                </div>
              )}

              <div className="auth-btn-row">
                <button type="submit" className="btn btn-primary">
                  {isRegistering ? "Register Account" : "Access Dashboard"}
                </button>
                <button 
                  type="button" 
                  className="btn" 
                  style={{ background: 'transparent', color: 'var(--text-secondary)' }}
                  onClick={() => {
                    setIsRegistering(!isRegistering);
                    setAuthError('');
                  }}
                >
                  {isRegistering ? "Back to Login" : "Create Account"}
                </button>
              </div>
            </form>

            <div className="credentials-hint">
              <strong>Demonstration User Roles:</strong><br />
              - Admin: <code>admin</code> / <code>admin123</code><br />
              - Analyst: <code>analyst</code> / <code>analyst123</code><br />
              - Viewer: <code>viewer</code> / <code>viewer123</code>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div className="logo-section">
          <div className="logo-icon">NS</div>
          <div className="logo-text">Vulnerability Scanner</div>
        </div>

        <nav>
          <ul className="nav-menu">
            <li className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`} onClick={() => setActiveTab('dashboard')}>
              <DashboardIcon /> Dashboard
            </li>
            <li className={`nav-item ${activeTab === 'scanner' ? 'active' : ''}`} onClick={() => setActiveTab('scanner')}>
              <ScanIcon /> Port Scanner
            </li>
            <li className={`nav-item ${activeTab === 'ids' ? 'active' : ''}`} onClick={() => setActiveTab('ids')}>
              <ShieldIcon /> IDS & Sniffer
            </li>
            <li className={`nav-item ${activeTab === 'topology' ? 'active' : ''}`} onClick={() => setActiveTab('topology')}>
              <MapIcon /> Network Topology
            </li>
            <li className={`nav-item ${activeTab === 'intel' ? 'active' : ''}`} onClick={() => setActiveTab('intel')}>
              <IntelIcon /> Threat Intel
            </li>
            <li className={`nav-item ${activeTab === 'assistant' ? 'active' : ''}`} onClick={() => setActiveTab('assistant')}>
              <AssistantIcon /> AI Assistant
            </li>
            <li className={`nav-item ${activeTab === 'history' ? 'active' : ''}`} onClick={() => setActiveTab('history')}>
              <HistoryIcon /> Scan History
            </li>
          </ul>
        </nav>

        <div className="sidebar-footer">
          <div className="status-badge">
            <div className={`status-dot ${backendConnected ? 'online' : 'demo'}`}></div>
            <span>{backendConnected ? "Spring Boot Active" : "Demo Mode Offline"}</span>
          </div>
        </div>

        <div className="profile-card">
          <div className="profile-info">
            <span className="profile-username">{user.username}</span>
            <span className="profile-role">{user.role}</span>
          </div>
          <button className="logout-btn" onClick={handleLogout} title="Log Out">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          </button>
        </div>
      </aside>

      {/* Main Panel */}
      <main className="main-content">
        <header className="top-bar">
          <h1>{activeTab.toUpperCase()} PANEL</h1>
          <div className="system-stats">
            <div className="stat-mini">Packets Captures: <span>{packetStats.total}</span></div>
            <div className="stat-mini">Rate: <span>{packetStats.rate} p/s</span></div>
            <div className="stat-mini">Bandwidth: <span>{packetStats.bandwidth} Kbps</span></div>
          </div>
        </header>

        <section className="content-body">
          {/* TAB 1: DASHBOARD OVERVIEW */}
          {activeTab === 'dashboard' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div className="dashboard-grid">
                <div className="card metric-card">
                  <div className="metric-header">Total Devices Discovered</div>
                  <div className="metric-value">{networkNodes.length} Active</div>
                  <div className="metric-footer">Across local subnet /24</div>
                </div>
                <div className="card metric-card">
                  <div className="metric-header">Open Ports Identified</div>
                  <div className="metric-value">{scanResults.length > 0 ? scanResults.length : 12} Ports</div>
                  <div className="metric-footer">Plotted in network services</div>
                </div>
                <div className="card metric-card">
                  <div className="metric-header">Threat Alerts Triggered</div>
                  <div className="metric-value" style={{ color: 'var(--color-critical)' }}>{alerts.length} Warnings</div>
                  <div className="metric-footer">Real-time Sniffer detection</div>
                </div>
                <div className="card metric-card">
                  {(() => {
                    const risk = getOverallRisk();
                    return (
                      <>
                        <div className="metric-header">Overall Risk Score</div>
                        <div className="metric-value" style={{ color: risk.color }}>{risk.score} / 100</div>
                        <div className="metric-footer">Security Grade: {risk.grade}</div>
                      </>
                    );
                  })()}
                </div>
              </div>

              <div className="chart-grid">
                {/* SVG Visual Bar Chart (Modules 11 & 12 visualization) */}
                <div className="card">
                  <h2>Active Port Frequency Graph</h2>
                  <div style={{ display: 'flex', justifyContent: 'space-around', alignItems: 'flex-end', height: '220px', padding: '20px 0', borderBottom: '1px solid var(--border-subtle)' }}>
                    {[
                      { port: '21 (FTP)', height: 80, color: 'var(--color-high)' },
                      { port: '22 (SSH)', height: 120, color: 'var(--color-high)' },
                      { port: '23 (Telnet)', height: 70, color: 'var(--color-high)' },
                      { port: '80 (HTTP)', height: 180, color: 'var(--color-critical)' },
                      { port: '443 (HTTPS)', height: 190, color: 'var(--color-low)' },
                      { port: '3306 (MySQL)', height: 90, color: 'var(--color-medium)' }
                    ].map((item, idx) => (
                      <div key={idx} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '60px' }}>
                        <div style={{ height: `${item.height}px`, width: '32px', background: item.color, borderRadius: '4px 4px 0 0', boxShadow: `0 0 10px ${item.color}50` }}></div>
                        <span style={{ fontSize: '10px', marginTop: '8px', color: 'var(--text-secondary)' }}>{item.port}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* SVG Visual Donut Chart for Risk Rating */}
                <div className="card" style={{ display: 'flex', flexDirection: 'column' }}>
                  <h2>Vulnerability Breakdown</h2>
                  <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '220px', position: 'relative' }}>
                    <svg width="150" height="150" viewBox="0 0 42 42">
                      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--border-subtle)" strokeWidth="4"></circle>
                      {/* Critical segment */}
                      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--color-critical)" strokeWidth="4.5" strokeDasharray="20 80" strokeDashoffset="25"></circle>
                      {/* High segment */}
                      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--color-high)" strokeWidth="4.5" strokeDasharray="30 70" strokeDashoffset="5"></circle>
                      {/* Medium segment */}
                      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--color-medium)" strokeWidth="4.5" strokeDasharray="25 75" strokeDashoffset="75"></circle>
                      {/* Low segment */}
                      <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--color-low)" strokeWidth="4.5" strokeDasharray="25 75" strokeDashoffset="50"></circle>
                    </svg>
                    <div style={{ position: 'absolute', fontSize: '12px', fontWeight: 'bold' }}>
                      RISK
                    </div>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', fontSize: '11px', marginTop: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ display: 'inline-block', width: '8px', height: '8px', background: 'var(--color-critical)' }}></span> Critical (20%)</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ display: 'inline-block', width: '8px', height: '8px', background: 'var(--color-high)' }}></span> High (30%)</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ display: 'inline-block', width: '8px', height: '8px', background: 'var(--color-medium)' }}></span> Medium (25%)</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}><span style={{ display: 'inline-block', width: '8px', height: '8px', background: 'var(--color-low)' }}></span> Low (25%)</div>
                  </div>
                </div>
              </div>

              {/* Threat Intelligence Feed */}
              <div className="card">
                <h2>Real-time Intrusion Detection Log (Mini IDS)</h2>
                <div className="threat-feed">
                  {alerts.length === 0 ? (
                    <div style={{ color: 'var(--text-muted)', fontSize: '14px', textAlign: 'center', padding: '20px' }}>No active threats detected. Network Traffic Normal.</div>
                  ) : (
                    alerts.map(alert => (
                      <div key={alert.id} className={`threat-item ${alert.severity}`}>
                        <div className="threat-meta">
                          <span className="p-protocol">{alert.time}</span>
                          <span className="threat-ip">{alert.source}</span>
                          <span className="threat-name">{alert.type}: {alert.desc}</span>
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                          <span className={`severity-pill ${alert.severity}`}>{alert.severity}</span>
                          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Rec: {alert.rec}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PORT SCANNER */}
          {activeTab === 'scanner' && (
            <div className="scanner-layout">
              <div className="card scanner-panel">
                <h2>Scan Configuration</h2>
                {user.role === 'VIEWER' && (
                  <div className="rbac-warning">
                    Read-Only Mode: You lack the privileges to run scanner modules.
                  </div>
                )}
                <div className="form-group">
                  <label>Target Host / IP Address</label>
                  <input type="text" className="cyber-input" value={targetHost} onChange={e => setTargetHost(e.target.value)} disabled={user.role === 'VIEWER'} />
                </div>
                <div className="form-row">
                  <div className="form-group">
                    <label>Start Port</label>
                    <input type="number" className="cyber-input" value={startPort} onChange={e => setStartPort(e.target.value)} disabled={user.role === 'VIEWER'} />
                  </div>
                  <div className="form-group">
                    <label>End Port</label>
                    <input type="number" className="cyber-input" value={endPort} onChange={e => setEndPort(e.target.value)} disabled={user.role === 'VIEWER'} />
                  </div>
                </div>
                <div className="form-group">
                  <label>Timeout (ms)</label>
                  <input type="number" className="cyber-input" value={timeout} onChange={e => setTimeoutVal(e.target.value)} disabled={user.role === 'VIEWER'} />
                </div>
                
                {isScanning ? (
                  <button className="btn btn-secondary" onClick={() => setIsScanning(false)}>Stop Scan</button>
                ) : (
                  <button 
                    className="btn btn-primary" 
                    onClick={triggerScan}
                    disabled={user.role === 'VIEWER'}
                  >
                    Start Network Scan
                  </button>
                )}

                {isScanning && (
                  <div className="progress-container">
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px' }}>
                      <span>Scanning ports...</span>
                      <span>{scanProgress}%</span>
                    </div>
                    <div className="progress-bar-bg">
                      <div className="progress-bar-fill" style={{ width: `${scanProgress}%` }}></div>
                    </div>
                  </div>
                )}
              </div>

              <div className="card">
                <div className="results-header">
                  <h2>Active Vulnerability & Service Report</h2>
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    {scanResults.length > 0 && (
                      <button 
                        className="btn btn-primary" 
                        style={{ padding: '6px 12px', fontSize: '12px', background: 'linear-gradient(135deg, #10b981, #059669)', boxShadow: '0 4px 10px rgba(16, 185, 129, 0.2)' }}
                        onClick={() => downloadPdfReport(targetHost)}
                        disabled={user.role === 'VIEWER'}
                      >
                        Export PDF
                      </button>
                    )}
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Found: {scanResults.length} Open Services</span>
                  </div>
                </div>

                <div className="cyber-table-wrapper">
                  <table className="cyber-table">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Service</th>
                        <th>State</th>
                        <th>Banner / Version Info</th>
                        <th>Vulnerability Maps (CVE Database)</th>
                        <th>Risk Score</th>
                      </tr>
                    </thead>
                    <tbody>
                      {scanResults.length === 0 ? (
                        <tr>
                          <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 0' }}>No active ports scanned yet. Trigger connection above.</td>
                        </tr>
                      ) : (
                        scanResults.map((res, idx) => (
                          <tr key={idx}>
                            <td style={{ fontWeight: 'bold', fontFamily: 'var(--font-mono)' }}>{res.port}</td>
                            <td><span style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '2px 6px', borderRadius: '4px' }}>{res.service}</span></td>
                            <td style={{ color: 'var(--color-low)' }}>{res.state}</td>
                            <td style={{ fontFamily: 'var(--font-mono)' }}>{res.banner}</td>
                            <td style={{ color: res.riskLevel === 'CRITICAL' || res.riskLevel === 'HIGH' ? 'var(--color-high)' : 'var(--text-muted)' }}>
                              {res.cves || 'None'}
                            </td>
                            <td>
                              <span className={`severity-pill ${res.riskLevel.toLowerCase()}`}>{res.riskLevel}</span>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: IDS & PACKET SNIFFER */}
          {activeTab === 'ids' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <h2>Live Packet Sniffer Log</h2>
                    <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>sniffing promiscuously on selected network interfaces</p>
                  </div>
                  <button className={`btn ${snifferActive ? 'btn-secondary' : 'btn-primary'}`} onClick={toggleSnifferStatus}>
                    {snifferActive ? "Pause Sniffer" : "Resume Sniffer"}
                  </button>
                </div>

                <div className="packet-log">
                  <div className="packet-item" style={{ borderBottom: '2px solid var(--border-subtle)', fontWeight: 'bold', color: 'var(--text-secondary)' }}>
                    <div>Time</div>
                    <div>Source IP</div>
                    <div>Destination IP</div>
                    <div>Protocol</div>
                    <div style={{ textAlign: 'right', paddingRight: '12px' }}>Length</div>
                    <div>Information Query</div>
                  </div>
                  {packets.length === 0 ? (
                    <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-muted)' }}>Sniffer listening... waiting for network activity.</div>
                  ) : (
                    packets.map((p, idx) => (
                      <div key={idx} className="packet-item">
                        <div>{p.time}</div>
                        <div className="p-ip">{p.src}</div>
                        <div className="p-ip">{p.dst}</div>
                        <div className="p-protocol">{p.protocol}</div>
                        <div className="p-len">{p.len} B</div>
                        <div className="p-info">{p.info}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: NETWORK MAP TOPOLOGY */}
          {activeTab === 'topology' && (
            <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2>Interactive Network Topology Map</h2>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Select nodes to inspect operating system guesses, hardware manufacturers, latency, and vulnerabilities.</p>
                </div>
                {!isDemoMode && (
                  <button 
                    className="btn btn-primary" 
                    style={{ padding: '8px 16px', fontSize: '12px' }}
                    onClick={() => loadTopology()}
                    disabled={loadingTopology}
                  >
                    {loadingTopology ? "Scanning Subnet..." : "Discover Devices"}
                  </button>
                )}
              </div>

              <div className="topology-container">
                <svg width="600" height="450" style={{ background: 'transparent' }}>
                  {/* Dynamic Connection Lines */}
                  {(() => {
                    const gatewayNode = networkNodes.find(n => n.ip.endsWith(".1") || n.id.includes("gateway")) || networkNodes[0];
                    return gatewayNode && networkNodes.filter(n => n.id !== gatewayNode.id).map(node => (
                      <line 
                        key={`link_${node.id}`} 
                        x1={gatewayNode.x} 
                        y1={gatewayNode.y} 
                        x2={node.x} 
                        y2={node.y} 
                        stroke="var(--border-subtle)" 
                        strokeWidth="2" 
                      />
                    ));
                  })()}

                  {/* Nodes */}
                  {networkNodes.map(node => {
                    const lastOctet = node.ip.substring(node.ip.lastIndexOf('.') + 1);
                    let initial = 'PC';
                    if (lastOctet === "1" || node.id.includes("gateway")) initial = 'RT';
                    else if (node.label.includes("Server")) initial = 'SRV';
                    else if (node.label.includes("Printer")) initial = 'PRN';
                    else if (node.label.includes("Phone") || node.label.includes("Mobile")) initial = 'MOB';

                    return (
                      <g key={node.id} className="node-group" onClick={() => setSelectedNode(node)}>
                        <circle 
                          cx={node.x} 
                          cy={node.y} 
                          r="24" 
                          className={`node-circle ${selectedNode?.id === node.id ? 'active' : ''} ${node.risk === 'CRITICAL' ? 'risk-critical' : node.risk === 'HIGH' ? 'risk-high' : node.risk === 'MEDIUM' ? 'risk-medium' : ''}`} 
                        />
                        <text x={node.x} y={node.y + 4} className="node-label">
                          {initial}
                        </text>
                        <text x={node.x} y={node.y + 36} className="node-label">{node.label}</text>
                        <text x={node.x} y={node.y + 46} className="node-ip">{node.ip}</text>
                      </g>
                    );
                  })}
                </svg>

                {selectedNode && (
                  <div className="node-details-card">
                    <div className="node-details-header">{selectedNode.label}</div>
                    <div className="node-details-row"><span>IP Address</span><span>{selectedNode.ip}</span></div>
                    <div className="node-details-row"><span>MAC Address</span><span>{selectedNode.mac}</span></div>
                    <div className="node-details-row"><span>Hardware vendor</span><span>{selectedNode.vendor}</span></div>
                    <div className="node-details-row"><span>OS Fingerprint</span><span style={{ color: 'var(--cyber-blue)' }}>{selectedNode.os}</span></div>
                    <div className="node-details-row"><span>Latency</span><span>{selectedNode.latency}</span></div>
                    <div className="node-details-row"><span>Open Ports</span><span>{selectedNode.ports}</span></div>
                    <div className="node-details-row">
                      <span>Threat Risk</span>
                      <span className={`severity-pill ${selectedNode.risk.toLowerCase()}`}>{selectedNode.risk}</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 5: THREAT INTEL */}
          {activeTab === 'intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
              <div className="card">
                <h2>IP Threat Intelligence Checker</h2>
                <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
                  Analyze public IP addresses using our Threat Intelligence Feed to evaluate abuse confidence scores, geo-location, ISP details, and potential malicious activities.
                </p>
                <div style={{ display: 'flex', gap: '12px', maxWidth: '600px' }}>
                  <input 
                    type="text" 
                    className="cyber-input" 
                    style={{ flex: 1 }}
                    placeholder="e.g. 185.190.140.23" 
                    value={intelIp} 
                    onChange={e => setIntelIp(e.target.value)} 
                  />
                  <button 
                    className="btn btn-primary" 
                    onClick={() => queryIntel()}
                    disabled={intelLoading}
                  >
                    {intelLoading ? "Querying..." : "Analyze IP"}
                  </button>
                </div>
              </div>

              {intelLoading && (
                <div className="card" style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', padding: '40px' }}>
                  <div className="status-dot online" style={{ width: '12px', height: '12px', marginRight: '10px' }}></div>
                  <span style={{ fontSize: '14px', color: 'var(--cyber-blue)', fontWeight: 'bold' }}>Querying Threat Intelligence Databases...</span>
                </div>
              )}

              {!intelLoading && intelResult && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                  {intelResult.abuseConfidenceScore >= 50 && (
                    <div className="card" style={{ borderLeft: '4px solid var(--color-critical)', background: 'rgba(239, 68, 68, 0.08)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className="status-dot" style={{ backgroundColor: 'var(--color-critical)', boxShadow: '0 0 10px var(--color-critical)', width: '10px', height: '10px' }}></div>
                        <h3 style={{ color: 'var(--color-critical)', fontWeight: 'bold' }}>HIGH THREAT LEVEL DETECTED</h3>
                      </div>
                      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
                        This IP address (<strong>{intelResult.ip}</strong>) has an Abuse Confidence Score of <strong>{intelResult.abuseConfidenceScore}%</strong> based on <strong>{intelResult.totalReports}</strong> distinct abuse reports. It is highly recommended to block this IP at your perimeter firewall.
                      </p>
                    </div>
                  )}

                  {intelResult.abuseConfidenceScore > 0 && intelResult.abuseConfidenceScore < 50 && (
                    <div className="card" style={{ borderLeft: '4px solid var(--color-medium)', background: 'rgba(245, 158, 11, 0.08)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className="status-dot" style={{ backgroundColor: 'var(--color-medium)', boxShadow: '0 0 10px var(--color-medium)', width: '10px', height: '10px' }}></div>
                        <h3 style={{ color: 'var(--color-medium)', fontWeight: 'bold' }}>SUSPICIOUS TRAFFIC WARNING</h3>
                      </div>
                      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
                        This IP address has low to moderate reports (Abuse Confidence Score: <strong>{intelResult.abuseConfidenceScore}%</strong>, <strong>{intelResult.totalReports}</strong> reports). Monitor traffic from this source.
                      </p>
                    </div>
                  )}

                  {intelResult.abuseConfidenceScore === 0 && (
                    <div className="card" style={{ borderLeft: '4px solid var(--color-low)', background: 'rgba(16, 185, 129, 0.08)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                        <div className="status-dot" style={{ backgroundColor: 'var(--color-low)', boxShadow: '0 0 10px var(--color-low)', width: '10px', height: '10px' }}></div>
                        <h3 style={{ color: 'var(--color-low)', fontWeight: 'bold' }}>IP VERIFIED CLEAN</h3>
                      </div>
                      <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '8px' }}>
                        This IP address has no reported history of malicious behavior or scanning activities.
                      </p>
                    </div>
                  )}

                  <div className="chart-grid">
                    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                      <h3>IP Profile Details</h3>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '14px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>IP Address</span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold' }}>{intelResult.ip}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>IP Version</span>
                          <span>IPv{intelResult.ipVersion || 4}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Country Origin</span>
                          <span style={{ fontWeight: 'bold' }}>{intelResult.countryCode || 'N/A'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Usage Classification</span>
                          <span>{intelResult.usageType || 'N/A'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Network Operator (ISP)</span>
                          <span>{intelResult.isp || 'N/A'}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', paddingBottom: '8px', borderBottom: '1px solid var(--border-subtle)' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Associated Domain</span>
                          <span>{intelResult.domain || 'N/A'}</span>
                        </div>
                      </div>
                    </div>

                    <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                      <h3>Abuse Confidence Score</h3>
                      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '160px', position: 'relative' }}>
                        <svg width="130" height="130" viewBox="0 0 42 42">
                          <circle cx="21" cy="21" r="15.915" fill="transparent" stroke="var(--border-subtle)" strokeWidth="4"></circle>
                          <circle 
                            cx="21" 
                            cy="21" 
                            r="15.915" 
                            fill="transparent" 
                            stroke={intelResult.abuseConfidenceScore >= 50 ? 'var(--color-critical)' : intelResult.abuseConfidenceScore > 0 ? 'var(--color-medium)' : 'var(--color-low)'} 
                            strokeWidth="4" 
                            strokeDasharray={`${intelResult.abuseConfidenceScore} ${100 - intelResult.abuseConfidenceScore}`} 
                            strokeDashoffset="25"
                          ></circle>
                        </svg>
                        <div style={{ position: 'absolute', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                          <span style={{ fontSize: '24px', fontWeight: 'bold', fontFamily: 'var(--font-mono)' }}>{intelResult.abuseConfidenceScore}%</span>
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Abuse Score</span>
                        </div>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', width: '100%', fontSize: '12px', marginTop: '10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Total Abuse Reports</span>
                          <span style={{ fontWeight: 'bold' }}>{intelResult.totalReports || 0}</span>
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>Last Reported Timestamp</span>
                          <span style={{ fontSize: '11px' }}>{intelResult.lastReportedAt ? new Date(intelResult.lastReportedAt).toLocaleDateString() : 'N/A'}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 6: AI SECURITY ASSISTANT */}
          {activeTab === 'assistant' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', height: 'calc(100vh - 200px)' }}>
              <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '20px' }}>
                <div style={{ borderBottom: '1px solid var(--border-subtle)', paddingBottom: '12px', marginBottom: '16px' }}>
                  <h2>AI Cybersecurity Assistant</h2>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Get instant mitigation rules, firewall settings, and exploits advice for your network scans.</p>
                </div>

                {/* Message Log Container */}
                <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '16px', paddingRight: '6px', marginBottom: '16px' }}>
                  {chatMessages.map((msg, idx) => (
                    <div 
                      key={idx} 
                      style={{ 
                        alignSelf: msg.sender === 'user' ? 'flex-end' : 'flex-start',
                        maxWidth: '85%',
                        background: msg.sender === 'user' ? 'linear-gradient(135deg, var(--primary), var(--accent))' : 'rgba(255, 255, 255, 0.02)',
                        border: '1px solid var(--border-subtle)',
                        borderLeft: msg.sender === 'ai' ? '4px solid var(--cyber-blue)' : '1px solid var(--border-subtle)',
                        borderRadius: '12px',
                        padding: '14px 18px',
                        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.15)'
                      }}
                    >
                      <div style={{ fontSize: '10px', color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: '6px', fontWeight: 'bold', letterSpacing: '0.5px' }}>
                        {msg.sender === 'user' ? 'Auditor Query' : 'NSPECT Security Advisor'}
                      </div>
                      <div style={{ color: '#fff' }}>
                        {msg.sender === 'user' ? (
                          <p style={{ fontSize: '13.5px', whiteSpace: 'pre-wrap', margin: 0 }}>{msg.text}</p>
                        ) : (
                          renderAdviceText(msg.text)
                        )}
                      </div>
                    </div>
                  ))}
                  
                  {chatLoading && (
                    <div style={{ alignSelf: 'flex-start', background: 'rgba(255, 255, 255, 0.01)', border: '1px solid var(--border-subtle)', borderLeft: '4px solid var(--cyber-blue)', borderRadius: '12px', padding: '14px 18px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div className="status-dot online" style={{ width: '8px', height: '8px' }}></div>
                      <span style={{ fontSize: '12.5px', color: 'var(--text-secondary)' }}>AI Advisor is analyzing security parameters...</span>
                    </div>
                  )}
                </div>

                {/* Input Controls */}
                <form onSubmit={sendChatMessage} style={{ display: 'flex', gap: '12px' }}>
                  <input 
                    type="text" 
                    className="cyber-input" 
                    style={{ flex: 1 }}
                    placeholder="Ask about vulnerabilities (e.g. 'Why is Port 445 dangerous?')" 
                    value={chatInput} 
                    onChange={e => setChatInput(e.target.value)} 
                    disabled={chatLoading}
                  />
                  <button 
                    type="submit" 
                    className="btn btn-primary" 
                    style={{ padding: '0 24px' }}
                    disabled={chatLoading}
                  >
                    Send Query
                  </button>
                </form>
              </div>
            </div>
          )}

          {/* TAB 5: SCAN HISTORY */}
          {activeTab === 'history' && (
            <div className="card">
              <div className="results-header">
                <h2>Historical Scans Log (MySQL/H2 Persistence)</h2>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  {historyList.length > 0 && (
                    <button 
                      className="btn btn-primary" 
                      style={{ padding: '6px 12px', fontSize: '12px', background: 'linear-gradient(135deg, #10b981, #059669)', boxShadow: '0 4px 10px rgba(16, 185, 129, 0.2)' }}
                      onClick={() => downloadPdfReport(historyList[0].host)}
                      disabled={user.role === 'VIEWER'}
                    >
                      Export Latest Report
                    </button>
                  )}
                  <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>Previous findings saved in standard database logs</span>
                </div>
              </div>

              <div className="cyber-table-wrapper">
                <table className="cyber-table">
                  <thead>
                    <tr>
                      <th>Host IP</th>
                      <th>Port</th>
                      <th>Identified Service</th>
                      <th>Protocol state</th>
                      <th>Grabbed Banner</th>
                      <th>Threat Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyList.length === 0 ? (
                      <tr>
                        <td colSpan="6" style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '40px 0' }}>No historical scan records found. Run a new scan to insert rows.</td>
                      </tr>
                    ) : (
                      historyList.map((hist, idx) => (
                        <tr key={idx}>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{hist.host}</td>
                          <td style={{ fontFamily: 'var(--font-mono)', fontWeight: 'bold' }}>{hist.port}</td>
                          <td><span style={{ background: 'rgba(255, 255, 255, 0.05)', padding: '2px 6px', borderRadius: '4px' }}>{hist.service}</span></td>
                          <td style={{ color: 'var(--color-low)' }}>{hist.state}</td>
                          <td style={{ fontFamily: 'var(--font-mono)' }}>{hist.banner}</td>
                          <td>
                            <span className={`severity-pill ${hist.riskLevel ? hist.riskLevel.toLowerCase() : 'low'}`}>{hist.riskLevel || 'LOW'}</span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;
